//! Derive macro for `statime-config`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Expr, Fields, Ident, LitStr, Token, Type, Variant,
    parse_macro_input, parse_quote, spanned::Spanned,
};

/// Generate the partial counterpart of a configuration struct.
///
/// A field with no `default` is required, one with `#[config(default = expr)]`
/// falls back to that expression, and a bare `#[config(default)]` falls back to
/// the field type's own [`Default`].
#[proc_macro_derive(Configurable, attributes(config))]
pub fn derive_configurable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// Mark a type as a configuration value the tree does not look inside.
///
/// Every traversal stops at it, so this is all a leaf type needs: enums,
/// newtypes around a duration or an address, and anything else that is a single
/// value as far as a configuration document is concerned.
///
/// ```ignore
/// #[derive(ConfigurableAtomic)]
/// pub enum LogLevel { Debug, Info, Warn, Error }
/// ```
#[proc_macro_derive(ConfigurableAtomic)]
pub fn derive_configurable_atomic(input: TokenStream) -> TokenStream {
    let name = parse_macro_input!(input as DeriveInput).ident;

    quote! {
        impl ::statime_config::ConfigurableAtomic for #name {}
    }
    .into()
}

/// One field of the configuration struct, and what the traversals need to know
/// about it.
struct Field {
    name: Ident,
    /// The name this field has in a configuration document. The same string
    /// reaches serde and the paths in diagnostics, so the two cannot disagree
    /// about what a document is supposed to say.
    key: String,
    /// Set when the key was chosen rather than derived from the field name.
    renamed: bool,
    ty: Type,
    default: Option<Expr>,
}

fn expand(input: DeriveInput) -> syn::Result<TokenStream2> {
    match &input.data {
        Data::Struct(data) => expand_struct(&input, data),
        Data::Enum(data) => expand_enum(&input, data),
        Data::Union(_) => Err(syn::Error::new(
            input.span(),
            "only structs and enums can be configurable",
        )),
    }
}

/// A struct becomes a section: one partial field per field, each of them a node
/// whose shape the field's own type decides.
fn expand_struct(input: &DeriveInput, data: &DataStruct) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let partial = format_ident!("Partial{}", name);

    // everything the generated code needs is named in full, so that it neither
    // collides with, nor depends on, whatever is in scope where it lands
    let private = quote!(::statime_config::__private);

    let fields = collect_fields(data)?;
    check_attributes(input)?;

    let declarations = fields.iter().map(|field| {
        let Field {
            name,
            key,
            renamed,
            ty,
            ..
        } = field;
        // otherwise the container's `rename_all` already produces this key
        let rename = renamed.then(|| quote!(#[serde(rename = #key)]));

        quote! {
            #rename
            #[serde(skip_serializing_if = "::statime_config::__private::is_effectively_unset")]
            pub #name: <#ty as ::statime_config::Configurable>::Node
        }
    });

    let emptiness = fields.iter().map(
        |Field { name, .. }| quote!(#private::EffectivelyUnset::is_effectively_unset(&self.#name)),
    );

    let attributions = fields.iter().map(|Field { name, .. }| {
        quote!(::statime_config::PartialValue::attribute(&mut self.#name, origin);)
    });

    let defaults = fields.iter().map(|Field { name, default, .. }| {
        let supply = default
            .as_ref()
            .map(|default| quote!(self.#name.default_to(|| #default);));
        quote! {
            #supply
            ::statime_config::PartialValue::apply_defaults(&mut self.#name);
        }
    });

    let merges = fields.iter().map(|Field { name, key, .. }| {
        quote! {
            context.at(#key, |context| {
                ::statime_config::Merge::merge(&mut self.#name, incoming.#name, context)
            })?;
        }
    });

    let resolutions = fields.iter().map(|Field { name, key, .. }| {
        quote! {
            #name: path.at(#key, |path| ::statime_config::PartialValue::resolve(self.#name, path))?
        }
    });

    let visibility = &input.vis;

    Ok(quote! {
        /// The partial counterpart of a configuration struct, holding only what
        /// the configuration documents actually said.
        #[doc(hidden)]
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        #[derive(#private::Deserialize, #private::Serialize)]
        #[serde(crate = "::statime_config::__private::serde")]
        #[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
        #visibility struct #partial {
            #(#declarations,)*
        }

        impl ::statime_config::Configurable for #name {
            type Partial = #partial;
            type Node = ::statime_config::Section<#partial>;
        }

        impl #private::EffectivelyUnset for #partial {
            fn is_effectively_unset(&self) -> bool {
                true #( && #emptiness )*
            }
        }

        impl ::statime_config::PartialValue for #partial {
            type Resolved = #name;

            fn attribute(&mut self, origin: ::statime_config::OriginId) {
                #(#attributions)*
            }

            fn apply_defaults(&mut self) {
                #(#defaults)*
            }

            fn resolve(
                self,
                path: &mut ::statime_config::ConfigPath,
            ) -> ::core::result::Result<#name, ::statime_config::ConfigError> {
                ::core::result::Result::Ok(#name {
                    #(#resolutions,)*
                })
            }
        }

        impl ::statime_config::Merge for #partial {
            fn merge(
                &mut self,
                incoming: Self,
                context: &mut ::statime_config::MergeContext<'_>,
            ) -> ::core::result::Result<(), ::statime_config::ConfigError> {
                #(#merges)*
                ::core::result::Result::Ok(())
            }
        }
    })
}

/// An enum becomes a choice between sections, told apart by a tag naming which
/// one a document means.
///
/// It is neither merged nor tested for emptiness: a configurable enum lives in
/// a vector, which is atomic, so two of them never meet.
fn expand_enum(input: &DeriveInput, data: &DataEnum) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let partial = format_ident!("Partial{}", name);
    let private = quote!(::statime_config::__private);

    let tag = enum_tag(input)?;
    let variants = data
        .variants
        .iter()
        .map(collect_variant)
        .collect::<syn::Result<Vec<_>>>()?;

    let declarations = variants.iter().map(|EnumVariant { name, ty, rename }| {
        // otherwise the container's `rename_all` already names this variant
        let rename = rename.as_ref().map(|key| quote!(#[serde(rename = #key)]));

        quote! {
            #rename
            #name(<#ty as ::statime_config::Configurable>::Partial)
        }
    });

    let attributions = variants.iter().map(|EnumVariant { name, .. }| {
        quote!(Self::#name(value) => ::statime_config::PartialValue::attribute(value, origin),)
    });

    let defaults = variants.iter().map(|EnumVariant { name, .. }| {
        quote!(Self::#name(value) => ::statime_config::PartialValue::apply_defaults(value),)
    });

    let variant_names = variants.iter().map(|EnumVariant { name, rename, .. }| {
        let string_name = rename.clone().unwrap_or_else(|| name.to_string());
        quote!(Self::#name(value) => #string_name,)
    });

    let variant_merges = variants.iter().map(|EnumVariant { name, .. }| {
        quote!((Self::#name(this), Self::#name(incoming)) => ::statime_config::Merge::merge(this, incoming, context),)
    });

    let resolutions = variants.iter().map(|EnumVariant { name: variant, .. }| {
        quote! {
            Self::#variant(value) => ::core::result::Result::Ok(
                #name::#variant(::statime_config::PartialValue::resolve(value, path)?)
            ),
        }
    });

    let visibility = &input.vis;

    Ok(quote! {
        /// The partial counterpart of a configuration enum, holding only what
        /// the configuration documents actually said.
        #[doc(hidden)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[derive(#private::Deserialize, #private::Serialize)]
        #[serde(crate = "::statime_config::__private::serde")]
        #[serde(rename_all = "kebab-case", tag = #tag)]
        #visibility enum #partial {
            #(#declarations,)*
        }

        impl ::statime_config::Configurable for #name {
            type Partial = #partial;
            type Node = ::statime_config::Section<#partial>;
        }

        impl ::statime_config::PartialValue for #partial {
            type Resolved = #name;

            fn attribute(&mut self, origin: ::statime_config::OriginId) {
                match self {
                    #(#attributions)*
                }
            }

            fn apply_defaults(&mut self) {
                match self {
                    #(#defaults)*
                }
            }

            fn resolve(
                self,
                path: &mut ::statime_config::ConfigPath,
            ) -> ::core::result::Result<#name, ::statime_config::ConfigError> {
                match self {
                    #(#resolutions)*
                }
            }
        }

        impl #partial {
            fn variant_name(&self) -> &'static str {
                match self {
                    #(#variant_names)*
                }
            }
        }

        impl ::statime_config::Merge for #partial {
            fn merge(
                &mut self,
                incoming: Self,
                context: &mut ::statime_config::MergeContext<'_>,
            ) -> ::core::result::Result<(), ::statime_config::ConfigError> {
                match (self, incoming) {
                    #(#variant_merges)*
                    (this, incoming) => match context.policy {
                        ::statime_config::__private::MergePolicy::RejectOverlap => Err(::statime_config::ConfigError::MismatchedVariants { position: context.path.clone(), current: this.variant_name(), incoming: incoming.variant_name() }),
                        ::statime_config::__private::MergePolicy::Override => {
                            *this = incoming;
                            ::core::result::Result::Ok(())
                        },
                    },
                }
            }
        }

        impl ::statime_config::PartialValue for ::statime_config::Section<#partial> {
            type Resolved = #name;

            /// A section records no origin of its own, and visits its children.
            fn attribute(&mut self, origin: ::statime_config::OriginId) {
                if let ::statime_config::Section::Set(value) = self {
                    value.attribute(origin);
                }
            }

            /// An absent section still has to be visited: a document that never
            /// mentions a section should still get the defaults of everything inside
            /// it.
            fn apply_defaults(&mut self) {
                if let ::statime_config::Section::Set(value) = self {
                    value.apply_defaults();
                }
            }

            /// A section resolves to whatever its contents resolve to. An unset one
            /// only reaches this point when resolving without defaulting first, and
            /// resolving the empty struct still reports any required value it misses.
            fn resolve(self, path: &mut ::statime_config::ConfigPath) -> ::core::result::Result<Self::Resolved, ::statime_config::ConfigError> {
                match self {
                    ::statime_config::Section::Set(value) => value.resolve(path),
                    ::statime_config::Section::Unset => ::core::result::Result::Err(::statime_config::ConfigError::MissingRequiredValue { position: path.clone() }),
                }
            }
        }

        impl ::statime_config::__private::EffectivelyUnset for ::statime_config::Section<#partial> {
            fn is_effectively_unset(&self) -> bool {
                match self {
                    ::statime_config::Section::Set(_) => true,
                    ::statime_config::Section::Unset => false,
                }
            }
        }
    })
}

/// The key that says which variant a document means.
fn enum_tag(input: &DeriveInput) -> syn::Result<String> {
    let mut tag = None;

    for attribute in &input.attrs {
        if !attribute.path().is_ident("config") {
            continue;
        }

        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("tag") {
                tag = Some(meta.value()?.parse::<LitStr>()?.value());
                return Ok(());
            }

            Err(meta.error("unrecognised configuration attribute"))
        })?;
    }

    tag.ok_or_else(|| {
        syn::Error::new(
            input.span(),
            "a configurable enum needs `#[config(tag = \"...\")]`, naming the key \
             a document uses to say which variant it means",
        )
    })
}

/// One variant of the configuration enum, and the configuration struct it
/// holds.
struct EnumVariant {
    name: Ident,
    ty: Type,
    rename: Option<String>,
}

fn collect_variant(variant: &Variant) -> syn::Result<EnumVariant> {
    let unnamed = match &variant.fields {
        Fields::Unnamed(unnamed) if unnamed.unnamed.len() == 1 => &unnamed.unnamed[0],
        _ => {
            return Err(syn::Error::new(
                variant.span(),
                "a configurable enum variant holds exactly one configuration struct; \
                 an enum that is itself a single value wants `ConfigurableAtomic` instead",
            ));
        }
    };

    Ok(EnumVariant {
        name: variant.ident.clone(),
        ty: unnamed.ty.clone(),
        rename: variant_rename(variant)?,
    })
}

fn collect_fields(data: &DataStruct) -> syn::Result<Vec<Field>> {
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "a configurable struct needs named fields",
        ));
    };

    named
        .named
        .iter()
        .map(|field| {
            let name = field.ident.clone().expect("named fields have a name");
            let FieldConfig { default, rename } = field_config(field)?;

            Ok(Field {
                renamed: rename.is_some(),
                key: rename.unwrap_or_else(|| name.to_string().replace('_', "-")),
                name,
                ty: field.ty.clone(),
                default,
            })
        })
        .collect()
}

/// Whether this struct is the root of a configuration tree
fn check_attributes(input: &DeriveInput) -> syn::Result<()> {
    for attribute in &input.attrs {
        if !attribute.path().is_ident("config") {
            continue;
        }

        attribute
            .parse_nested_meta(|meta| Err(meta.error("unrecognised configuration attribute")))?;
    }

    Ok(())
}

/// What the `#[config(...)]` attributes on a field say.
#[derive(Default)]
struct FieldConfig {
    default: Option<Expr>,
    rename: Option<String>,
}

fn field_config(field: &syn::Field) -> syn::Result<FieldConfig> {
    let mut config = FieldConfig::default();

    for attribute in &field.attrs {
        if !attribute.path().is_ident("config") {
            continue;
        }

        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("default") {
                // a bare `default` means the type's own `Default`
                config.default = Some(if meta.input.peek(Token![=]) {
                    meta.value()?.parse()?
                } else {
                    parse_quote!(::core::default::Default::default())
                });
                return Ok(());
            }

            if meta.path.is_ident("rename") {
                config.rename = Some(meta.value()?.parse::<LitStr>()?.value());
                return Ok(());
            }

            Err(meta.error("unrecognised configuration attribute"))
        })?;
    }

    Ok(config)
}

/// The name a variant is known by in a document, when it is not the one the
/// container's `rename_all` would produce.
fn variant_rename(variant: &Variant) -> syn::Result<Option<String>> {
    let mut rename = None;

    for attribute in &variant.attrs {
        if !attribute.path().is_ident("config") {
            continue;
        }

        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                rename = Some(meta.value()?.parse::<LitStr>()?.value());
                return Ok(());
            }

            Err(meta.error("unrecognised configuration attribute"))
        })?;
    }

    Ok(rename)
}
