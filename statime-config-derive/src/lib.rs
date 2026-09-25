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
        impl ::statime_config::__private::ConfigurableAtomic for #name {}
    }
    .into()
}

/// One field of the configuration struct, and what the traversals need to know
/// about it.
struct Field {
    name: Ident,
    /// The name this field has in a configuration document.
    key: String,
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

    let declarations = fields.iter().map(|field| {
        let Field { name, ty, .. } = field;
        quote! {
            #[serde(skip_serializing_if = "::statime_config::__private::is_effectively_unset")]
            pub #name: <#ty as #private::Configurable>::Node
        }
    });

    let emptiness = fields.iter().map(
        |Field { name, .. }| quote!(#private::EffectivelyUnset::is_effectively_unset(&self.#name)),
    );

    let attributions = fields.iter().map(
        |Field { name, .. }| quote!(#private::Attributable::attribute(&mut self.#name, origin);),
    );

    let defaults = fields.iter().map(|Field { name, default, .. }| {
        let supply = default
            .as_ref()
            .map(|default| quote!(self.#name.default_to(|| #default);));
        quote! {
            #supply
            #private::ApplyDefaults::apply_defaults(&mut self.#name);
        }
    });

    let merges = fields.iter().map(|Field { name, key, .. }| {
        quote! {
            context.at(#key, |context| {
                #private::Merge::merge(&mut self.#name, incoming.#name, context)
            })?;
        }
    });

    let resolutions = fields.iter().map(|Field { name, key, .. }| {
        quote! {
            #name: path.at(#key, |path| #private::Resolve::resolve(self.#name, path))?
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

        impl #private::Configurable for #name {
            type Partial = #partial;
            type Node = #private::Section<#partial>;
        }

        impl #private::EffectivelyUnset for #partial {
            fn is_effectively_unset(&self) -> bool {
                true #( && #emptiness )*
            }
        }

        impl #private::Attributable for #partial {
            fn attribute(&mut self, origin: #private::OriginId) {
                #(#attributions)*
            }
        }

        impl #private::ApplyDefaults for #partial {
            fn apply_defaults(&mut self) {
                #(#defaults)*
            }
        }

        impl #private::Merge for #partial {
            fn merge(
                &mut self,
                incoming: Self,
                context: &mut #private::MergeContext<'_>,
            ) -> ::core::result::Result<(), #private::ConfigError> {
                #(#merges)*
                ::core::result::Result::Ok(())
            }
        }

        impl #private::Resolve for #partial {
            type Resolved = #name;

            fn resolve(
                self,
                path: &mut #private::ConfigPath,
            ) -> ::core::result::Result<#name, #private::ConfigError> {
                ::core::result::Result::Ok(#name {
                    #(#resolutions,)*
                })
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

    let declarations = variants
        .iter()
        .map(|(variant, ty)| quote!(#variant(<#ty as #private::Configurable>::Partial)));

    let attributions = variants.iter().map(|(variant, _)| {
        quote!(Self::#variant(value) => #private::Attributable::attribute(value, origin),)
    });

    let defaults = variants.iter().map(|(variant, _)| {
        quote!(Self::#variant(value) => #private::ApplyDefaults::apply_defaults(value),)
    });

    let resolutions = variants.iter().map(|(variant, _)| {
        quote! {
            Self::#variant(value) => ::core::result::Result::Ok(
                #name::#variant(#private::Resolve::resolve(value, path)?)
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

        impl #private::Configurable for #name {
            type Partial = #partial;
            type Node = #private::Section<#partial>;
        }

        impl #private::Attributable for #partial {
            fn attribute(&mut self, origin: #private::OriginId) {
                match self {
                    #(#attributions)*
                }
            }
        }

        impl #private::ApplyDefaults for #partial {
            fn apply_defaults(&mut self) {
                match self {
                    #(#defaults)*
                }
            }
        }

        impl #private::Resolve for #partial {
            type Resolved = #name;

            fn resolve(
                self,
                path: &mut #private::ConfigPath,
            ) -> ::core::result::Result<#name, #private::ConfigError> {
                match self {
                    #(#resolutions)*
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

/// A variant, and the configuration struct it holds.
fn collect_variant(variant: &Variant) -> syn::Result<(Ident, Type)> {
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

    Ok((variant.ident.clone(), unnamed.ty.clone()))
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

            Ok(Field {
                key: name.to_string().replace('_', "-"),
                name,
                ty: field.ty.clone(),
                default: field_default(field)?,
            })
        })
        .collect()
}

/// The built-in default a field names, if it names one.
fn field_default(field: &syn::Field) -> syn::Result<Option<Expr>> {
    let mut default = None;

    for attribute in &field.attrs {
        if !attribute.path().is_ident("config") {
            continue;
        }

        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("default") {
                // a bare `default` means the type's own `Default`
                default = Some(if meta.input.peek(Token![=]) {
                    meta.value()?.parse()?
                } else {
                    parse_quote!(::core::default::Default::default())
                });
                return Ok(());
            }

            Err(meta.error("unrecognised configuration attribute"))
        })?;
    }

    Ok(default)
}
