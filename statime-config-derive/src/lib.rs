//! Derive macro for `statime-config`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Expr, Fields, Ident, Type, parse_macro_input, spanned::Spanned};

/// Generate the partial counterpart of a configuration struct.
#[proc_macro_derive(Configurable, attributes(config))]
pub fn derive_configurable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
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
    let name = &input.ident;
    let partial = format_ident!("Partial{}", name);

    // everything the generated code needs is named in full, so that it neither
    // collides with, nor depends on, whatever is in scope where it lands
    let private = quote!(::statime_config::__private);

    let fields = collect_fields(&input)?;

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
            .map(|default| quote!(self.#name.default_to(#default);));
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

fn collect_fields(input: &DeriveInput) -> syn::Result<Vec<Field>> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            input.span(),
            "only structs can be configurable",
        ));
    };
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
                default = Some(meta.value()?.parse()?);
                return Ok(());
            }

            Err(meta.error("unrecognised configuration attribute"))
        })?;
    }

    Ok(default)
}
