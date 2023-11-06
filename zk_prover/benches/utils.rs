extern crate proc_macro;

use proc_macro::TokenStream;
// use quote::quote;
// use syn::{parse2, LitStr};

#[proc_macro_attribute]
pub fn env_var(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // let input = parse2::<LitStr>(input).expect("Expected a string literal.");
    // let var_name = input.value();
    // let value = std::env::var(&var_name).unwrap_or_default();

    // TokenStream::from(quote! {
    //     #value
    // })
    println!("item: {:?}", item);
    item
}
