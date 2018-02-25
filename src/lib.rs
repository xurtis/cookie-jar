//! Implementation of a [RFC6265][rfc6265] compliant cookie store.
//!

#![deny(missing_docs)]

#[macro_use] extern crate error_chain;
extern crate idna;
extern crate time;
extern crate url;

pub mod cookie;
pub mod error;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
