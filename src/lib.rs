//! Implementation of a [RFC6265][rfc6265] compliant cookie store.
//!
//! [rfc6265]: https://tools.ietf.org/html/rfc6265

#![deny(missing_docs)]

#[macro_use]
extern crate error_chain;
extern crate idna;
#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;
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
