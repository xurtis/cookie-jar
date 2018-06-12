//! Errors produced by the cookie jar.

#![allow(missing_docs)]

error_chain!{
    // Links to other error chains.
    links {
        CookieParse(parser::Error, parser::ErrorKind);
    }

    // Links to other standard errors.
    foreign_links {
    }

    // Internal error forms.
    errors {
        InvalidOrigin(url: ::url::Url) {
            description("The origin supplied for the cookie was invalid"),
            display("The url is not a valid cookie origin: {}", url),
        }
        InvalidDomain(err: ::idna::uts46::Errors) {
            description("Invalid domain name"),
        }
    }
}

/// Errors specific to parsing the cookie.
pub mod parser {
    error_chain!{
        foreign_links {
            Utf8(::std::str::Utf8Error);
            ParseInt(::std::num::ParseIntError);
            Time(::time::ParseError);
        }

        errors {
            NotEnoughBytes {
                description("Not enough bytes were present to form a fragment of the cookie"),
            }
            MissingQuote {
                description("The trailing quote to a quoted section was not present"),
            }
            MissingDelimiter {
                description("A delimiter was missing in the cookie string"),
            }
            Incomplete {
                description("The cookie string was incomplete"),
            }
            InvalidByte {
                description("The cookie string contained an invalid byte"),
            }
            IncompleteDate {
                description("The provided date was incomplete"),
            }
            InvalidDate {
                description("The date provided was invalid"),
            }
        }
    }
}
