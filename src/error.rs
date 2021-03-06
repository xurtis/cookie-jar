//! Errors produced by the cookie jar.

#![allow(missing_docs)]

error_chain!{
    // Links to other error chains.
    links {
        CookieParse(parser::Error, parser::ErrorKind);
    }

    // Links to other standard errors.
    foreign_links {
        Url(::url::ParseError);
    }

    // Internal error forms.
    errors {
        InvalidDomain(domain: ::idna::uts46::Errors) {
            description("An invalid domain was provided"),
            display("InvalidDomain({:?})", domain),
        }
        InvalidOrigin(url: ::url::Url) {
            description("The origin supplied for the cookie was invalid"),
            display("InvalidOrigin({})", url),
        }
        MissingDomain {
            description("No domain was provided for the cookie")
        }
        MissingPath {
            description("No path was provided for the cookie")
        }
        HostInvalid {
            description("Invalid to provide an IP address for a SetCookie")
        }
    }
}

impl From<::idna::uts46::Errors> for ErrorKind {
    fn from(error: ::idna::uts46::Errors) -> ErrorKind {
        ErrorKind::InvalidDomain(error)
    }
}

impl From<::idna::uts46::Errors> for Error {
    fn from(error: ::idna::uts46::Errors) -> Error {
        ErrorKind::from(error).into()
    }
}

/// Errors specific to parsing the cookie.
pub mod parser {
    error_chain!{
        foreign_links {
            Utf8(::std::str::Utf8Error);
            ParseInt(::std::num::ParseIntError);
            Time(::time::ParseError);
            Url(::url::ParseError);
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
