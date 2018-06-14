//! Representation of a cookie within the value store.

mod parse;

use self::parse::{process_cookie, Argument};
pub(crate) use self::parse::Pair;
use error::*;
use idna::domain_to_ascii;
use time::{now_utc, Tm};
use url::{Host, Url};

/// A builder for a cookie.
#[derive(Debug)]
pub enum Builder {
    /// A partially constructed cookie.
    Cookie(Cookie),

    /// An error.
    Err(Error),
}

impl From<parser::Error> for Builder {
    fn from(e: parser::Error) -> Builder {
        Builder::Err(e.into())
    }
}

impl From<Error> for Builder {
    fn from(e: Error) -> Builder {
        Builder::Err(e)
    }
}

macro_rules! try_build {
    ($result:expr) => (
        match $result {
            Err(e) => return Builder::Err(e.into()),
            Ok(v) => v,
        }
    )
}

impl Builder {
    /// Create a new cookie builder.
    ///
    /// The default cookie applies only to the root domain and to all paths beneath it.
    pub fn new() -> Builder {
        Builder::Cookie(Default::default())
    }

    /// Set the origin from which the cookie came.
    pub fn origin(self, origin: &Url) -> Builder {
        if let Some(host) = origin.host() {
            self
                .host(host.to_owned())
                .path(url_dir_path(origin))
        } else {
            Builder::Err(ErrorKind::InvalidOrigin(origin.clone()).into())
        }
    }

    /// Set the domain for the cookie to match a single domain.
    pub fn host(self, host: Host) -> Builder {
        self.map(|cookie| {
            Ok(Cookie {
                domain: Domain::from_host(host)?,
                ..
                cookie
            })
        }).map_payload(|payload| {
            Ok(Payload {
                suffix_domain: false,
                ..
                payload
            })
        })

    }

    /// Set the host for a cookie to match a given string.
    pub fn host_str(self, host: &str) -> Builder {
        match Host::parse(host) {
            Ok(host) => self.host(host),
            Err(error) => Builder::Err(error.into()),
        }
    }

    /// Set the domain for a cookie to match a a given domain and all subdomains.
    pub fn domain(self, domain: &str) -> Builder {
        let domain = try_build!(domain_to_ascii(domain));
        self.map(|cookie| {
            Ok(Cookie {
                domain: Domain::Suffix(domain),
                ..
                cookie
            })
        }).map_payload(|payload| {
            Ok(Payload {
                suffix_domain: true,
                ..
                payload
            })
        })
    }

    /// Set the path for a cookie to be matched in.
    pub fn path(self, path: &str) -> Builder {
        self.map(|cookie| {
            Ok(Cookie {
                path: path.to_owned(),
                ..
                cookie
            })
        })
    }

    /// Set the key, value pair for the cookie.
    pub fn pair(self, pair: Pair) -> Builder {
        self.map_payload(|payload| {
            Ok(Payload {
                pair: pair,
                ..
                payload
            })
        })
    }

    /// Set the key, value pair for the cookie from a string.
    pub fn pair_str(self, pair: &str) -> Builder {
        match pair.parse() {
            Ok(pair) => self.pair(pair),
            Err(error) => Builder::Err(error.into())
        }
    }

    /// Set the expiry time of a cookie.
    pub fn expiry(self, time: Tm) -> Builder {
        self.map_payload(|payload| {
            Ok(Payload {
                expiry: Expires::AtUtc(time),
                ..
                payload
            })
        })
    }

    /// Set whether or not the cookie requires a secure connection.
    pub fn secure(self, secure: bool) -> Builder {
        self.map_payload(|payload| {
            Ok(Payload {
                secure: secure,
                ..
                payload
            })
        })
    }

    /// Set whether a cookie should only be sent of HTTP/HTTPS connections.
    pub fn http_only(self, http_only: bool) -> Builder {
        self.map_payload(|payload| {
            Ok(Payload {
                http_only: http_only,
                ..
                payload
            })
        })
    }

    /// Build the cookie.
    pub fn build(self) -> Result<Cookie> {
        match self {
            Builder::Cookie(cookie) => Ok(cookie),
            Builder::Err(error) => Err(error),
        }
    }

    fn map<F>(self, f: F) -> Builder
    where
        F: FnOnce(Cookie) -> Result<Cookie>,
    {
        if let Builder::Cookie(cookie) = self {
            match f(cookie) {
                Ok(cookie) => Builder::Cookie(cookie),
                Err(error) => Builder::Err(error),
            }
        } else {
            self
        }
    }

    fn map_payload<F>(self, f:F) -> Builder
    where
        F: FnOnce(Payload) -> Result<Payload>
    {
        self.map(|cookie| {
            Ok(Cookie {
                payload: f(cookie.payload)?,
                ..
                cookie
            })
        })
    }
}

/// This is the form that the cookie is represented in within the jar.
/// It is formed by parsing the provided string into a cookie object.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cookie {
    /// Domain or host restriction of the cookie.
    domain: Domain,

    /// Path restriction of the cookie.
    path: String,

    /// The cookie contents and security requirements.
    payload: Payload,
}

/// The payload of the cookie including security requirements.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Payload {
    /// Data stored within the cookie (key = value pair).
    pair: Pair,

    /// The expiration time of the cookie in UTC.
    expiry: Expires,

    /// If the cookie also applies to subdomains.
    suffix_domain: bool,

    /// The cookie can only be sent over a TLS connection.
    secure: bool,

    /// The cookie can only be sent via a HTTP (or HTTPS) connection.
    http_only: bool,
}

impl Cookie {
    /// Decode a string cookie from a given origin.
    pub fn decode(cookie: &str, origin: &Url) -> Result<Cookie> {
        let builder = Builder::new().origin(origin);
        Cookie::parse_onto_builder(cookie, builder)
    }

    /// Parse a string as a cookie that applies to the 0.0.0.0 domain.
    pub fn parse_global(cookie: &str) -> Result<Cookie> {
        Cookie::parse_onto_builder(cookie, Builder::new())
    }

    /// Parse a given cookie into a builder.
    pub fn parse_onto_builder(cookie: &str, mut builder: Builder) -> Result<Cookie> {
        let (pair, args) = process_cookie(cookie)?;
        builder = builder.pair(pair);

        // If a Max-Age argument has been seen, Expires should be ignored.
        let mut use_max_age = false;

        for arg in args {
            match (arg?, use_max_age) {
                (Argument::Expires(time), false) => {
                    builder = builder.expiry(time);
                }
                (Argument::MaxAge(duration), _) => {
                    builder = builder.expiry(now_utc() + duration);
                    use_max_age = true;
                }
                (Argument::Domain(domain), _) => {
                    builder = builder.domain(domain);
                }
                (Argument::Path(path), _) => {
                    builder = builder.path(path);
                }
                (Argument::Secure, _) => {
                    builder = builder.secure(true);
                }
                (Argument::HttpOnly, _) => {
                    builder = builder.http_only(true);
                }
                // Ignore all others
                _ => {}
            }
        }

        builder.build()
    }

    /// Get the name of the cookie.
    pub fn name(&self) -> &str {
        self.payload.pair.name()
    }

    /// Get the value of a cookie.
    pub fn value(&self) -> &str {
        self.payload.pair.value()
    }

    /// Get the (name, value) pair of a cookie.
    pub fn pair(&self) -> (&str, &str) {
        self.payload.pair.as_tuple()
    }

    /// Get the formatted `name=value` pair string of a cookie.
    ///
    /// Preserves any quotation from the original cookie as read.
    pub fn pair_str(&self) -> &str {
        self.payload.pair.as_str()
    }

    /// Check if the cookie requires a secure connection.
    pub fn secure(&self) -> bool {
        self.payload.secure
    }

    /// Check if the cookie should only be sent over http requests.
    pub fn http_only(&self) -> bool {
        self.payload.http_only
    }

    /// Check if the cookie is host-only.
    pub fn host_only(&self) -> bool {
        match self.domain {
            Domain::Host(_) => true,
            Domain::Suffix(_) => false,
        }
    }

    /// Check if the cookie has expired.
    pub fn expired(&self) -> bool {
        self.expired_since(now_utc())
    }

    /// Check if the cookie was expired after a given time.
    pub fn expired_since(&self, time: Tm) -> bool {
        match self.payload.expiry {
            Expires::Never => false,
            Expires::AtUtc(expiry) => time >= expiry,
        }
    }

    /// Get the expiry of the cookie.
    pub fn expiry(&self) -> &Expires {
        &self.payload.expiry
    }

    /// Get the domain or host the cookie applies to.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// Get the domain name associated with the cookie.
    ///
    /// None if the cookie is host-only for an IP address.
    pub fn domain_name(&self) -> Option<&str> {
        match self.domain {
            Domain::Suffix(ref domain) => Some(&domain),
            Domain::Host(Host::Domain(ref domain)) => Some(&domain),
            _ => None,
        }
    }

    /// Get the path the cookie applies to.
    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    /// Check if a cookie should replace another cookie.
    pub fn replaces(&self, other: &Cookie) -> bool {
        self.payload.pair.name() == other.payload.pair.name()
            && self.path == other.path
            && self.domain_name() == other.domain_name()
    }

    /// Check if a cookie applies to a particular request URL.
    pub fn applies_to(&self, url: Url) -> bool {
        unimplemented!()
    }
}

/// Expiry time of a cookie.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Expires {
    /// The cookie expires at a specified time from UTC.
    AtUtc(Tm),
    /// The cookie never expires.
    Never,
}

impl Default for Expires {
    fn default() -> Expires {
        Expires::Never
    }
}

/// Domain for a specific cookie
///
/// The default domain is for the "0.0.0.0" host and should not match any requests.
#[derive(Debug, Eq, PartialEq)]
pub enum Domain {
    /// The cookies only applies to a specific host.
    Host(Host),
    /// The cookie applies the given domain and all subdomains.
    Suffix(String),
}

impl Default for Domain {
    fn default() -> Domain {
        use std::net::Ipv4Addr;
        Domain::Host(Host::Ipv4(Ipv4Addr::new(0, 0, 0, 0)))
    }
}

impl Domain {
    fn from_host(host: Host) -> Result<Domain> {
        let host = match host {
            Host::Domain(domain) => Host::Domain(domain_to_ascii(&domain)?),
            host => host,
        };
        Ok(Domain::Host(host))
    }
}

/// Get the directory of the path of a Url.
fn url_dir_path(url: &Url) -> &str {
    let path = url.path();
    if path.ends_with('/') {
        path
    } else {
        let end = path.rfind('/').unwrap();
        &path[0..=end]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// Examples from [RFC6265](https://tools.ietf.org/html/rfc6265).
    fn parse_rfc_examples() {
        let origin = "http://www.example.com/path/to/page.html".parse().unwrap();
        let examples = [
            (
                "SID=31d4d96e407aad42",
                Builder::new()
                    .host_str("www.example.com")
                    .path("/path/to/")
                    .pair_str("SID=31d4d96e407aad42")
                    .build()
                    .unwrap(),
            ),
            (
                "SID=31d4d96e407aad42; Path=/; Domain=example.com",
                Builder::new()
                    .domain("example.com")
                    .path("/")
                    .pair_str("SID=31d4d96e407aad42")
                    .build()
                    .unwrap(),
            ),
            (
                "SID=31d4d96e407aad42; Path=/; Secure; HttpOnly",
                Builder::new()
                    .host_str("www.example.com")
                    .path("/")
                    .pair_str("SID=31d4d96e407aad42")
                    .http_only(true)
                    .secure(true)
                    .build()
                    .unwrap(),
            ),
            (
                "lang=en-US; Path=/; Domain=example.com",
                Builder::new()
                    .domain("example.com")
                    .path("/")
                    .pair_str("lang=en-US")
                    .build()
                    .unwrap(),
            ),
        ];

        for &(cookie_str, ref expected) in examples.iter() {
            let cookie = Cookie::decode(cookie_str, &origin).expect("Could not parse cookie");
            assert_eq!(&cookie, expected);
        }
    }

    // TODO: Test for use of last attribute of given name to determine setting on cookie.

    // TODO: Test for ignored unknown attributes.

    // TODO: Test for precedence of Max-Age over Expires attributes.
}
