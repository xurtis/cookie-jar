//! Representation of a cookie within the value store.

mod parse;

use self::parse::{process_cookie, Argument, CookiePair};
use error::*;
use idna::domain_to_ascii;
use std::str::FromStr;
use time::{now_utc, Duration, Tm};
use url::{Host, Url};

/// This is the form that the cookie is represented in within the jar.
/// It is formed by parsing the provided string into a cookie object.
#[derive(Debug, PartialEq, Eq)]
pub struct Cookie {
    /// Data stored within the cookie (key = value pair).
    pair: CookiePair,

    /// The expiration time of the cookie in UTC.
    expiry: Expires,

    /// Domain or host restriction of the cookie.
    domain: Domain,

    /// Path restriction of the cookie.
    path: String,

    /// The cookie can only be sent over a TLS connection.
    secure: bool,

    /// The cookie can only be sent via a HTTP (or HTTPS) connection.
    http_only: bool,
}

impl Cookie {
    /// Decode a string cookie from a given origin.
    pub fn decode(cookie: &str, origin: &Url) -> Result<Cookie> {
        let (pair, args) = process_cookie(cookie)?;
        let mut cookie = Cookie::default(pair, origin)?;

        // If a Max-Age argument has been seen, Expires should be ignored.
        let mut use_max_age = false;

        for arg in args {
            match (arg?, use_max_age) {
                (Argument::Expires(time), false) => {
                    cookie.expiry = Expires::AtUtc(time);
                }
                (Argument::MaxAge(duration), _) => {
                    cookie.expiry = Expires::AtUtc(now_utc() + duration);
                    use_max_age = true;
                }
                (Argument::Domain(domain), _) => {
                    cookie.domain = Domain::Suffix(domain.to_string());
                }
                (Argument::Path(path), _) => {
                    cookie.path = path.to_string();
                }
                (Argument::Secure, _) => {
                    cookie.secure = true;
                }
                (Argument::HttpOnly, _) => {
                    cookie.http_only = true;
                }
                // Ignore all others
                _ => {}
            }
        }

        Ok(cookie)
    }

    /// Default value for a cookie with no additional flags.
    fn default(pair: CookiePair, origin: &Url) -> Result<Cookie> {
        let domain = origin
            .host()
            .ok_or_else(|| ErrorKind::InvalidOrigin(origin.clone()))?
            .to_owned();
        Ok(Cookie {
            pair: pair,
            expiry: Expires::Never,
            domain: Domain::from_host(domain)?,
            path: url_dir_path(origin).to_string(),
            secure: false,
            http_only: false,
        })
    }

    /// Get the name of the cookie.
    pub fn name(&self) -> &str {
        self.pair.name()
    }

    /// Get the value of a cookie.
    pub fn value(&self) -> &str {
        self.pair.value()
    }

    /// Get the (name, value) pair of a cookie.
    pub fn pair(&self) -> (&str, &str) {
        self.pair.as_tuple()
    }

    /// Get the formatted `name=value` pair string of a cookie.
    ///
    /// Preserves any quotation from the original cookie as read.
    pub fn str_pair(&self) -> &str {
        self.pair.as_str()
    }

    /// Check if the cookie requires a secure connection.
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Check if the cookie should only be sent over http requests.
    pub fn http_only(&self) -> bool {
        self.http_only
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
        match self.expiry {
            Expires::Never => false,
            Expires::AtUtc(expiry) => now_utc() >= expiry,
        }
    }

    /// Get the expiry of the cookie.
    pub fn expiry(&self) -> &Expires {
        &self.expiry
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
        self.pair.name() == other.pair.name()
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

/// Domain for a specific cookie
#[derive(Debug, Eq, PartialEq)]
pub enum Domain {
    /// The cookies only applies to a specific host.
    Host(Host),
    /// The cookie applies the given domain and all subdomains.
    Suffix(String),
}

impl Domain {
    fn from_host(host: Host) -> Result<Domain> {
        let host = match host {
            Host::Domain(domain) => {
                Host::Domain(domain_to_ascii(&domain).map_err(ErrorKind::InvalidDomain)?)
            }
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
                Cookie {
                    pair: "SID=31d4d96e407aad42".parse().unwrap(),
                    expiry: Expires::Never,
                    domain: Domain::Host(Host::Domain("www.example.com".to_string())),
                    path: "/path/to/".to_string(),
                    secure: false,
                    http_only: false,
                },
            ),
            (
                "SID=31d4d96e407aad42; Path=/; Domain=example.com",
                Cookie {
                    pair: "SID=31d4d96e407aad42".parse().unwrap(),
                    expiry: Expires::Never,
                    domain: Domain::Suffix("example.com".to_string()),
                    path: "/".to_string(),
                    secure: false,
                    http_only: false,
                },
            ),
            (
                "SID=31d4d96e407aad42; Path=/; Secure; HttpOnly",
                Cookie {
                    pair: "SID=31d4d96e407aad42".parse().unwrap(),
                    expiry: Expires::Never,
                    domain: Domain::Host(Host::Domain("www.example.com".to_string())),
                    path: "/".to_string(),
                    secure: true,
                    http_only: true,
                },
            ),
            (
                "lang=en-US; Path=/; Domain=example.com",
                Cookie {
                    pair: "lang=en-US".parse().unwrap(),
                    expiry: Expires::Never,
                    domain: Domain::Suffix("example.com".to_string()),
                    path: "/".to_string(),
                    secure: false,
                    http_only: false,
                },
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
