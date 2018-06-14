//! Representation of a cookie within the value store.

mod parse;

use std::ops::Deref;

use self::parse::{process_cookie, Argument};
pub(crate) use self::parse::Pair;
use error::*;
use idna::domain_to_ascii;
use time::{now_utc, strftime, Tm};
use url::{Host, Url};

/// A builder for a cookie.
#[derive(Debug)]
pub enum Builder {
    /// A partially constructed cookie.
    Cookie(SetCookie),

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
        self.map(|set_cookie| {
            Ok(SetCookie {
                domain: Some(Domain::from_host(host)?),
                ..
                set_cookie
            })
        }).map_attributes(|attributes| {
            Ok(Attributes {
                host_only: true,
                ..
                attributes
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
        self.map(|set_cookie| {
            Ok(SetCookie {
                domain: Some(Domain::Suffix(domain_to_ascii(domain)?)),
                ..
                set_cookie
            })
        }).map_attributes(|attributes| {
            Ok(Attributes {
                host_only: false,
                ..
                attributes
            })
        })
    }

    /// Set the path for a cookie to be matched in.
    pub fn path(self, path: &str) -> Builder {
        self.map(|set_cookie| {
            Ok(SetCookie {
                path: Some(path.to_owned()),
                ..
                set_cookie
            })
        })
    }

    /// Set the key, value pair for the cookie.
    pub fn pair(self, pair: Pair) -> Builder {
        self.map_attributes(|attributes| {
            Ok(Attributes {
                pair: pair,
                ..
                attributes
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
        self.map_attributes(|attributes| {
            Ok(Attributes {
                expiry: Expires::AtUtc(time),
                ..
                attributes
            })
        })
    }

    /// Set whether or not the cookie requires a secure connection.
    pub fn secure(self, secure: bool) -> Builder {
        self.map_attributes(|attributes| {
            Ok(Attributes {
                secure: secure,
                ..
                attributes
            })
        })
    }

    /// Set whether a cookie should only be sent of HTTP/HTTPS connections.
    pub fn http_only(self, http_only: bool) -> Builder {
        self.map_attributes(|attributes| {
            Ok(Attributes {
                http_only: http_only,
                ..
                attributes
            })
        })
    }

    /// Build the SetCookie.
    pub fn build_set_cookie(self) -> Result<SetCookie> {
        match self {
            Builder::Cookie(set_cookie) => Ok(set_cookie),
            Builder::Err(error) => Err(error),
        }
    }

    /// Build the Cookie.
    pub fn build_cookie(self) -> Result<Cookie> {
        match self {
            Builder::Cookie( SetCookie {
                domain: None,
                path: _,
                attributes: _,
            }) => Err(ErrorKind::MissingDomain.into()),
            Builder::Cookie( SetCookie {
                domain: _,
                path: None,
                attributes: _,
            }) => Err(ErrorKind::MissingDomain.into()),
            Builder::Cookie( SetCookie {
                domain: Some(domain),
                path: Some(path),
                attributes: attributes,
            }) => Ok(Cookie {
                domain: domain,
                path: path,
                attributes: attributes,
            }),
            Builder::Err(error) => Err(error),
        }
    }

    fn map<F>(self, f: F) -> Builder
    where
        F: FnOnce(SetCookie) -> Result<SetCookie>,
    {
        match self {
            Builder::Cookie(set_cookie) => match f(set_cookie) {
                Ok(set_cookie) => Builder::Cookie(set_cookie),
                Err(error) => Builder::Err(error),
            },
            _ => return self,
        }
    }

    fn map_attributes<F>(self, f:F) -> Builder
    where
        F: FnOnce(Attributes) -> Result<Attributes>
    {
        if let Builder::Cookie(set_cookie) = self {
            match f(set_cookie.attributes) {
                Ok(attributes) => Builder::Cookie( SetCookie {
                    attributes: attributes,
                    ..
                    set_cookie
                }),
                Err(error) => Builder::Err(error),
            }
        } else {
            self
        }
    }

    /// Parse a given cookie into a builder.
    fn parse(self, cookie: &str) -> Result<Builder> {
        let (pair, args) = process_cookie(cookie)?;
        let mut builder = self.pair(pair);

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

        Ok(builder)
    }
}

/// The SetCookie directive sent from the server.
#[derive(Debug, Default)]
pub struct SetCookie {
    /// Domain or host restriction of the cookie.
    domain: Option<Domain>,

    /// Path restriction of the cookie.
    path: Option<String>,

    /// The cookie contents and security requirements.
    attributes: Attributes,
}

impl Deref for SetCookie {
    type Target = Attributes;

    fn deref(&self) -> &Attributes {
        &self.attributes
    }
}

impl SetCookie {
    /// Parse a given cookie.
    fn parse(cookie: &str) -> Result<SetCookie> {
        Builder::new().parse(cookie)?.build_set_cookie()
    }

    /// Get the domain or host the cookie applies to.
    pub fn domain(&self) -> Option<&Domain> {
        self.domain.as_ref()
    }

    /// Get the domain name associated with the cookie.
    ///
    /// None if the cookie is host-only for an IP address.
    pub fn domain_name(&self) -> Option<&str> {
        match self.domain {
            Some(Domain::Suffix(ref domain)) => Some(&domain),
            Some(Domain::Host(Host::Domain(ref domain))) => Some(&domain),
            _ => None,
        }
    }

    /// Get the path the cookie applies to.
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(String::as_str)
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
    attributes: Attributes,
}

impl Deref for Cookie {
    type Target = Attributes;

    fn deref(&self) -> &Attributes {
        &self.attributes
    }
}

impl Cookie {
    /// Parse a string cookie from a given origin.
    pub fn parse(set_cookie: &str, origin: &Url) -> Result<Cookie> {
        Builder::new()
            .origin(origin)
            .parse(set_cookie)?
            .build_cookie()
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

    /// Check if a cookie applies to a particular request URL.
    pub fn applies_to(&self, url: Url) -> bool {
        unimplemented!()
    }
}

/// The payload of the cookie including security requirements.
#[derive(Debug, PartialEq, Eq)]
pub struct Attributes {
    /// Data stored within the cookie (key = value pair).
    pair: Pair,

    /// The expiration time of the cookie in UTC.
    expiry: Expires,

    /// If the cookie also applies to subdomains.
    host_only: bool,

    /// The cookie can only be sent over a TLS connection.
    secure: bool,

    /// The cookie can only be sent via a HTTP (or HTTPS) connection.
    http_only: bool,
}

impl Default for Attributes {
    fn default() -> Attributes {
        Attributes {
            pair: Default::default(),
            expiry: Expires::Never,
            host_only: true,
            secure: false,
            http_only: false,
        }
    }
}

impl Attributes {

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
    pub fn pair_str(&self) -> &str {
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
        self.host_only
    }

    /// Check if the cookie has expired.
    pub fn expired(&self) -> bool {
        self.expired_since(now_utc())
    }

    /// Check if the cookie was expired after a given time.
    pub fn expired_since(&self, time: Tm) -> bool {
        match self.expiry {
            Expires::Never => false,
            Expires::AtUtc(expiry) => time >= expiry,
        }
    }

    /// Get the expiry of the cookie.
    pub fn expiry(&self) -> &Expires {
        &self.expiry
    }
}

impl ::std::string::ToString for SetCookie {
    fn to_string(&self) -> String {
        let mut cookie = self.pair.as_str().to_owned();

        if let Some(ref path) = self.path {
            cookie = format!("{}; Path={}", cookie, path);
        }

        if let Some(Domain::Suffix(ref domain)) = self.domain {
            cookie = format!("{}; Domain={}", cookie, domain);
        }

        if self.secure() {
            cookie = format!("{}; Secure", cookie);
        }

        if self.http_only() {
            cookie = format!("{}; HttpOnly", cookie);
        }

        if let Expires::AtUtc(ref time) = self.expiry() {
            cookie = format!(
                "{}; Expires={}",
                cookie,
                strftime("%a, %d %b %Y %T %z", time).unwrap()
            );
        }

        // Add Max-Age expiry.

        cookie
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
                    .build_cookie()
                    .unwrap(),
            ),
            (
                "SID=31d4d96e407aad42; Path=/; Domain=example.com",
                Builder::new()
                    .domain("example.com")
                    .path("/")
                    .pair_str("SID=31d4d96e407aad42")
                    .build_cookie()
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
                    .build_cookie()
                    .unwrap(),
            ),
            (
                "lang=en-US; Path=/; Domain=example.com",
                Builder::new()
                    .domain("example.com")
                    .path("/")
                    .pair_str("lang=en-US")
                    .build_cookie()
                    .unwrap(),
            ),
        ];

        for &(cookie_str, ref expected) in examples.iter() {
            let cookie = Cookie::parse(cookie_str, &origin)
                .expect("Could not parse cookie");
            assert_eq!(&cookie, expected);
        }
    }

    #[test]
    /// Examples from [RFC6265](https://tools.ietf.org/html/rfc6265).
    fn render_rfc_examples() {
        let examples = [
            (
                Builder::new()
                    .pair_str("SID=31d4d96e407aad42")
                    .build_set_cookie()
                    .unwrap(),
                "SID=31d4d96e407aad42",
            ),
            (
                Builder::new()
                    .domain("example.com")
                    .path("/")
                    .pair_str("SID=31d4d96e407aad42")
                    .build_set_cookie()
                    .unwrap(),
                "SID=31d4d96e407aad42; Path=/; Domain=example.com",
            ),
            (
                Builder::new()
                    .path("/")
                    .pair_str("SID=31d4d96e407aad42")
                    .http_only(true)
                    .secure(true)
                    .build_set_cookie()
                    .unwrap(),
                "SID=31d4d96e407aad42; Path=/; Secure; HttpOnly",
            ),
            (
                Builder::new()
                    .domain("example.com")
                    .path("/")
                    .pair_str("lang=en-US")
                    .build_set_cookie()
                    .unwrap(),
                "lang=en-US; Path=/; Domain=example.com",
            ),
        ];

        for &(ref cookie, ref expected) in examples.iter() {
            assert_eq!(&cookie.to_string(), expected);
        }
    }

    // TODO: Test for use of last attribute of given name to determine setting on cookie.

    // TODO: Test for ignored unknown attributes.

    // TODO: Test for precedence of Max-Age over Expires attributes.
}
