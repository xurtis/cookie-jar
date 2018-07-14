//! Representation of a cookie within the value store.

mod parse;

use std::ops::Deref;

use self::parse::{process_cookie, Argument};
pub use self::parse::Pair;
use error::*;
use time::{now_utc, strftime, Tm};
use url::{Host, Url};

/// A builder for a cookie.
#[derive(Default, Debug)]
pub struct Builder<'u> {
    /// The associated host for the cookie.
    host: Option<Host>,

    /// The associated path for the cookie.
    path: Option<String>,

    /// The scheme used to transmit a given cookie.
    scheme: Option<Scheme<'u>>,

    /// The cookie attributes.
    attributes: Attributes,

    /// Any error that has occured.
    error: Option<Error>,
}

impl<'u> From<parser::Error> for Builder<'u> {
    fn from(e: parser::Error) -> Builder<'u> {
        Builder {
            error: Some(e.into()),
            ..
            Builder::default()
        }
    }
}

impl<'u> From<Error> for Builder<'u> {
    fn from(e: Error) -> Builder<'u> {
        Builder {
            error: Some(e),
            ..
            Builder::default()
        }
    }
}

impl<'u> Builder<'u> {
    /// Create a new cookie builder.
    ///
    /// The default cookie applies only to the root domain and to all paths beneath it.
    pub fn new() -> Builder<'u> {
        Builder::default()
    }

    /// Set the error of the builder.
    fn error(mut self, error: Error) -> Builder<'u> {
        if self.error.is_none() {
            self.error = Some(error);
        }
        self
    }

    /// Set the origin from which the cookie came.
    pub fn origin(self, origin: &'u Url) -> Builder<'u> {
        if let Some(host) = origin.host() {
            Builder {
                host: Some(host.to_owned()),
                path: Some(url_dir_path(origin).to_owned()),
                scheme: Some(origin.into()),
                attributes: Attributes {
                    host_only: true,
                    ..
                    self.attributes
                },
                ..
                self
            }
        } else {
            self.error(ErrorKind::InvalidOrigin(origin.clone()).into())
        }
    }

    /// Set the domain for the cookie to match a single domain.
    pub fn host(self, host: Host) -> Builder<'u> {
        Builder {
            host: Some(host),
            attributes: Attributes {
                host_only: true,
                ..
                self.attributes
            },
            ..
            self
        }
    }

    /// Set the host for a cookie to match a given string.
    pub fn host_str(self, host: &str) -> Builder<'u> {
        match Host::parse(host) {
            Ok(host) => self.host(host),
            Err(error) => self.error(error.into()),
        }
    }

    /// Set the domain for a cookie to match a a given domain and all subdomains.
    pub fn domain(self, domain: &str) -> Builder<'u> {
        match Host::parse(domain) {
            Ok(host) => Builder {
                host: Some(host),
                attributes: Attributes {
                    host_only: false,
                    ..
                    self.attributes
                },
                ..
                self
            },
            Err(error) => self.error(error.into()),
        }
    }

    /// Set the path for a cookie to be matched in.
    pub fn path(self, path: &str) -> Builder<'u> {
        Builder {
            path: Some(path.to_owned()),
            ..
            self
        }
    }

    /// Set the key, value pair for the cookie.
    pub fn pair(self, pair: Pair) -> Builder<'u> {
        Builder {
            attributes: Attributes {
                pair: pair,
                ..
                self.attributes
            },
            ..
            self
        }
    }

    /// Set the key, value pair for the cookie from a string.
    pub fn pair_str(self, pair: &str) -> Builder<'u> {
        match pair.parse() {
            Ok(pair) => self.pair(pair),
            Err(error) => self.error(error.into())
        }
    }

    /// Set the expiry time of a cookie.
    pub fn expiry(self, time: Tm) -> Builder<'u> {
        Builder {
            attributes: Attributes {
                expiry: Expires::AtUtc(time),
                ..
                self.attributes
            },
            ..
            self
        }
    }

    /// Set whether or not the cookie requires a secure connection.
    pub fn secure(self, secure: bool) -> Builder<'u> {
        if let Some(scheme) = self.scheme {
            if secure && !scheme.is_secure() {
                return self.error(ErrorKind::InsecureOrigin.into());
            }
        };

        Builder {
            attributes: Attributes {
                secure: secure,
                ..
                self.attributes
            },
            ..
            self
        }
    }

    /// Set whether a cookie should only be sent of HTTP/HTTPS connections.
    pub fn http_only(self, http_only: bool) -> Builder<'u> {
        if let Some(scheme) = self.scheme {
            if http_only && !scheme.is_http() {
                return self.error(ErrorKind::NonHttpOrigin.into());
            }
        };

        Builder {
            attributes: Attributes {
                http_only: http_only,
                ..
                self.attributes
            },
            ..
            self
        }
    }

    /// Build the SetCookie.
    pub fn build_set_cookie(self) -> Result<SetCookie> {
        match self {
            Builder {
                host: _,
                path: _,
                attributes: _,
                scheme: _,
                error: Some(error),
            } => Err(error),
            Builder {
                host: Some(Host::Domain(domain)),
                path,
                attributes,
                scheme: _,
                error: None,
            } => Ok(SetCookie {
                domain: Some(domain),
                path: path,
                attributes: attributes,
            }),
            Builder {
                host: None,
                path,
                attributes,
                scheme: _,
                error: None,
            } => Ok(SetCookie {
                domain: None,
                path: path,
                attributes: attributes,
            }),
            _ => Err(ErrorKind::HostInvalid.into()),
        }
    }

    /// Build the Cookie.
    pub fn build_cookie(self) -> Result<Cookie> {
        match self {
            Builder {
                host: _,
                path: _,
                attributes: _,
                scheme: _,
                error: Some(error),
            } => Err(error),
            Builder {
                host: None,
                path: _,
                attributes: _,
                scheme: _,
                error: None,
            } => Err(ErrorKind::MissingDomain.into()),
            Builder {
                host: _,
                path: None,
                attributes: _,
                scheme: _,
                error: None,
            } => Err(ErrorKind::MissingDomain.into()),
            Builder {
                host: Some(host),
                path: Some(path),
                attributes,
                scheme: _,
                error: None,
            } => Ok(Cookie {
                host: host,
                path: path,
                attributes: attributes,
            }),
        }
    }

    /// Parse a given cookie into a builder.
    fn parse(self, cookie: &str) -> Result<Builder<'u>> {
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
    domain: Option<String>,

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
    pub fn parse(cookie: &str) -> Result<SetCookie> {
        Builder::new().parse(cookie)?.build_set_cookie()
    }

    /// Get the domain or host the cookie applies to.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_ref().map(String::as_str)
    }

    /// Get the path the cookie applies to.
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(String::as_str)
    }
}

/// This is the form that the cookie is represented in within the jar.
/// It is formed by parsing the provided string into a cookie object.
#[derive(Debug, PartialEq, Eq)]
pub struct Cookie {
    /// Domain or host restriction of the cookie.
    host: Host,

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
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Get the domain name associated with the cookie.
    ///
    /// None if the cookie is host-only for an IP address.
    pub fn domain(&self) -> Option<&str> {
        match self.host {
            Host::Domain(ref host) => Some(&host),
            _ => None,
        }
    }

    /// Get the path the cookie applies to.
    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    pub(crate) fn explode(self) -> (Host, String, Attributes) {
        let Cookie { host, path, attributes } = self;
        (host, path, attributes)
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

    /// Get the (name, value) pair of a cookie.
    pub fn pair(&self) -> &Pair {
        &self.pair
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

impl Deref for Attributes {
    type Target = Pair;

    fn deref(&self) -> &Pair {
        &self.pair
    }
}

impl ::std::string::ToString for SetCookie {
    fn to_string(&self) -> String {
        let mut cookie = self.pair.as_str().to_owned();

        if let Some(ref path) = self.path {
            cookie = format!("{}; Path={}", cookie, path);
        }

        if let Some(ref domain) = self.domain {
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

/// Get the directory of the path of a Url.
pub(crate) fn url_dir_path(url: &Url) -> &str {
    let path = url.path();
    if path.ends_with('/') {
        path
    } else {
        let end = path.rfind('/').unwrap();
        &path[0..=end]
    }
}

/// The transport scheme for a URI.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Scheme<'u> {
    Http,
    Https,
    Other(&'u str),
}

impl<'u> From<&'u Url> for Scheme<'u> {
    fn from(url: &'u Url) -> Scheme<'u> {
        match url.scheme() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            scheme => Scheme::Other(scheme)
        }
    }
}

impl<'u> Scheme<'u> {
    fn is_http(&self) -> bool {
        match self {
            Scheme::Http | Scheme::Https => true,
            _ => false,
        }
    }

    fn is_secure(&self) -> bool {
        match self {
            Scheme::Https => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_scheme() {
        assert_eq!(Scheme::Http, Scheme::from(&"http://example.com".parse::<Url>().unwrap()));
        assert_eq!(Scheme::Https, Scheme::from(&"https://example.com".parse::<Url>().unwrap()));
        assert_eq!(Scheme::Other("ftp"), Scheme::from(&"ftp://example.com".parse::<Url>().unwrap()));
    }

    #[test]
    /// Examples from [RFC6265](https://tools.ietf.org/html/rfc6265).
    fn parse_rfc_examples() {
        let origin = "https://www.example.com/path/to/page.html".parse().unwrap();
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
