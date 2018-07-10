//! Iterators that produce cookies.

use url::Url;

use ::cookie::Cookie;
use ::error::*;

/// A trait representing the source of a set of cookie strings.
///
/// This is applied to anything that produces cookies to represent the source of the cookie.
pub trait SimpleCookieSource {
    /// The URL for which the response was produced.
    fn url(&self) -> &Url;

    /// Produce a collection of cookies as strings.
    fn cookie_strings(&self) -> Vec<&str>;
}

/// A trait representing the source of a set of cookies.
pub trait CookieSource {
    /// Produce a collection of cookies.
    fn cookies(&self) -> Vec<Cookie>;
}

/// An iterator that iterates over a collection of strings to produce a collection of cookies.
#[derive(Debug)]
pub struct CookieIter<'u, I> {
    /// The source of the cookie strings.
    source: I,
    /// The URL the cookies are associated with.
    url: &'u Url,
}

impl<'s> From<&'s CookieSource> for CookieIter<'s, ::std::vec::IntoIter<&'s str>> {
    fn from(source: &'s CookieSource) -> Self {
        Self {
            source: source.cookies().into_iter(),
            url: source.url(),
        }
    }
}

impl<'u, 's, I, S> CookieIter<'u, I>
where
    S: AsRef<str> + 's,
    I: Iterator<Item = S>
{
    /// Create a new iterator over strings to produce cookies.
    pub fn new(cookie_strings: I, url: &'u Url) -> CookieIter<'u, I> {
        CookieIter {
            source: cookie_strings,
            url: url,
        }
    }
}

impl<'u, 's, I, S> Iterator for CookieIter<'u, I>
where
    I: Iterator<Item = S>,
    S: AsRef<str> + 's,
{
    type Item = Result<Cookie>;

    fn next(&mut self) -> Option<Result<Cookie>> {
        self.source.next().map(|s| Cookie::decode(s.as_ref(), self.url))
    }
}

// May not wont this as it would conflict eith existing IntoIterator impls.
#[cfg(not(all))]
impl<'s> IntoIterator for &'s CookieSource {
    type Item = Result<Cookie>;
    type IntoIter = CookieIter<'s, ::std::vec::IntoIter<&'s str>>;

    fn into_iter(self) -> CookieIter<'s, ::std::vec::IntoIter<&'s str>> {
        self.into()
    }
}
