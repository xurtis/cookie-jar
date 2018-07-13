//! A cookie jar.
//!
//! The cookie jar is responsible for storing and maintaining a set of cookies.
//! It takes cookies from cookie recievers such as HTTP responses and applies them to appropriate
//! cookie senders such as HTTP requests.
//!
//! The jar is also responsible for managing the expiry of cookies and expunging cookies.
//!
//! The jar is structured as a tree representing the domains the the paths for which it has
//! stored values. The jar contains a root domain which branches out into its
//! subdomains. Similarly, each domain contains its root path which branches out into its
//! sub-paths.

use std::borrow::Cow;
use std::collections::HashMap;

use url::Url;
use time::{Tm, now_utc};

use ::cookie::{Cookie, Attributes, Pair};

/// A carrier of cookies being sent to a server.
///
/// This trait represents somthing that is used to send cookies. Usually some
/// representation of a HTTP request.
pub trait Carrier {
    /// The URL for which a request is being sent.
    fn url(&self) -> &Url;

    /// Add a cookie onto the sender.
    fn cookies(&mut self);
}

/// Something that produces the current UTC time.
pub trait Clock {

    /// Get the current UTC time.
    fn now(&self) -> Tm;
}

/// A function that produces the current time in UTC.
pub type ClockFn = fn() -> Tm;

impl Clock for ClockFn {
    fn now(&self) -> Tm {
        self()
    }
}

/// A jar containing the cookies seen so far.
#[derive(Debug)]
pub struct Jar<T: Clock> {
    clock: T,
    domain: Domain,
}

impl Default for Jar<ClockFn> {
    fn default() -> Jar<ClockFn> {
        Jar {
            clock: now_utc,
            domain: Default::default(),
        }
    }
}

impl<T: Clock> Jar<T> {
    /// Create a new empty jar.
    pub fn new() -> Jar<ClockFn> {
        Jar {
            clock: now_utc,
            domain: Default::default(),
        }
    }

    /// Create a jar with a specific time source.
    pub fn with_clock(clock: T) -> Jar<T> {
        Jar {
            clock: clock,
            domain: Default::default(),
        }
    }

    /// Add a cookie to the jar.
    pub fn add_cookie(&mut self, cookie: &Cookie) {
        unimplemented!()
    }

    /// Take all cookies from a reciever.
    pub fn take_cookies<I, C>(&mut self, cookies: I)
    where
        I: Iterator<Item = C>,
        C: AsRef<Cookie>,
    {
        unimplemented!()
    }

    /// Get the matching cookies for a Url.
    pub fn url_matches<'j>(&'j self, url: &'j Url) -> impl Iterator<Item = &'j Pair> {
        self.domain.url_matches(url).map(Attributes::pair)
    }
}

/// The heirarchy of domains.
#[derive(Debug, Default)]
struct Domain {
    path: Path,
    children: HashMap<String, Domain>,
}

impl Domain {
    /// Finds all of the matching attributes for a given url.
    pub fn url_matches<'j>(&'j self, url: &'j Url) -> Box<dyn Iterator<Item = &'j Attributes> + 'j> {
        let iter = self.children.iter()
            .filter(parent_domains(url))
            .flat_map(move |(_, v)| v.url_matches(url))
            .chain(self.path.url_matches(url));
        Box::new(iter)
    }
}

/// The heriarchy of paths.
#[derive(Debug, Default)]
struct Path {
    cookies: Vec<Attributes>,
    children: HashMap<String, Path>,
}

impl Path {
    /// Finds all of the matching attributes for a given url.
    pub fn url_matches<'j>(&'j self, url: &'j Url) -> Box<dyn Iterator<Item = &'j Attributes> + 'j> {
        let iter = self.children.iter()
            .filter(parent_paths(url))
            .flat_map(move |(_, v)| v.url_matches(url));
        Box::new(iter)
    }
}

/// An iterator over the paths matching a URL.
struct PathMatches {
}

fn parent_domains<'u, T>(url: &'u Url) -> impl (FnMut(&(&String, T)) -> bool) + 'u {
    move |(parent, _)| {
        if let Some(domain) = url.domain() {
            domain.ends_with(parent.as_str())
        } else {
            false
        }
    }
}

fn parent_paths<'u, T>(url: &'u Url) -> impl (FnMut(&(&String, T)) -> bool) + 'u {
    move |(parent, _)| url.path().starts_with(parent.as_str())
}
