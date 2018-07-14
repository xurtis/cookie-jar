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

use std::collections::HashMap;
use std::net::IpAddr;
use std::path;

use url::{Url, Host};
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
    hosts: HashMap<IpAddr, Path>,
}

impl Default for Jar<ClockFn> {
    fn default() -> Jar<ClockFn> {
        Jar {
            clock: now_utc,
            domain: Default::default(),
            hosts: Default::default(),
        }
    }
}

impl<T: Clock> Jar<T> {
    /// Create a new empty jar.
    pub fn new() -> Jar<ClockFn> {
        Default::default()
    }

    /// Create a jar with a specific time source.
    pub fn with_clock(clock: T) -> Jar<T> {
        Jar {
            clock: clock,
            domain: Default::default(),
            hosts: Default::default(),
        }
    }

    /// Add a cookie to the jar.
    pub fn add_cookie(&mut self, cookie: Cookie) {
        let (host, path, attributes) = cookie.explode();
        let path_segments = path.trim_left_matches('/').split('/');
        match host {
            Host::Domain(domain) => {
                let domain_segments: Vec<_> = domain.trim_matches('.').split('.').collect();
                self.domain.add_cookie(domain_segments, path_segments, attributes);
            }
            Host::Ipv4(addr) => {
                self.update_host(IpAddr::V4(addr), path_segments, attributes);
            }
            Host::Ipv6(addr) => {
                self.update_host(IpAddr::V6(addr), path_segments, attributes);
            }
        }
    }

    /// Update a cookie for a host.
    fn update_host<'s, S>(&mut self, host: IpAddr, segments: S, attributes: Attributes)
    where
        S: Iterator<Item = &'s str> + 's,
    {
        self.hosts.entry(host)
            .or_insert_with(Path::default)
            .add_cookie(segments, attributes);
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

    /// Add a set of cookie attributes to a domain.
    pub fn add_cookie<'p, P>(&mut self, mut segments: Vec<&str>, path: P, attributes: Attributes)
    where
        P: Iterator<Item = &'p str> + 'p,
    {
        if let Some(child) = segments.pop() {
            self.children.entry(child.to_owned())
                .or_insert_with(Domain::default)
                .add_cookie(segments, path, attributes);
        } else {
            self.path.add_cookie(path, attributes);
        }
    }
}

/// A wrapper around a cookie producing fragments of the domain.
struct DomainFragments {
    cookie: Cookie,
    start: usize,
    length: usize,
}

/// The heriarchy of paths.
#[derive(Debug, Default)]
struct Path {
    cookies: HashMap<String, Attributes>,
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

    /// Add a cookie to the matching path.
    pub fn add_cookie<'s, S>(&mut self, mut segments: S, attributes: Attributes)
    where
        S: Iterator<Item = &'s str> + 's,
    {
        if let Some(child) = segments.next() {
            self.children
                .entry(child.to_owned())
                .or_insert_with(Path::default)
                .add_cookie(segments, attributes);
        } else {
            self.cookies.insert(attributes.pair().name().to_owned(), attributes);
        }
    }
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
