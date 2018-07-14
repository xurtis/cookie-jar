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
use std::iter;
use std::net::IpAddr;

use url::{Url, Host};
use time::{Tm, now_utc};

use ::cookie::{Cookie, Attributes, Pair, url_dir_path};

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

    /// Get the matching cookies for a Url.
    pub fn url_matches<'j>(&'j self, url: &'j Url) -> impl Iterator<Item = &'j Pair> {
        let path_segments = url_dir_path(url).trim_left_matches('/').split('/');
        match url.host() {
            Some(Host::Domain(domain)) => {
                let domain_segments: Vec<_> = domain.trim_matches('.').split('.').collect();
                self.domain.match_url(domain_segments, path_segments)
            }
            Some(Host::Ipv4(addr)) => self.host_matches(IpAddr::V4(addr), path_segments),
            Some(Host::Ipv6(addr)) => self.host_matches(IpAddr::V6(addr), path_segments),
            _ => Box::new(iter::empty()),
        }
    }

    /// Get all of the matches for a specific host.
    fn host_matches<'j, 's, S>(&'j self, host: IpAddr, segments: S)
        -> Box<Iterator<Item = &'j Pair> + 'j>
    where
        S: Iterator<Item = &'s str> + 's,
    {
        if let Some(host) = self.hosts.get(&host) {
            host.match_url(segments, HostMatch::Exact)
        } else {
            Box::new(iter::empty())
        }
    }
}

/// The given URL is an exact host match.
#[derive(PartialEq, Eq, Clone, Copy)]
enum HostMatch {
    Exact,
    Suffix,
}

/// The heirarchy of domains.
#[derive(Debug, Default)]
struct Domain {
    path: Path,
    children: HashMap<String, Domain>,
}

impl Domain {
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

    /// Get all of the attributes that match a given request URL.
    pub fn match_url<'c, 'p, P>(&'c self, mut segments: Vec<&str>, path: P)
        -> Box<Iterator<Item = &'c Pair> + 'c>
    where
        P: Iterator<Item = &'p str> + 'p + Clone,
    {

        if let Some(child) = segments.pop() {
            let iter = self.path.match_url(path.clone(), HostMatch::Suffix);
            if let Some(child) = self.children.get(child) {
                Box::new(iter.chain(child.match_url(segments, path)))
            } else {
                Box::new(iter)
            }
        } else {
            Box::new(self.path.match_url(path, HostMatch::Exact))
        }
    }
}

/// The heriarchy of paths.
#[derive(Debug, Default)]
struct Path {
    cookies: HashMap<String, Attributes>,
    children: HashMap<String, Path>,
}

impl Path {
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

    /// Get all of the attributes that match a given request URL.
    pub fn match_url<'c, 's, S>(&'c self, mut segments: S, host: HostMatch)
        -> Box<Iterator<Item = &'c Pair> + 'c>
    where
        S: Iterator<Item = &'s str> + 's,
    {
        let iter = self.cookies.values()
            .filter(move |attributes| match host {
                HostMatch::Exact => true,
                HostMatch::Suffix => !attributes.host_only(),
            })
            .map(Attributes::pair);

        if let Some(child) = segments.next() {
            if let Some(child) = self.children.get(child) {
                Box::new(iter.chain(child.match_url(segments, host)))
            } else {
                Box::new(iter)
            }
        } else {
            Box::new(iter)
        }
    }
}
