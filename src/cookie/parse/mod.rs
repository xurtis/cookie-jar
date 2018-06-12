//! Parsing for a cookie string.

mod date;

use error::parser::*;
use std::str::{from_utf8, FromStr};
use time::{Duration, Tm};

/// Byte is a [RFC5234](https://tools.ietf.org/html/rfc5234) CTL character.
///
/// ```text
/// CTL =  %x00-1F / %x7F ; controls
/// ```
fn is_ctl(byte: u8) -> bool {
    byte <= 0x1F || byte == 0x7F
}

/// Byte is a [RFC2616](https://tools.ietf.org/html/rfc2616) separator.
///
/// ```text
/// separator = "(" | ")" | "<" | ">" | "@"
///           | "," | ";" | ":" | "\" | <">
///           | "/" | "[" | "]" | "?" | "="
///           | "{" | "}" | SP | HT
/// ```
fn is_separator(byte: u8) -> bool {
    // TODO: This could be converted into a much faster test.
    //     Options include using fewer comparisons due to consecutive bytes
    //     being known matches.
    //     An alternative would be a lookup static table of all 256 values.
    match byte {
        b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':' | b'\\' | b'"' | b'/' | b'['
        | b']' | b'?' | b'=' | b'{' | b'}' | b' ' | b'\t' => true,
        _ => false,
    }
}

/// Byte is a [RFC2616](https://tools.ietf.org/html/rfc2616) token character.
fn is_token_octet(byte: u8) -> bool {
    !(is_ctl(byte) || is_separator(byte))
}

/// Byte is a valid cookie fragment octet.
fn is_fragment_octet(byte: u8) -> bool {
    !(is_ctl(byte) || byte == b';')
}

/// Byte is a valid [RFC6265](https://tools.ietf.org/html/rfc6265)
/// cookie-octet.
///
/// ```text
/// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
/// ```
fn is_cookie_octet(byte: u8) -> bool {
    byte == 0x21 || (byte >= 0x23 && byte <= 0x2B) || (byte >= 0x2D && byte <= 0x3A)
        || (byte >= 0x3C && byte <= 0x5B) || (byte >= 0x5D && byte <= 0x7E)
}

/// Collect a substring from a slice matching a character set.
fn collect_matching<T>(source: &[u8], test: T) -> &[u8]
where
    T: Fn(u8) -> bool,
{
    let mut len = 0;
    let source_len = source.len();
    while len < source_len && test(source[len]) {
        len += 1;
    }

    &source[0..len]
}

/// Collect a substing matching a character set that has optionally been quoted.
fn maybe_quoted<'s>(text: &'s [u8]) -> Result<Quotable<'s>> {
    if text.len() >= 1 && text[0] == b'"' {
        ensure!(
            text.len() >= 2 && text[text.len() - 1] == b'"',
            ErrorKind::MissingQuote
        );
        Ok(Quotable::Quoted(text))
    } else {
        Ok(Quotable::Plain(text))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Quotable<'s> {
    Quoted(&'s [u8]),
    Plain(&'s [u8]),
}

/// Require that a string has a non-zero length.
fn non_zero_length(s: &[u8]) -> Result<&[u8]> {
    ensure!(s.len() > 0, ErrorKind::NotEnoughBytes);
    Ok(s)
}

/// Take the next valid [RFC2616](https://tools.ietf.org/html/rfc2616)
/// token from a cookie string.
fn next_token(source: &[u8]) -> Result<&[u8]> {
    non_zero_length(collect_matching(source, is_token_octet))
}

/// Take the next valid [RFC6265](https://tools.ietf.org/html/rfc6265)
/// cookie-value.
fn next_cookie_value<'s>(source: &'s [u8]) -> Result<Quotable<'s>> {
    maybe_quoted(non_zero_length(collect_matching(source, is_cookie_octet))?)
}

/// Take the next cookie fragment.
fn next_fragment<'s>(source: &'s [u8]) -> Result<&'s [u8]> {
    non_zero_length(collect_matching(source, is_fragment_octet))
}

/// Split a cookit into its `name=value` pair and arguments.
fn split_cookie<'s>(source: &'s [u8]) -> Result<(&'s [u8], &'s [u8])> {
    let cookie = next_fragment(source.as_ref())?;
    let arguments = &source[cookie.len()..];
    Ok((cookie, arguments))
}

/// Process a cookie string into a pair and a set of arguments.
pub fn process_cookie<'s>(source: &'s str) -> Result<(CookiePair, ArgumentIter<'s>)> {
    let (cookie, arguments) = split_cookie(source.as_bytes())?;
    Ok((
        CookiePair::from_bytes(cookie)?,
        ArgumentIter::new(arguments),
    ))
}

/// A decoded cookie name=value pair.
#[derive(Debug, PartialEq, Eq)]
pub struct CookiePair {
    /// Formated `name=value` pair.
    pair: String,
    /// The length of the name at the start of the cookie.
    name_len: usize,
    /// The start and location of the value of the cookie.
    value_location: (usize, usize),
}

impl CookiePair {
    /// Create a cookie pair from a byte slice.
    fn from_bytes(source: &[u8]) -> Result<CookiePair> {
        let name = next_token(source)?;
        let value_start = name.len() + 1;
        ensure!(
            source.len() >= value_start && source[name.len()] == b'=',
            ErrorKind::MissingDelimiter
        );
        let value = next_cookie_value(&source[value_start..])?;

        let value_location = match value {
            Quotable::Quoted(value) => (value_start + 1, value.len() - 2),
            Quotable::Plain(value) => (value_start, value.len()),
        };

        Ok(CookiePair {
            pair: from_utf8(source)?.to_string(),
            name_len: name.len(),
            value_location: value_location,
        })
    }

    /// Get the name of the cookie.
    pub fn name(&self) -> &str {
        &self.pair.as_str()[0..self.name_len]
    }

    /// Get the value of a cookie.
    pub fn value(&self) -> &str {
        let (start, length) = self.value_location;
        &self.pair.as_str()[start..length]
    }

    /// Get the (name, value) pair of a cookie.
    pub fn as_tuple(&self) -> (&str, &str) {
        (self.name(), self.value())
    }

    /// Get the formatted `name=value` pair string of a cookie.
    pub fn as_str(&self) -> &str {
        self.pair.as_str()
    }
}

impl FromStr for CookiePair {
    type Err = Error;

    fn from_str(source: &str) -> Result<CookiePair> {
        CookiePair::from_bytes(source.as_bytes())
    }
}

/// Iterator over the fragments of a single cookie.
pub struct ArgumentIter<'s> {
    remaining: &'s [u8],
}

impl<'s> ArgumentIter<'s> {
    /// Create a new iterator over a cookie.
    pub fn new(source: &'s [u8]) -> ArgumentIter<'s> {
        ArgumentIter { remaining: source }
    }

    /// Take the next argument from the list.
    fn next_argument(&mut self) -> Result<Option<Argument<'s>>> {
        // No more arguments
        if self.remaining.len() == 0 {
            return Ok(None);
        }

        // Remove the leading delimieter
        ensure!(
            self.remaining.len() >= 2 && &self.remaining[..2] == b"; ",
            ErrorKind::MissingDelimiter
        );
        self.remaining = &self.remaining[2..];

        // Get the next argument
        let next = next_fragment(self.remaining)?;
        self.remaining = &self.remaining[next.len()..];
        Ok(Some(Argument::decode(next)?))
    }
}

impl<'s> Iterator for ArgumentIter<'s> {
    type Item = Result<Argument<'s>>;

    fn next(&mut self) -> Option<Result<Argument<'s>>> {
        match self.next_argument() {
            Ok(value) => value.map(Ok),
            Err(err) => Some(Err(err)),
        }
    }
}

/// Possible cookie fragments.
#[derive(Debug, PartialEq, Eq)]
pub enum Argument<'s> {
    Expires(Tm),
    MaxAge(Duration),
    Domain(&'s str),
    Path(&'s str),
    Secure,
    HttpOnly,
    Extension(&'s [u8]),
}

impl<'s> Argument<'s> {
    fn decode(fragment: &'s [u8]) -> Result<Argument<'s>> {
        if fragment.starts_with(b"Expires=") {
            let time = date::parse(&fragment[8..])?;
            Ok(Argument::Expires(time))
        } else if fragment.starts_with(b"Max-Age=") {
            let seconds = from_utf8(&fragment[8..])?.parse()?;
            let duration = Duration::seconds(seconds);
            Ok(Argument::MaxAge(duration))
        } else if fragment.starts_with(b"Domain=") {
            Ok(Argument::Domain(from_utf8(&fragment[7..])?))
        } else if fragment.starts_with(b"Path=") {
            Ok(Argument::Path(from_utf8(&fragment[5..])?))
        } else if fragment == b"Secure" {
            Ok(Argument::Secure)
        } else if fragment == b"HttpOnly" {
            Ok(Argument::HttpOnly)
        } else {
            Ok(Argument::Extension(fragment))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use time::strptime;

    #[test]
    fn maybe_quoted() {
        let checks = &[
            (b"ABBA" as &[u8], Quotable::Plain(b"ABBA" as &[u8])),
            (b"\"ABBA\"" as &[u8], Quotable::Quoted(b"\"ABBA\"" as &[u8])),
        ];

        for &(ref text, ref expected) in checks {
            let quote = super::maybe_quoted(text).unwrap();
            assert_eq!(&quote, expected);
        }
    }

    #[test]
    fn extract_tokens() {
        let token = next_token(b"key=value").unwrap();
        assert_eq!(token, b"key");
    }

    #[test]
    fn fragment_iterator() {
        let (cookie, args) = process_cookie(
            "\
             some=thing; \
             fragment; \
             Domain=google.com; \
             Expires=Sun, 25 Feb 2018 01:36:48 GMT; \
             Max-Age=3200; \
             other=fragment",
        ).unwrap();
        let args: Vec<Argument<'static>> = args.map(Result::unwrap).collect();
        let expected_cookie = CookiePair {
            pair: "some=thing".to_string(),
            name_len: 4,
            value_location: (5, 5),
        };
        let expected_args = vec![
            Argument::Extension(b"fragment"),
            Argument::Domain("google.com"),
            Argument::Expires(
                strptime("Sun Feb 25 01:36:48 UTC 2018", "%a %b %d %H:%M:%S UTC %Y").unwrap(),
            ),
            Argument::MaxAge(Duration::seconds(3200)),
            Argument::Extension(b"other=fragment"),
        ];
        assert_eq!(cookie, expected_cookie);
        assert_eq!(args, expected_args);
    }
}
