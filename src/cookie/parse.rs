//! Parsing for a cookie string.

use ::error::parser::*;
use std::str::{FromStr, from_utf8};
use time::{Duration, Tm, strptime};

/// Byte is a [RFC5234](https://tools.ietf.org/html/rfc5234) CTL character.
///
/// ```text
/// CTL =  %x00-1F / %x7F ; controls
/// ```
fn is_ctl(byte: u8) -> bool {
    (byte >= 0x00 && byte <= 0x1F) || byte == 0x7F
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
        b'(' | b')' | b'<' | b'>' | b'@' |
        b',' | b';' | b':' | b'\\' | b'"' |
        b'/' | b'[' | b']' | b'?' | b'=' |
        b'{' | b'}' | b' ' | b'\t' => true,
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
    byte == 0x21
        || (byte >= 0x23 && byte <= 0x2B)
        || (byte >= 0x2D && byte <= 0x3A)
        || (byte >= 0x3C && byte <= 0x5B)
        || (byte >= 0x5D && byte <= 0x7E)
}

/// Collect a substring from a slice matching a character set.
fn collect_matching<T>(source: &[u8], test: T) -> &[u8]
where
    T: Fn(u8) -> bool
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
fn split_cookie<'s>(source: &'s [u8]) -> Result<(&'s [u8], &'s [u8])>
{
    let cookie = next_fragment(source.as_ref())?;
    let arguments = &source[cookie.len()..];
    Ok((cookie, arguments))
}

/// Process a cookie string into a pair and a set of arguments.
pub fn process_cookie<'s>(source: &'s str) -> Result<(CookiePair, ArgumentIter<'s>)>{
    let (cookie, arguments) = split_cookie(source.as_bytes())?;
    Ok((CookiePair::from_bytes(cookie)?, ArgumentIter::new(arguments)))
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
    pub fn new(source: &'s [u8]) -> ArgumentIter<'s>{
        ArgumentIter {
            remaining: source,
        }
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

/// Dates in Cookies have their own parsing rules.
///
/// ```text
/// cookie-date     = *delimiter date-token-list *delimiter
/// date-token-list = date-token *( 1*delimiter date-token )
/// date-token      = 1*non-delimiter
///
/// delimiter       = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E
/// non-delimiter   = %x00-08 / %x0A-1F / DIGIT / ":" / ALPHA / %x7F-FF
/// non-digit       = %x00-2F / %x3A-FF
///
/// day-of-month    = 1*2DIGIT ( non-digit *OCTET )
/// month           = ( "jan" / "feb" / "mar" / "apr" /
///                     "may" / "jun" / "jul" / "aug" /
///                     "sep" / "oct" / "nov" / "dec" ) *OCTET
/// year            = 2*4DIGIT ( non-digit *OCTET )
/// time            = hms-time ( non-digit *OCTET )
/// hms-time        = time-field ":" time-field ":" time-field
/// time-field      = 1*2DIGIT
/// ```
mod date {
    use super::*;

    /// Is a date delimiter.
    ///
    /// ```text
    /// delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E
    /// ```
    fn is_delimiter(byte: u8) -> bool {
        byte == 0x09
            || byte >= 0x20 && byte <= 0x2F
            || byte >= 0x3B && byte <= 0x40
            || byte >= 0x5B && byte <= 0x60
            || byte >= 0x7B && byte <= 0x7E
    }

    /// Is not a date delimiter
    ///
    /// ```text
    /// non-delimiter = %x00-08 / %x0A-1F / DIGIT / ":" / ALPHA / %x7F-FF
    /// ```
    fn is_non_delimiter(byte: u8) -> bool {
        byte >= 0x00 && byte <= 0x08
            || byte >= 0x0A && byte <= 0x1F
            || byte.is_ascii_alphanumeric()
            || byte == b':'
            || byte >= 0x7F && byte <= 0xFF
    }

    /// Get the next date token.
    fn next_date_token(source: &[u8]) -> Result<&[u8]> {
        non_zero_length(collect_matching(source, is_non_delimiter))
    }

    /// Get the next date delimiter.
    fn next_date_delimiter(source: &[u8]) -> Result<&[u8]> {
        non_zero_length(collect_matching(source, is_delimiter))
    }

    /// Attempt to decode a time token.
    fn decode_time(token: &[u8]) -> Option<(i32, i32, i32)> {
        decode_time_field(token)
            .and_then(cookie_time_continues)
            .and_then(decode_next_time_field)
            .map(|(hour, (minute, remaining))| ((hour, minute), remaining))
            .and_then(cookie_time_continues)
            .and_then(decode_next_time_field)
            .map(|((hour, minute), (second, remaining))| ((hour, minute, second), remaining))
            .and_then(invalid_if_trailing_digit)
    }

    /// Check that there are further valid characters in the cookie-time.
    fn cookie_time_continues<T>(decoded: (T, &[u8])) -> Option<(T, &[u8])> {
        if decoded.1.len() >= 2 && decoded.1[0] == b':' {
            Some(decoded)
        } else {
            None
        }
    }

    /// Get the next time field in a cookie-time.
    fn decode_next_time_field<T>(decoded: (T, &[u8])) -> Option<(T, (i32, &[u8]))> {
        let (date, remaining) = decoded;
        decode_time_field(&remaining[1..]).map(|value| (date, value))
    }

    /// Trailing digits invalidate fields.
    fn invalid_if_trailing_digit<T>(decoded: (T, &[u8])) -> Option<T> {
        let (value, remaining) = decoded;
        if remaining.len() > 0 && remaining[1].is_ascii_digit() {
            None
        } else {
            Some(value)
        }
    }

    /// Attempt to decode a time field.
    fn decode_time_field(source: &[u8]) -> Option<(i32, &[u8])> {
        decode_digits(source, 1, 2)
    }

    /// Attempt to decode a day of month field.
    fn decode_day(token: &[u8]) -> Option<i32> {
        decode_time_field(token)
            .and_then(invalid_if_trailing_digit)
    }

    /// Attempt to decode a month by abbreviated name case insensitively.
    fn decode_month(token: &[u8]) -> Option<i32> {
        let months = &[
            b"jan", b"feb", b"mar", b"apr", b"may", b"jun",
            b"jul", b"aug", b"sep", b"oct", b"nov", b"dec",
        ];

        if token.len() < 3 {
            return None;
        }

        for (numeric, month) in months.iter().enumerate() {
            //Check the characters match
            if token[0].to_ascii_lowercase() == month[0]
                && token[1].to_ascii_lowercase() == month[1]
                && token[2].to_ascii_lowercase() == month[2]
            {
                return Some(numeric as i32);
            }
        }

        None
    }

    /// Attempt to decode a number of digits.
    fn decode_digits(token: &[u8], min: usize, max: usize) -> Option<(i32, &[u8])> {
        if token.len() < min || !token[0].is_ascii_digit() {
            // Token not long enough or doesn't start with digit
            return None;
        }

        // Upper bound of length to try
        let max_len = max.min(token.len());

        // Add the leading digits in the token.
        let (value, used, _) = token[..max_len]
            .iter()
            .fold((0, 0, true), |(value, count, leading), next| {
                if leading && next.is_ascii_digit() {
                    (
                        (value * 10) + (next - b'0') as i32,
                        count + 1,
                        true,
                    )
                } else {
                    (value, count, false)
                }
            });

        Some((value, &token[used..]))
    }

    /// Attempt to decode a year as a 2-4 digit value.
    fn decode_year(token: &[u8]) -> Option<i32> {
        let mut decoded = decode_digits(token, 2, 4)
            .and_then(invalid_if_trailing_digit);

        // Uplift 2-digit years.
        if let Some(year) = decoded {
            let year = if year >= 0 && year <= 69 {
                year + 2000
            } else if year >= 70 && year <= 99 {
                year + 1900
            } else {
                year
            };

            // Tm stores year since 1900 rather than absolute year.
            decoded = Some(year - 1900);
        }

        decoded
    }

    /// Determine if a function is a leap year.
    fn is_leap_year(year: i32) -> bool {
        year % 400 == 0
            || year % 100 != 0 && year % 4 == 0
    }

    /// Gets the weekday and day of year for a given date.
    ///
    /// Ensure that a given day is within the number of days for a given month.
    fn verify_date(day: i32, month: i32, year: i32) -> Result<()> {

        let month_days = &[
            31, // January
            28, // February
            31, // March
            30, // April
            31, // May
            30, // June
            31, // July
            31, // August
            30, // Spetember
            31, // October
            30, // November
            31, // December
        ];

        // Validate the date.
        ensure!(
            day >= 0 && month >= 0 && month < 12,
            ErrorKind::InvalidDate
        );
        ensure!(
            is_leap_year(year) && month == 1 && day <= 29
                || day <= month_days[month as usize],
            ErrorKind::InvalidDate
        );

        Ok(())
    }


    /// Parse a cookie-date string into an actual datetime.
    pub fn parse(source: &[u8]) -> Result<Tm> {
        let mut date = Date::unset();
        date.gather(source)?;
        date.into_time()
    }

    /// Partial representation of a date.
    struct Date {
        time: Option<(i32, i32, i32)>,
        day: Option<i32>,
        month: Option<i32>,
        year: Option<i32>,
    }

    impl Date {

        /// The unset date.
        fn unset() -> Date {
            Date {
                time: None,
                day: None,
                month: None,
                year: None,
            }
        }

        /// Gather the raw values from the tokens.
        fn gather(&mut self, source: &[u8]) -> Result<()> {
            for token in DateIter::new(source) {
                let token = token?;

                // Try and decode the time from the token.
                Date::try_replace(token, &mut self.time, decode_time)
                    || Date::try_replace(token, &mut self.day, decode_day)
                    || Date::try_replace(token, &mut self.month, decode_month)
                    || Date::try_replace(token, &mut self.year, decode_year);
            }

            Ok(())
        }

        /// Convert to a time.
        fn into_time(self) -> Result<Tm> {
            match (self.time, self.day, self.month, self.year) {
                (Some((hour, minute, second)), Some(day), Some(month), Some(year)) => {
                    // Validate the time
                    ensure!(
                        second >= 0 && second < 60
                            && minute >= 0 && second < 60
                            && hour >= 0 && hour < 24,
                        ErrorKind::InvalidDate
                    );

                    // Also validate the date
                    verify_date(day, month, year)?;

                    Ok(Tm {
                        tm_sec: second,
                        tm_min: minute,
                        tm_hour: hour,
                        tm_mday: day,
                        tm_mon: month,
                        tm_year: year,
                        tm_wday: 0,
                        tm_yday: 0,
                        tm_isdst: 0,
                        tm_utcoff: 0,
                        tm_nsec: 0,
                    })
                }
                _ => bail!(ErrorKind::IncompleteDate),
            }
        }

        /// Try and replace a given field of the date.
        fn try_replace<T, F>(token: &[u8], field: &mut Option<T>, decode: F) -> bool
        where
            F: Fn(&[u8]) -> Option<T>,
        {
            if field.is_none() {
                match decode(token) {
                    None => false,
                    value => {
                        *field = value;
                        true
                    }
                }
            } else {
                false
            }
        }
    }

    /// Iterator over a list of date tokens.
    pub struct DateIter<'s> {
        remaining: &'s [u8],
        first: bool,
    }

    impl<'s> DateIter<'s> {
        fn new(source: &'s [u8]) -> DateIter<'s> {
            DateIter {
                remaining: source,
                first: true,
            }
        }

        /// Get the next valid date token
        fn next_token(&mut self) -> Result<Option<&'s [u8]>> {
            if self.remaining.len() == 0 {
                return Ok(None);
            }

            // Remove leading delimeter
            if self.first {
                self.first = false;
            } else {
                let delimieter = next_date_delimiter(self.remaining)?;
                self.remaining = &self.remaining[delimieter.len()..];
            }

            /// Collect the next token.
            let token = next_date_token(self.remaining)?;
            self.remaining = &self.remaining[token.len()..];

            Ok(Some(token))
        }
    }

    impl<'s> Iterator for DateIter<'s> {
        type Item = Result<&'s [u8]>;

        fn next(&mut self) -> Option<Result<&'s [u8]>> {
            match self.next_token() {
                Ok(value) => value.map(Ok),
                Err(err) => Some(Err(err)),
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use time::strptime;

        #[test]
        fn date_parse () {
            let tests = &[
                (
                    parse(b"\
                        I do delcare that this cookie doth expire on the 14th day of January. \
                        On that day it shall entirely expire when the clock reads 12:52:13. \
                        It shall not exist beyong the 32nd year of the 21st century\
                    ").unwrap(),
                    strptime("2032-01-14 12:52:13", "%Y-%m-%d %H:%M:%S").unwrap(),
                ),
            ];

            for &(parsed, expected) in tests {
                assert_eq!(parsed, expected);
            }

        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        let (cookie, args) = process_cookie("\
            some=thing; \
            fragment; \
            Domain=google.com; \
            Expires=Sun, 25 Feb 2018 01:36:48 GMT; \
            Max-Age=3200; \
            other=fragment"
        ).unwrap();
        let args: Vec<Argument<'static>> = args
            .map(Result::unwrap)
            .collect();
        let expected_cookie = CookiePair {
            pair: "some=thing".to_string(),
            name_len: 4,
            value_location: (5, 5),
        };
        let expected_args = vec![
            Argument::Extension(b"fragment"),
            Argument::Domain("google.com"),
            Argument::Expires(strptime(
                "Sun Feb 25 01:36:48 UTC 2018",
                "%a %b %d %H:%M:%S UTC %Y",
            ).unwrap()),
            Argument::MaxAge(Duration::seconds(3200)),
            Argument::Extension(b"other=fragment"),
        ];
        assert_eq!(cookie, expected_cookie);
        assert_eq!(args, expected_args);
    }
}
