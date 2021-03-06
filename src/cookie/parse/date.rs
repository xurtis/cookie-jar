//! Dates in Cookies have their own parsing rules.
//!
//! ```text
//! cookie-date     = *delimiter date-token-list *delimiter
//! date-token-list = date-token *( 1*delimiter date-token )
//! date-token      = 1*non-delimiter
//!
//! delimiter       = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E
//! non-delimiter   = %x00-08 / %x0A-1F / DIGIT / ":" / ALPHA / %x7F-FF
//! non-digit       = %x00-2F / %x3A-FF
//!
//! day-of-month    = 1*2DIGIT ( non-digit *OCTET )
//! month           = ( "jan" / "feb" / "mar" / "apr" /
//!                     "may" / "jun" / "jul" / "aug" /
//!                     "sep" / "oct" / "nov" / "dec" ) *OCTET
//! year            = 2*4DIGIT ( non-digit *OCTET )
//! time            = hms-time ( non-digit *OCTET )
//! hms-time        = time-field ":" time-field ":" time-field
//! time-field      = 1*2DIGIT
//! ```

use super::*;

/// Is a date delimiter.
///
/// ```text
/// delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E
/// ```
fn is_delimiter(byte: u8) -> bool {
    byte == 0x09 || byte >= 0x20 && byte <= 0x2F || byte >= 0x3B && byte <= 0x40
        || byte >= 0x5B && byte <= 0x60 || byte >= 0x7B && byte <= 0x7E
}

/// Is not a date delimiter
///
/// ```text
/// non-delimiter = %x00-08 / %x0A-1F / DIGIT / ":" / ALPHA / %x7F-FF
/// ```
fn is_non_delimiter(byte: u8) -> bool {
    byte <= 0x08
        || byte >= 0x0A && byte <= 0x1F
        || byte.is_ascii_alphanumeric()
        || byte == b':'
        || byte >= 0x7F
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
    decode_time_field(token).and_then(invalid_if_trailing_digit)
}

/// Attempt to decode a month by abbreviated name case insensitively.
fn decode_month(token: &[u8]) -> Option<i32> {
    let months = &[
        b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov",
        b"dec",
    ];

    if token.len() < 3 {
        return None;
    }

    for (numeric, month) in months.iter().enumerate() {
        //Check the characters match
        if token[0].to_ascii_lowercase() == month[0] && token[1].to_ascii_lowercase() == month[1]
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
    let (value, used, _) = token[..max_len].iter().fold(
        (0, 0, true),
        |(value, count, leading), next| {
            if leading && next.is_ascii_digit() {
                ((value * 10) + (next - b'0') as i32, count + 1, true)
            } else {
                (value, count, false)
            }
        },
    );

    Some((value, &token[used..]))
}

/// Attempt to decode a year as a 2-4 digit value.
fn decode_year(token: &[u8]) -> Option<i32> {
    let mut decoded = decode_digits(token, 2, 4).and_then(invalid_if_trailing_digit);

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
    year % 400 == 0 || year % 100 != 0 && year % 4 == 0
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
    ensure!(day >= 0 && month >= 0 && month < 12, ErrorKind::InvalidDate);
    ensure!(
        is_leap_year(year) && month == 1 && day <= 29 || day <= month_days[month as usize],
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
                .or_else(|| Date::try_replace(token, &mut self.day, decode_day))
                .or_else(|| Date::try_replace(token, &mut self.month, decode_month))
                .or_else(|| Date::try_replace(token, &mut self.year, decode_year));
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
    fn try_replace<T, F>(token: &[u8], field: &mut Option<T>, decode: F) -> Option<()>
    where
        F: Fn(&[u8]) -> Option<T>,
    {
        if field.is_none() {
            match decode(token) {
                None => None,
                value => {
                    *field = value;
                    Some(())
                }
            }
        } else {
            None
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

        // Collect the next token.
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
    fn date_parse() {
        let tests: &[(&str, &str)] = &[
            (
                "\
                 I do delcare that this cookie doth expire on the 14th day of January. \
                 On that day it shall entirely expire when the clock reads 12:52:13. \
                 It shall not exist beyond the 32nd year of the 21st century\
                 ",
                "2032-01-14 12:52:13",
            ),
            ("Sun, 06 Nov 1994 08:49:37 GMT", "1994-11-06 08:49:37"),
            ("Sunday, 06-Nov-94 08:49:37 GMT", "1994-11-06 08:49:37"),
            ("Sun Nov  6 08:49:37 1994", "1994-11-06 08:49:37"),
        ];

        for &(parsed, expected) in tests {
            assert_eq!(
                parse(parsed.as_bytes())
                    .expect(&format!("Couldn't parse cookie date '{}'", parsed)),
                strptime(expected, "%Y-%m-%d %H:%M:%S").expect("couldn't parse string date"),
            );
        }
    }
}
