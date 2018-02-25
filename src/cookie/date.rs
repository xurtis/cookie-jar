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
//! delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E
//! ```
fn is_delimiter(byte: u8) -> bool {
    byte == 0x09
        || byte >= 0x20 && byte <= 0x2F
        || byte >= 0x3B && byte <= 0x40
        || byte >= 0x5B && byte <= 0x60
        || byte >= 0x7B && byte <= 0x7E
}
