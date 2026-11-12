//! A whole-second UTC timestamp with an RFC 3339 encoding.
//!
//! The export formats store dates as `YYYY-MM-DDTHH:MM:SSZ` (C `strftime("%FT%TZ")`).
//! This is a small hand-rolled formatter/parser instead of a date crate: the
//! format is fixed, we only ever need UTC, and the civil-date conversion is
//! twenty lines (Howard Hinnant's `days_from_civil`).  Unlike the reference
//! `mpw_timegm`, parsing never consults the local time zone or DST rules.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, UTC.  Ordered chronologically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(i64);

/// Earliest and latest representable instants: years 0000 and 9999.
const MIN_SECS: i64 = -62_167_219_200; // 0000-01-01T00:00:00Z
const MAX_SECS: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z

impl Timestamp {
    /// The Unix epoch.
    pub const EPOCH: Self = Self(0);

    /// The current time, truncated to whole seconds.
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Self(i64::try_from(d.as_secs()).unwrap_or(MAX_SECS).min(MAX_SECS)),
            Err(e) => Self(-i64::try_from(e.duration().as_secs()).unwrap_or(0).max(MIN_SECS)),
        }
    }

    /// From seconds since the epoch; clamped to years 0000–9999.
    pub fn from_unix(secs: i64) -> Self {
        Self(secs.clamp(MIN_SECS, MAX_SECS))
    }

    pub fn as_unix(self) -> i64 {
        self.0
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn to_rfc3339(self) -> String {
        let days = self.0.div_euclid(86_400);
        let secs = self.0.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }

    /// Parse an RFC 3339 date-time: `YYYY-MM-DD(T|t| )HH:MM:SS[.frac](Z|z|±HH:MM)`.
    ///
    /// Fractional seconds are truncated, a leap second (`:60`) is read as `:59`.
    /// Returns `None` for anything else, including out-of-range fields.
    pub fn parse_rfc3339(s: &str) -> Option<Self> {
        let b = s.trim().as_bytes();
        let num = |r: std::ops::Range<usize>| -> Option<i64> {
            let digits = b.get(r)?;
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            digits
                .iter()
                .try_fold(0i64, |acc, d| Some(acc * 10 + i64::from(d - b'0')))
        };
        let at = |i: usize, set: &[u8]| b.get(i).is_some_and(|c| set.contains(c));
        if !(at(4, b"-") && at(7, b"-") && at(10, b"Tt ") && at(13, b":") && at(16, b":")) {
            return None;
        }
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 60
        {
            return None;
        }
        let mut i = 19;
        if at(i, b".") {
            i += 1;
            let start = i;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            if i == start {
                return None;
            }
        }
        let offset = if at(i, b"Zz") && i + 1 == b.len() {
            0
        } else if at(i, b"+-") && at(i + 3, b":") && i + 6 == b.len() {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let sign = if at(i, b"-") { -1 } else { 1 };
            sign * (oh * 3600 + om * 60)
        } else {
            return None;
        };
        let days = days_from_civil(year, month, day);
        let secs = days * 86_400 + hour * 3600 + minute * 60 + second.min(59) - offset;
        (MIN_SECS..=MAX_SECS).contains(&secs).then_some(Self(secs))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses() {
        let cases = [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_557_573_296, "2019-05-11T11:14:56Z"),
            (-1, "1969-12-31T23:59:59Z"),
            (MAX_SECS, "9999-12-31T23:59:59Z"),
            (MIN_SECS, "0000-01-01T00:00:00Z"),
        ];
        for (secs, text) in cases {
            assert_eq!(Timestamp::from_unix(secs).to_rfc3339(), text);
            assert_eq!(Timestamp::parse_rfc3339(text), Some(Timestamp(secs)), "{text}");
        }
    }

    #[test]
    fn parses_variants_and_rejects_garbage() {
        let t = |s| Timestamp::parse_rfc3339(s).map(Timestamp::as_unix);
        assert_eq!(t("2019-05-11T13:14:56+02:00"), Some(1_557_573_296));
        assert_eq!(t("2019-05-11t11:14:56.999z"), Some(1_557_573_296));
        assert_eq!(t("2019-05-11 11:14:56Z"), Some(1_557_573_296));
        assert_eq!(t(" 2019-05-11T11:14:56Z\r"), Some(1_557_573_296));
        for bad in [
            "",
            "2019-05-11",
            "2019-13-01T00:00:00Z",
            "2019-02-29T00:00:00Z",
            "2019-05-11T24:00:00Z",
            "2019-05-11T11:14:56",
            "2019-05-11T11:14:56Zjunk",
            "2019-05-11T11:14:56.Z",
            "+019-05-11T11:14:56Z",
            "2019-05-11T11:14:56+2:00",
            "２０１９-05-11T11:14:56Z",
        ] {
            assert_eq!(t(bad), None, "{bad:?}");
        }
    }
}
