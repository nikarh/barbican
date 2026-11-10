//! Timestamps in logs.

/// Days since 1970-01-01 of a date (Howard Hinnant's `days_from_civil`).
fn days(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = (month + 9) % 12;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn number(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Unix seconds of an RFC 3339 time, as Docker and VictoriaLogs write them: `2026-11-10T15:42:51.995856621Z` or
/// with an offset (`+02:00`). Fractions are dropped.
#[must_use]
pub fn rfc3339(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once(['T', 't', ' '])?;
    let mut parts = date.splitn(3, '-');
    let year = number(parts.next()?)?;
    let month = number(parts.next()?)?;
    let day = number(parts.next()?)?;
    let hms = rest.get(..8)?;
    let mut parts = hms.splitn(3, ':');
    let hour = number(parts.next()?)?;
    let minute = number(parts.next()?)?;
    let second = number(parts.next()?)?;
    let mut zone = rest.get(8..)?;
    if let Some(fraction) = zone.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        zone = fraction.get(digits..)?;
    }
    let offset = match zone {
        "Z" | "z" => 0,
        _ => {
            let sign = match zone.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (h, m) = zone.get(1..)?.split_once(':')?;
            sign * (number(h)? * 3_600 + number(m)? * 60)
        }
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some(days(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second - offset)
}

/// Splits a line written with a leading RFC 3339 time (`docker logs --timestamps`) into the time and the rest.
#[must_use]
pub fn split_timestamped(line: &str) -> Option<(i64, &str)> {
    let (time, rest) = line.split_once(' ')?;
    Some((rfc3339(time)?, rest))
}

/// The nanoseconds of an RFC 3339 time's fraction (`.5` is 500 000 000).
#[must_use]
pub fn fraction(time: &str) -> i128 {
    let Some((_, rest)) = time.split_once('.') else {
        return 0;
    };
    let digits: String = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .take(9)
        .collect();
    format!("{digits:0<9}").parse().unwrap_or(0)
}

/// Unix nanoseconds of an RFC 3339 time.
#[must_use]
pub fn rfc3339_nanos(s: &str) -> Option<i128> {
    Some(i128::from(rfc3339(s)?) * 1_000_000_000 + fraction(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractions() {
        assert_eq!(fraction("2026-11-10T15:42:51.995856621Z"), 995_856_621);
        assert_eq!(fraction("2026-11-10T15:42:51.5Z"), 500_000_000);
        assert_eq!(fraction("2026-11-10T15:42:51Z"), 0);
        assert_eq!(rfc3339_nanos("1970-01-01T00:00:01.5Z"), Some(1_500_000_000));
    }

    #[test]
    fn parses() {
        assert_eq!(rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339("2026-11-10T15:42:51.995856621Z"),
            Some(1_794_325_371)
        );
        assert_eq!(rfc3339("2026-11-10T17:42:51+02:00"), Some(1_794_325_371));
        assert_eq!(rfc3339("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        assert_eq!(rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(rfc3339("2026-11-10"), None);
        assert_eq!(rfc3339("garbage"), None);
        assert_eq!(
            split_timestamped("2026-11-10T15:42:51.1Z Invalid user a from 192.0.2.1"),
            Some((1_794_325_371, "Invalid user a from 192.0.2.1"))
        );
    }
}
