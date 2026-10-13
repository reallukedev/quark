//! Times as milliseconds since the Unix epoch, and XEP-0082 formatting.

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `2026-10-13T18:07:00.123Z` (XEP-0082 DateTime, UTC).
pub fn xep82(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", sod / 3600, (sod / 60) % 60, sod % 60)
}

/// Parses XEP-0082 DateTime (`Z` or `±hh:mm` offsets, optional fractions) into milliseconds.
pub fn parse_xep82(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let num = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if &s[4..5] != "-" || &s[7..8] != "-" || !matches!(&s[10..11], "T" | "t") || &s[13..14] != ":" || &s[16..17] != ":" {
        return None;
    }
    let mut rest = &s[19..];
    let mut millis = 0i64;
    if let Some(r) = rest.strip_prefix('.') {
        let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        let frac = format!("{:0<3}", &digits[..digits.len().min(3)]);
        millis = frac.parse().ok()?;
        rest = &r[digits.len()..];
    }
    let offset = match rest {
        "Z" | "z" | "" => 0,
        o if o.len() == 6 => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (o[1..3].parse::<i64>().ok()? * 3600 + o[4..6].parse::<i64>().ok()? * 60)
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    Some(((days * 86_400 + h * 3600 + mi * 60 + se) - offset) * 1000 + millis)
}

// Howard Hinnant's civil calendar algorithms.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips() {
        let t = 1_791_900_420_123;
        assert_eq!(parse_xep82(&xep82(t)), Some(t));
        assert_eq!(parse_xep82("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_xep82("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(xep82(0), "1970-01-01T00:00:00.000Z");
    }
}
