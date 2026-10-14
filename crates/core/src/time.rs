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
///
/// Works on bytes and checks every position before reading it, so any input (non-ASCII,
/// truncated, out-of-range fields) gives `None` instead of a panic: these strings come from
/// clients and other servers (MAM `start`/`end`, MUC `<history since>`).
pub fn parse_xep82(s: &str) -> Option<i64> {
    let b = s.trim().as_bytes();
    // `n` ASCII digits at `a` (no signs or spaces, which `str::parse` would let through).
    let num = |a: usize, n: usize| -> Option<i64> {
        b.get(a..a.checked_add(n)?)?.iter().try_fold(0i64, |acc, &c| c.is_ascii_digit().then(|| acc * 10 + i64::from(c - b'0')))
    };
    let at = |i: usize, set: &[u8]| b.get(i).is_some_and(|c| set.contains(c));
    if !(at(4, b"-") && at(7, b"-") && at(10, b"Tt") && at(13, b":") && at(16, b":")) {
        return None;
    }
    let (y, mo, d, h, mi, se) = (num(0, 4)?, num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?);
    // 60 allows a leap second (it reads as the next second).
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = b.get(19..)?;
    let mut millis = 0i64;
    if let Some(r) = rest.strip_prefix(b".") {
        let n = r.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        // Milliseconds are all we keep; further digits are dropped.
        let used = n.min(3);
        millis = num(20, used)? * [100, 10, 1][used - 1];
        rest = r.get(n..)?;
    }
    let offset = match rest {
        b"Z" | b"z" | b"" => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let base = b.len() - 6;
            let (oh, om) = (num(base + 1, 2)?, num(base + 4, 2)?);
            if oh > 23 || om > 59 {
                return None;
            }
            (if *sign == b'-' { -1 } else { 1 }) * (oh * 3600 + om * 60)
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
        assert_eq!(parse_xep82("1970-01-01T00:00:00.5Z"), Some(500));
        assert_eq!(parse_xep82("1970-01-01T00:00:00.123456-00:30"), Some(1_800_123));
    }

    #[test]
    fn bad_input_is_refused() {
        for s in [
            "1970-01-01T00:00:00+0\u{e4}00",
            "1970-01-01T00:00:00+\u{e4}:00",
            "1970-01-01T00:00:00\u{e4}",
            "1970-01-01T00:00:00.\u{e4}",
            "\u{e4}970-01-01T00:00:00Z",
            "19\u{e4}-01-01T00:00:00Z",
            "1970-01-01T00:00:00.Z",
            "1970-01-01T00:00:00+01:0",
            "1970-01-01T00:00:00+1:00",
            "1970-13-01T00:00:00Z",
            "1970-01-01T24:00:00Z",
            "1970-01-01 00:00:00Z",
            "+970-01-01T00:00:00Z",
            "1970-01-01T00:00:00*01:00",
        ] {
            assert_eq!(parse_xep82(s), None, "{s}");
        }
    }

    /// Random near-timestamps with characters swapped for ASCII, multi-byte or control
    /// characters never panic.
    #[test]
    fn fuzz_never_panics() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let pool = ['0', '9', '-', ':', '+', 'T', 'Z', '.', ' ', '\u{e4}', '\u{20ac}', '\u{1f600}', '\0', '\u{7f}'];
        let base: Vec<char> = "2026-10-13T18:07:00.123+05:30".chars().collect();
        for _ in 0..50_000 {
            let mut v = base.clone();
            v.truncate((rnd() % 32) as usize);
            for _ in 0..rnd() % 4 {
                if v.is_empty() {
                    break;
                }
                let i = (rnd() % v.len() as u64) as usize;
                v[i] = pool[(rnd() % pool.len() as u64) as usize];
            }
            if rnd() % 4 == 0 {
                let i = (rnd() % (v.len() as u64 + 1)) as usize;
                v.insert(i, pool[(rnd() % pool.len() as u64) as usize]);
            }
            let s: String = v.into_iter().collect();
            let _ = parse_xep82(&s);
        }
    }
}
