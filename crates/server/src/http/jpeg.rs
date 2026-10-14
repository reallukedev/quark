//! Strips metadata from JPEG uploads as they stream in: EXIF (camera, time, GPS position), XMP,
//! IPTC, comments, vendor segments and anything appended after the image (multi-picture
//! extras, which carry their own EXIF). The EXIF orientation is kept, rewritten into a tiny EXIF
//! segment of its own, so phone photos still show the right way up. Image data, color profiles
//! (ICC) and the JFIF/Adobe segments decoders need pass through untouched.
//!
//! Anything that doesn't look like the JPEG structure we expect is passed through unchanged
//! from that point on: the scrubber never breaks a file it doesn't understand.

/// What happens to a marker segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Keep,
    Drop,
    /// Buffer it (at most 64 KiB, a segment's limit) and decide on its contents.
    Inspect,
}

fn action(marker: u8) -> Action {
    match marker {
        // APP1: EXIF or XMP. APP2: ICC profile (kept) or multi-picture index (dropped).
        0xE1 | 0xE2 => Action::Inspect,
        // APP3..APP13 and APP15: vendor data and IPTC. COM: comments.
        0xE3..=0xED | 0xEF | 0xFE => Action::Drop,
        // APP0 (JFIF), APP14 (Adobe color transform), tables, frames, scans.
        _ => Action::Keep,
    }
}

#[derive(Debug)]
enum St {
    /// Matching the start-of-image marker; how many of its two bytes we've seen.
    Start(u8),
    /// Between segments, expecting 0xFF.
    Marker,
    /// After 0xFF, expecting the marker code (more 0xFF are fill bytes).
    MarkerCode,
    /// Reading the two length bytes of segment `marker`.
    Length {
        marker: u8,
        hi: Option<u8>,
    },
    Copy {
        left: usize,
        then_scan: bool,
    },
    Skip {
        left: usize,
    },
    Collect {
        marker: u8,
        left: usize,
        buf: Vec<u8>,
    },
    /// Entropy-coded scan data, until the next real marker.
    Scan,
    /// After 0xFF inside scan data.
    ScanFf,
    /// After the end-of-image marker: dropped.
    Trailer,
    /// Not (or no longer) understood: everything passes.
    Pass,
}

/// A streaming JPEG metadata scrubber. Feed it chunks; it appends what to keep to `out`.
pub struct Scrubber {
    st: St,
}

impl Default for Scrubber {
    fn default() -> Self {
        Scrubber { st: St::Start(0) }
    }
}

impl Scrubber {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) {
        let mut i = 0;
        while i < input.len() {
            match &mut self.st {
                St::Pass => {
                    out.extend_from_slice(&input[i..]);
                    return;
                }
                St::Trailer => return,
                St::Start(n) => {
                    let want = if *n == 0 { 0xFF } else { 0xD8 };
                    if input[i] != want {
                        // Not a JPEG after all: hand back what we held and pass the rest.
                        out.extend_from_slice(&[0xFF, 0xD8][..usize::from(*n)]);
                        self.st = St::Pass;
                        continue;
                    }
                    i += 1;
                    if *n == 1 {
                        out.extend_from_slice(&[0xFF, 0xD8]);
                        self.st = St::Marker;
                    } else {
                        *n = 1;
                    }
                }
                St::Marker => {
                    if input[i] == 0xFF {
                        i += 1;
                        self.st = St::MarkerCode;
                    } else {
                        self.st = St::Pass;
                    }
                }
                St::MarkerCode => {
                    let m = input[i];
                    i += 1;
                    match m {
                        0xFF => {}
                        // Standalone markers have no length.
                        0x01 | 0xD0..=0xD7 => {
                            out.extend_from_slice(&[0xFF, m]);
                            self.st = St::Marker;
                        }
                        0xD9 => {
                            out.extend_from_slice(&[0xFF, 0xD9]);
                            self.st = St::Trailer;
                        }
                        0x00 | 0xD8 => {
                            out.extend_from_slice(&[0xFF, m]);
                            self.st = St::Pass;
                        }
                        _ => self.st = St::Length { marker: m, hi: None },
                    }
                }
                St::Length { marker, hi } => {
                    let b = input[i];
                    i += 1;
                    let Some(h) = *hi else {
                        *hi = Some(b);
                        continue;
                    };
                    let marker = *marker;
                    let len = usize::from(h) << 8 | usize::from(b);
                    if len < 2 {
                        out.extend_from_slice(&[0xFF, marker, h, b]);
                        self.st = St::Pass;
                        continue;
                    }
                    let left = len - 2;
                    self.st = match action(marker) {
                        Action::Keep => {
                            out.extend_from_slice(&[0xFF, marker, h, b]);
                            St::Copy { left, then_scan: marker == 0xDA }
                        }
                        Action::Drop => St::Skip { left },
                        Action::Inspect => St::Collect { marker, left, buf: Vec::with_capacity(left) },
                    };
                    self.after_segment_if_empty(out);
                }
                St::Copy { left, then_scan } => {
                    let n = (*left).min(input.len() - i);
                    out.extend_from_slice(&input[i..i + n]);
                    i += n;
                    *left -= n;
                    if *left == 0 {
                        self.st = if *then_scan { St::Scan } else { St::Marker };
                    }
                }
                St::Skip { left } => {
                    let n = (*left).min(input.len() - i);
                    i += n;
                    *left -= n;
                    if *left == 0 {
                        self.st = St::Marker;
                    }
                }
                St::Collect { left, buf, .. } => {
                    let n = (*left).min(input.len() - i);
                    buf.extend_from_slice(&input[i..i + n]);
                    i += n;
                    *left -= n;
                    if *left == 0 {
                        self.finish_collect(out);
                    }
                }
                St::Scan => match input[i..].iter().position(|&b| b == 0xFF) {
                    None => {
                        out.extend_from_slice(&input[i..]);
                        return;
                    }
                    Some(p) => {
                        out.extend_from_slice(&input[i..i + p]);
                        i += p + 1;
                        self.st = St::ScanFf;
                    }
                },
                St::ScanFf => {
                    let b = input[i];
                    match b {
                        // A stuffed 0xFF or a restart marker: still scan data.
                        0x00 | 0xD0..=0xD7 => {
                            out.extend_from_slice(&[0xFF, b]);
                            i += 1;
                            self.st = St::Scan;
                        }
                        0xFF => i += 1,
                        // A real marker ends the scan (next scan's tables, or the end).
                        _ => self.st = St::MarkerCode,
                    }
                }
            }
        }
    }

    /// A segment with no payload is finished as soon as its length is read.
    fn after_segment_if_empty(&mut self, out: &mut Vec<u8>) {
        let empty = matches!(self.st, St::Copy { left: 0, .. } | St::Skip { left: 0 } | St::Collect { left: 0, .. });
        if !empty {
            return;
        }
        match &self.st {
            St::Copy { then_scan: true, .. } => self.st = St::Scan,
            St::Collect { .. } => self.finish_collect(out),
            _ => self.st = St::Marker,
        }
    }

    fn finish_collect(&mut self, out: &mut Vec<u8>) {
        let St::Collect { marker, buf, .. } = std::mem::replace(&mut self.st, St::Marker) else { return };
        match marker {
            0xE1 => {
                if let Some(o) = exif_orientation(&buf).filter(|o| *o != 1) {
                    out.extend_from_slice(&orientation_segment(o));
                }
            }
            0xE2 if buf.starts_with(b"ICC_PROFILE\0") => {
                let len = buf.len() + 2;
                out.extend_from_slice(&[0xFF, 0xE2, (len >> 8) as u8, len as u8]);
                out.extend_from_slice(&buf);
            }
            _ => {}
        }
    }
}

/// The orientation tag (0x0112) from an APP1 EXIF payload's first IFD.
fn exif_orientation(p: &[u8]) -> Option<u16> {
    let tiff = p.strip_prefix(b"Exif\0\0")?;
    let be = match tiff.get(..2)? {
        b"MM" => true,
        b"II" => false,
        _ => return None,
    };
    let u16_at = |o: usize| -> Option<u16> {
        let b: [u8; 2] = tiff.get(o..o.checked_add(2)?)?.try_into().ok()?;
        Some(if be { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
    };
    let u32_at = |o: usize| -> Option<u32> {
        let b: [u8; 4] = tiff.get(o..o.checked_add(4)?)?.try_into().ok()?;
        Some(if be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    };
    if u16_at(2)? != 42 {
        return None;
    }
    let ifd = usize::try_from(u32_at(4)?).ok()?;
    let count = usize::from(u16_at(ifd)?);
    for k in 0..count.min(512) {
        let e = ifd.checked_add(2 + k * 12)?;
        if u16_at(e)? == 0x0112 && u16_at(e + 2)? == 3 && u32_at(e + 4)? == 1 {
            return Some(u16_at(e + 8)?).filter(|o| (1..=8).contains(o));
        }
    }
    None
}

/// A complete APP1 segment holding only an EXIF orientation.
fn orientation_segment(o: u16) -> [u8; 36] {
    let [oh, ol] = o.to_be_bytes();
    #[rustfmt::skip]
    let seg = [
        0xFF, 0xE1, 0x00, 0x22,
        b'E', b'x', b'i', b'f', 0, 0,
        b'M', b'M', 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x01,
        0x01, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, oh, ol, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    seg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() + 2;
        let mut v = vec![0xFF, marker, (len >> 8) as u8, len as u8];
        v.extend_from_slice(payload);
        v
    }

    /// EXIF in little-endian order with a make, an orientation and a GPS pointer.
    fn exif(orientation: u16) -> Vec<u8> {
        let mut t = b"Exif\0\0II\x2a\x00\x08\x00\x00\x00".to_vec();
        t.extend_from_slice(&3u16.to_le_bytes());
        // Make: ASCII, 4 bytes inline.
        t.extend_from_slice(&[0x0F, 0x01, 2, 0, 4, 0, 0, 0, b'A', b'c', b'm', 0]);
        t.extend_from_slice(&[0x12, 0x01, 3, 0, 1, 0, 0, 0]);
        t.extend_from_slice(&orientation.to_le_bytes());
        t.extend_from_slice(&[0, 0]);
        // GPS IFD pointer, and the GPS data itself as bytes we can search for.
        t.extend_from_slice(&[0x25, 0x88, 4, 0, 1, 0, 0, 0, 50, 0, 0, 0]);
        t.extend_from_slice(&[0, 0, 0, 0]);
        t.extend_from_slice(b"GPS-SECRET-52.5200N");
        t
    }

    fn sample(orientation: u16) -> (Vec<u8>, Vec<u8>) {
        let jfif = seg(0xE0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0");
        let icc = seg(0xE2, b"ICC_PROFILE\0\x01\x01profile");
        let mpf = seg(0xE2, b"MPF\0index");
        let xmp = seg(0xE1, b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>GPS-SECRET</x:xmpmeta>");
        let iptc = seg(0xED, b"Photoshop 3.0\0GPS-SECRET");
        let com = seg(0xFE, b"GPS-SECRET comment");
        let dqt = seg(0xDB, &[0u8; 65]);
        let sof = seg(0xC0, &[8, 0, 16, 0, 16, 1, 1, 0x11, 0]);
        let sos = seg(0xDA, &[1, 1, 0, 0, 63, 0]);
        let scan = [0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56, 0xFF, 0xFF, 0x00, 0x78];
        let mut input = vec![0xFF, 0xD8];
        for s in [&jfif, &seg(0xE1, &exif(orientation)), &xmp, &icc, &mpf, &iptc, &com, &dqt, &sof, &sos] {
            input.extend_from_slice(s);
        }
        input.extend_from_slice(&scan);
        // A progressive second scan with its own table before it.
        input.extend_from_slice(&seg(0xC4, &[0, 1, 2, 3]));
        input.extend_from_slice(&sos);
        input.extend_from_slice(&[0x9A, 0xBC]);
        input.extend_from_slice(&[0xFF, 0xD9]);
        input.extend_from_slice(b"\xFF\xD8appended image with GPS-SECRET");

        let mut want = vec![0xFF, 0xD8];
        want.extend_from_slice(&jfif);
        if orientation != 1 {
            want.extend_from_slice(&orientation_segment(orientation));
        }
        for s in [&icc, &dqt, &sof, &sos] {
            want.extend_from_slice(s);
        }
        // The extra fill 0xFF before the stuffed byte is dropped; decoders skip it anyway.
        want.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56, 0xFF, 0x00, 0x78]);
        want.extend_from_slice(&seg(0xC4, &[0, 1, 2, 3]));
        want.extend_from_slice(&sos);
        want.extend_from_slice(&[0x9A, 0xBC, 0xFF, 0xD9]);
        (input, want)
    }

    fn run(input: &[u8], chunk: usize) -> Vec<u8> {
        let mut s = Scrubber::new();
        let mut out = Vec::new();
        for c in input.chunks(chunk) {
            s.push(c, &mut out);
        }
        out
    }

    #[test]
    fn strips_metadata_in_any_chunking() {
        let (input, want) = sample(6);
        for chunk in [1, 2, 3, 7, 64, input.len()] {
            let out = run(&input, chunk);
            assert_eq!(out, want, "chunk size {chunk}");
            assert!(!out.windows(10).any(|w| w == b"GPS-SECRET"));
        }
    }

    #[test]
    fn keeps_only_the_orientation() {
        let (input, _) = sample(6);
        let out = run(&input, 5);
        let at = out.windows(4).position(|w| w == b"Exif").unwrap();
        assert_eq!(exif_orientation(&out[at..at + 32]), Some(6));
        let (input, want) = sample(1);
        assert_eq!(run(&input, 9), want);
        assert!(!run(&input, 9).windows(4).any(|w| w == b"Exif"));
    }

    #[test]
    fn big_endian_exif_orientation() {
        assert_eq!(exif_orientation(&orientation_segment(8)[4..]), Some(8));
        assert_eq!(exif_orientation(b"Exif\0\0MM\x00\x2a\x00\x00\xff\xff"), None);
        assert_eq!(exif_orientation(b"Exif\0\0XX"), None);
    }

    #[test]
    fn non_jpeg_passes_untouched() {
        for data in [b"\x89PNG\r\n\x1a\nrest".to_vec(), b"\xFFnope".to_vec(), vec![0xFF, 0xD8, 0x00, 0x01, 0x02]] {
            assert_eq!(run(&data, 1), data);
            assert_eq!(run(&data, 100), data);
        }
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let (input, _) = sample(3);
        for cut in 0..input.len() {
            let _ = run(&input[..cut], 4);
        }
    }
}
