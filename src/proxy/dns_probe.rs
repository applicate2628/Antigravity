//! Bounded framing of one anonymous HTTP/1 probe response.
use std::io::{self, Read};

// Bounds the entire wire response, including interim headers and chunk framing.
// The observed response is 1,152 bytes; 1 MiB leaves ample room for diagnostic
// JSON while bounding memory and reads from an untrusted peer.
const WIRE_LIMIT: usize = 1024 * 1024;

pub(super) struct ParsedResponse {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

struct Input<'a, R> {
    reader: &'a mut R,
    bytes: Vec<u8>,
    pos: usize,
}

impl<R: Read> Input<'_, R> {
    fn more(&mut self) -> Result<bool, String> {
        let mut buffer = [0u8; 8192];
        let remaining = WIRE_LIMIT - self.bytes.len();
        // At the limit, one byte distinguishes a valid close from overflow.
        let take = remaining.min(buffer.len()).max(1);
        loop {
            match self.reader.read(&mut buffer[..take]) {
                Ok(0) => return Ok(false),
                Ok(n) if n > remaining => return Err("response exceeds wire limit".into()),
                Ok(n) => {
                    self.bytes.extend_from_slice(&buffer[..n]);
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("response read failed: {:?}", e.kind())),
            }
        }
    }

    fn need(&mut self, count: usize) -> Result<(), String> {
        let end = self.pos.checked_add(count).ok_or("response length overflow")?;
        if end > WIRE_LIMIT { return Err("response exceeds wire limit".into()); }
        while self.bytes.len() < end {
            if !self.more()? { return Err("incomplete response body".into()); }
        }
        Ok(())
    }
}

// A header field occupies at least four wire bytes (a:\r\n), so this
// capacity is derived from bytes already received rather than a field limit.
fn header_capacity(bytes: &[u8]) -> usize { bytes.len() / 4 + 1 }

pub(super) fn read_response(reader: &mut impl Read) -> Result<ParsedResponse, String> {
    let mut input = Input { reader, bytes: Vec::new(), pos: 0 };
    let (status, length, chunked) = loop {
        let parsed = {
            let available = &input.bytes[input.pos..];
            let mut headers = vec![httparse::EMPTY_HEADER; header_capacity(available)];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(available) {
                Ok(httparse::Status::Partial) => None,
                Ok(httparse::Status::Complete(n)) => {
                    let code = response.code.ok_or("missing HTTP status")?;
                    if !(100..=599).contains(&code) { return Err("invalid HTTP status".into()); }
                    let mut length = None;
                    let mut transfer = false;
                    let mut content_encoding = false;
                    for header in response.headers.iter() {
                        if header.name.eq_ignore_ascii_case("content-length") {
                            let value = std::str::from_utf8(header.value).map_err(|_| "invalid content length")?;
                            for part in value.split(',') {
                                let part = part.trim();
                                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) { return Err("invalid content length".into()); }
                                let v: usize = part.parse().map_err(|_| "content length overflow")?;
                                if length.is_some_and(|old| old != v) { return Err("conflicting content lengths".into()); }
                                length = Some(v);
                            }
                        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                            if transfer || !header.value.eq_ignore_ascii_case(b"chunked") { return Err("unsupported transfer encoding".into()); }
                            transfer = true;
                        } else if header.name.eq_ignore_ascii_case("content-encoding") {
                            if content_encoding || !header.value.eq_ignore_ascii_case(b"identity") { return Err("unsupported content encoding".into()); }
                            content_encoding = true;
                        }
                    }
                    if transfer && length.is_some() { return Err("ambiguous response framing".into()); }
                    Some((n, code, length, transfer))
                }
                Err(_) => return Err("malformed response headers".into()),
            }
        };
        if let Some((n, code, length, transfer)) = parsed {
            input.pos += n;
            if (100..200).contains(&code) {
                if code == 101 || length.is_some() || transfer { return Err("unsupported interim response".into()); }
                continue;
            }
            break (code, length, transfer);
        }
        if !input.more()? { return Err("incomplete response headers".into()); }
    };

    if status == 204 || status == 304 {
        if status == 204 && (length.is_some() || chunked) { return Err("invalid bodyless response framing".into()); }
        return Ok(ParsedResponse { status, body: Vec::new() });
    }
    let body = if chunked {
        let mut body = Vec::new();
        loop {
            let (line, size) = loop {
                match httparse::parse_chunk_size(&input.bytes[input.pos..]) {
                    Ok(httparse::Status::Complete(v)) => break v,
                    Ok(httparse::Status::Partial) => if !input.more()? { return Err("incomplete chunk size".into()); },
                    Err(_) => return Err("invalid chunk size".into()),
                }
            };
            input.pos += line;
            let size = usize::try_from(size).map_err(|_| "chunk size overflow")?;
            if size == 0 {
                loop {
                    let available = &input.bytes[input.pos..];
                    let mut headers = vec![httparse::EMPTY_HEADER; header_capacity(available)];
                    match httparse::parse_headers(available, &mut headers) {
                        Ok(httparse::Status::Complete((_, trailers))) => {
                            if trailers.iter().any(|h| h.name.eq_ignore_ascii_case("content-length") || h.name.eq_ignore_ascii_case("transfer-encoding") || h.name.eq_ignore_ascii_case("content-encoding")) { return Err("invalid framing trailer".into()); }
                            break;
                        }
                        Ok(httparse::Status::Partial) => if !input.more()? { return Err("incomplete chunk trailers".into()); },
                        Err(_) => return Err("invalid chunk trailers".into()),
                    }
                }
                break;
            }
            let framed = size.checked_add(2).ok_or("chunk size overflow")?;
            input.need(framed)?;
            body.extend_from_slice(&input.bytes[input.pos..input.pos + size]);
            input.pos += size;
            if &input.bytes[input.pos..input.pos + 2] != b"\r\n" { return Err("invalid chunk terminator".into()); }
            input.pos += 2;
        }
        body
    } else if let Some(n) = length {
        input.need(n)?;
        input.bytes[input.pos..input.pos + n].to_vec()
    } else {
        while input.more()? {}
        input.bytes[input.pos..].to_vec()
    };
    Ok(ParsedResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn content_encoding_requires_absent_or_single_identity() {
        for wire in [
            &b"HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 403 Forbidden\r\nContent-Encoding: identity, gzip\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 403 Forbidden\r\nContent-Encoding: identity\r\nContent-Encoding: identity\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 403 Forbidden\r\nContent-Encoding: \r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Encoding: gzip\r\n\r\n"[..],
        ] { assert!(read_response(&mut Cursor::new(wire)).is_err()); }
        for wire in [
            &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1\r\n\r\nx"[..],
            &b"HTTP/1.1 403 Forbidden\r\nContent-Encoding: Identity\r\nContent-Length: 1\r\n\r\nx"[..],
        ] {
            let response = read_response(&mut Cursor::new(wire)).unwrap();
            assert_eq!(response.status, 403);
            assert_eq!(response.body, b"x");
        }
    }

    struct Fragmented<'a>(&'a [u8]);
    impl Read for Fragmented<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.0.len().min(out.len()).min(1);
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn fragmented_chunked_with_trailers_and_interim() {
        let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n";
        let result = read_response(&mut Fragmented(wire)).unwrap();
        assert_eq!(result.status, 400);
        assert_eq!(result.body, b"abc");
    }

    #[test]
    fn rejects_ambiguous_truncated_and_unsupported_framing() {
        for wire in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nx"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nX: unfinished"[..],
        ] { assert!(read_response(&mut Cursor::new(wire)).is_err()); }
    }

    struct NoExtraRead<'a>(Option<&'a [u8]>);
    impl Read for NoExtraRead<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let bytes = self.0.take().expect("framed response must not request EOF");
            out[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    #[test]
    fn framed_messages_do_not_wait_for_eof() {
        for wire in [
            &b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 1\r\n\r\nx"[..],
            &b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"[..],
        ] { assert_eq!(read_response(&mut NoExtraRead(Some(wire))).unwrap().body, b"x"); }
    }

    #[test]
    fn close_delimited_zero_body_and_read_failure() {
        assert_eq!(read_response(&mut Cursor::new(b"HTTP/1.0 404 Not Found\r\n\r\nx")).unwrap().body, b"x");
        assert!(read_response(&mut Cursor::new(b"HTTP/1.1 204 No Content\r\n\r\n")).unwrap().body.is_empty());
        struct Failed;
        impl Read for Failed { fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { Err(io::Error::new(io::ErrorKind::Other, "synthetic")) } }
        assert!(read_response(&mut Failed).is_err());
    }

    #[test]
    #[ignore = "requires DNS_PROBE_WIRE_SAMPLE path to retained native response"]
    fn retained_native_wire_response() {
        let path = std::env::var_os("DNS_PROBE_WIRE_SAMPLE").expect("DNS_PROBE_WIRE_SAMPLE must name the retained wire response");
        let bytes = std::fs::read(path).expect("read retained native response");
        let result = read_response(&mut Cursor::new(bytes)).expect("parse retained native response");
        assert_eq!(result.status, 401);
        assert_eq!(result.body.len(), 651);
        let value: serde_json::Value = serde_json::from_slice(&result.body).expect("JSON response");
        assert_eq!(value["error"]["status"], "UNAUTHENTICATED");
    }
}
