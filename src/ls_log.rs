//! Reads the two facts no probe can measure - the region 400, and a model
//! answer - out of the language server's own log.
//!
//! `cloudcode-pa` refuses a blocked region with `FAILED_PRECONDITION (code 400):
//! User location is not supported for the API use`. That answer travels inside
//! the client's own TLS, and an unauthenticated probe never sees it -
//! `loadCodeAssist` answers 401 from a permitted and a blocked exit alike
//! (kb/dns.md). Every signal the tool has about a route's region is therefore
//! indirect: the exit's country, whether an address was substituted, whether a
//! tunnel carried bytes. The client's log is the only place the refusal is
//! written down in plain text, so the relay tails it.
//!
//! The other half is the one thing that proves the bypass works: a model answer
//! logs `…/v1internal:streamGenerateContent?alt=sse Trace: 0x… ResponseID: …`
//! when it starts streaming, and a refused turn logs no such line (measured on
//! the IDE log of 2026-09-12: refusals 14:58–15:00, first `ResponseID` 15:16).
//! Silence proves nothing - a user who gave up is silent too (G50) - so the
//! window says "работает" only on this line, and the route table ranks routes by
//! it (`routes`).
//!
//! Tailing, not reading: each pass looks at the lines appended since the last
//! one and nothing else, so an old refusal from a session hours ago cannot
//! trigger anything now. A file seen for the first time is taken from its end
//! for the same reason. A file that shrank was rotated or the app restarted, and
//! is read from the start - it is new content either way.
//!
//! Two readers, asking different questions of the same file. `poll` is the
//! relay's: "what came in since I last looked", which is what may be *acted*
//! on. `newest_refusal` is the window's: "is the user hitting the gate right
//! now", which has to be answerable about the minutes before this process
//! started - so it reads the log's own stamps rather than a saved offset. The
//! two share the pattern and the file list and nothing else; they run in
//! different processes and neither moves the other's position.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The refusal, as the language server logs it. Matched ASCII-case-insensitively
/// and never on the whole `FAILED_PRECONDITION` line: that status wraps other
/// preconditions too, and only this one is about where the request came from.
const REGION_400: &str = "user location is not supported";
const REGION_REASON: &str = "unsupported_location";
const REGION_NOT_ELIGIBLE: &str = "location_not_eligible";

fn is_region_reason(reason: &str) -> bool {
    reason.eq_ignore_ascii_case(REGION_REASON) || reason.eq_ignore_ascii_case(REGION_NOT_ELIGIBLE)
}

/// A model answer, as the language server logs it: the generation call and the
/// id of the response it got back, on one line. Both halves: `loadCodeAssist`
/// and `fetchAvailableModels` are logged the same way on a refused session too,
/// and only the generation call is behind the gate.
const ANSWER_CALL: &str = "streamgeneratecontent";
const ANSWER_ID: &str = "responseid:";

/// Google had no capacity for the model the user picked: `UNAVAILABLE (code
/// 503): No capacity available for model <name> on the server`, logged by the
/// language server on every retry of the turn. Not the gate and not the route -
/// the request got past both - so the only thing that helps is another model.
const OVERLOAD_503: &str = "unavailable (code 503)";
/// The same condition under the other names Google gives it: a quota-style 429
/// and the text the client shows the user (`Our servers are experiencing high
/// traffic`). Either way the request got past the gate and the route.
const OVERLOAD_429: &str = "resource_exhausted (code 429)";
const OVERLOAD_TRAFFIC: &str = "experiencing high traffic";
/// Google's own fault, not a capacity one: `INTERNAL (code 500)`. Counted for
/// the report only - the card does not tell anyone to pick another model for it.
const SERVER_500: &str = "internal (code 500)";
const OVERLOAD_MODEL: &[u8] = b"for model ";

/// The account's credentials stopped being accepted: `UNAUTHENTICATED (code
/// 401): Request had invalid authentication credentials` on every call (G11).
/// A re-login is the fix; no route changes it.
const UNAUTH_401: &str = "unauthenticated (code 401)";

/// A generation request the connection died under: `Run: attempt N failed
/// (request failed: Post ".../streamGenerateContent?alt=sse": EOF)` before a
/// byte came back, or `(stream reading error: unexpected EOF)` in the middle of
/// the answer. One line per attempt - the executor's own final report repeats
/// the last one without the word `attempt`, and is not counted.
const DROP_ATTEMPT: &str = "attempt";
const DROP_FAILED: &str = "failed (";
const DROP_STREAM_EOF: &str = "stream reading error: unexpected eof";
/// What the client's retries say once the first EOF has killed its connection
/// to our proxy: attempts 2..N fail on `write tcp …: use of closed network
/// connection`, never EOF again. Counting only EOF left the streak at 1 for six
/// attempts and the dead route in place (2026-10-15).
const DROP_CLOSED_CONN: &str = "use of closed network connection";

/// Longest slice of appended log read in one pass. Anything beyond it is a log
/// that grew by megabytes between two passes, which is not a session anyone is
/// working in; the tail is what carries the news.
const MAX_READ: u64 = 1024 * 1024;

#[cfg(test)]
pub(crate) fn test_max_read() -> u64 { MAX_READ }

/// How many products the scan is willing to look at. A user profile does not
/// hold more than a handful of `Antigravity*` folders, and a bound keeps a
/// pathological `%APPDATA%` from turning a 15 s tick into a directory walk.
const MAX_PRODUCTS: usize = 8;

/// Where each watched file was read up to.
static OFFSETS: Mutex<Option<HashMap<PathBuf, LogCursor>>> = Mutex::new(None);

#[derive(Clone, Default)]
struct LogCursor {
    offset: u64,
    source: Option<LogSourceId>,
    continuous: bool,
}

/// The gate host each file last named in a `URL:` line, carried across passes:
/// a refusal line names no host, and the call it refused was logged in an
/// earlier chunk more often than not.
static LAST_HOST: Mutex<Option<HashMap<PathBuf, String>>> = Mutex::new(None);

/// Whether the first pass has run. Files found on it hold history and are taken
/// from their end; a file that *appears* later is a new session - an IDE launch,
/// a CLI run - and everything in it is news, from the first byte. Taking those
/// from their end too lost the answer (or the refusal) a short CLI run writes
/// before the next pass comes round.
static FIRST_PASS_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// What one stretch of log said about the gate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tally {
    /// Refusal lines. One refused turn writes several (the stream handler, the
    /// executor and the error report each repeat it), so this counts lines, not
    /// turns.
    pub refusals: usize,
    /// How long ago the newest refusal was stamped. `None` when there was none,
    /// or its stamp could not be placed against the clock.
    pub refused_ago: Option<Duration>,
    /// Model answers: one line per answer that started streaming.
    pub answers: usize,
    pub answered_ago: Option<Duration>,
    /// Which gate host the newest refusal was about: the host of the last
    /// `URL: https://…` line before it in this file. The client keeps a
    /// connection pool per host, and the two can sit on different routes.
    pub refused_host: Option<String>,
    pub(crate) refused_endpoint: Option<EndpointEvent>,
    /// The host the newest answer's own line names.
    pub answered_host: Option<String>,
    pub(crate) answered_endpoint: Option<EndpointEvent>,
    /// Generation attempts the connection died under (EOF), and the newest.
    pub drops: usize,
    pub dropped_ago: Option<Duration>,
    pub dropped_host: Option<String>,
    pub(crate) direct_signals: Vec<DirectSignal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DirectSignalKind { Drop, Answer, Refusal }

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LogSourceId { volume: u64, file: [u8; 16] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignalContinuity { Proven, Fence }

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectSignal {
    pub(crate) kind: DirectSignalKind,
    pub(crate) at: Option<Instant>,
    pub(crate) host: Option<String>,
    pub(crate) source: Option<LogSourceId>,
    pub(crate) record_start: u64,
    pub(crate) record_end: u64,
    pub(crate) continuity: SignalContinuity,
    pub(crate) conflicting_record: bool,
}

#[cfg(unix)]
fn source_id(_: &File, metadata: &fs::Metadata) -> Option<LogSourceId> {
    use std::os::unix::fs::MetadataExt;
    let mut file = [0u8; 16];
    file[..8].copy_from_slice(&metadata.ino().to_ne_bytes());
    Some(LogSourceId { volume: metadata.dev(), file })
}

#[cfg(windows)]
fn source_id(file: &File, _: &fs::Metadata) -> Option<LogSourceId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandleEx, FileIdInfo, FILE_ID_INFO};
    let mut info = FILE_ID_INFO::default();
    // The retained File owns this valid handle throughout the call, and the
    // buffer has the size and layout required by FileIdInfo.
    let ok = unsafe {
        GetFileInformationByHandleEx(file.as_raw_handle(), FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(), std::mem::size_of::<FILE_ID_INFO>() as u32)
    };
    (ok != 0).then_some(LogSourceId { volume: info.VolumeSerialNumber, file: info.FileId.Identifier })
}

#[cfg(not(any(unix, windows)))]
fn source_id(_: &File, _: &fs::Metadata) -> Option<LogSourceId> { None }

#[cfg(test)]
pub(crate) fn test_source_id(file: &File) -> Option<LogSourceId> {
    source_id(file, &file.metadata().ok()?)
}

/// A placed event and the host named on that same line are inseparable. A
/// hostless or conflicting equal-time event cannot borrow another event's host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointEvent { pub(crate) age: Duration, pub(crate) host: Option<String> }

pub(crate) fn merge_endpoint_event(current: &mut Option<EndpointEvent>, incoming: Option<EndpointEvent>) {
    let Some(incoming) = incoming else { return; };
    match current {
        None => *current = Some(incoming),
        Some(existing) if incoming.age < existing.age => *existing = incoming,
        Some(existing) if incoming.age == existing.age && incoming.host != existing.host => existing.host = None,
        _ => {}
    }
}

impl Tally {
    pub fn is_empty(&self) -> bool {
        self.refusals == 0 && self.answers == 0 && self.drops == 0
    }

    fn add(&mut self, mut other: Tally) {
        self.direct_signals.append(&mut other.direct_signals);
        self.refusals += other.refusals;
        self.answers += other.answers;
        self.drops += other.drops;
        if other.dropped_ago.is_some()
            && newer(self.dropped_ago, other.dropped_ago) == other.dropped_ago
        {
            self.dropped_host = other.dropped_host.clone();
        } else if self.dropped_host.is_none() {
            self.dropped_host = other.dropped_host.clone();
        }
        self.dropped_ago = newer(self.dropped_ago, other.dropped_ago);
        // The host goes with whichever event is newer - an unplaceable one
        // (no age) never displaces a placed one.
        if other.refused_ago.is_some()
            && newer(self.refused_ago, other.refused_ago) == other.refused_ago
        {
            self.refused_host = other.refused_host.clone();
        } else if self.refused_host.is_none() {
            self.refused_host = other.refused_host.clone();
        }
        if other.answered_ago.is_some()
            && newer(self.answered_ago, other.answered_ago) == other.answered_ago
        {
            self.answered_host = other.answered_host.clone();
        } else if self.answered_host.is_none() {
            self.answered_host = other.answered_host.clone();
        }
        self.refused_ago = newer(self.refused_ago, other.refused_ago);
        self.answered_ago = newer(self.answered_ago, other.answered_ago);
        merge_endpoint_event(&mut self.refused_endpoint, other.refused_endpoint);
        merge_endpoint_event(&mut self.answered_endpoint, other.answered_endpoint);
    }
}

fn newer(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// One pass over every client log on the machine. Returns the files that
/// gained a refusal or an answer since the last pass, with what each gained.
pub fn poll() -> Vec<(PathBuf, Tally)> {
    let mut out = Vec::new();
    let Ok(mut guard) = OFFSETS.lock() else {
        return out;
    };
    let offsets = guard.get_or_insert_with(HashMap::new);
    let started = FIRST_PASS_DONE.swap(true, std::sync::atomic::Ordering::Relaxed);
    let mut hosts = LAST_HOST.lock().ok();
    let now = crate::utils::local_clock();
    let anchor = Instant::now();
    for path in candidate_logs() {
        let mut last_host = hosts
            .as_mut()
            .and_then(|h| h.get_or_insert_with(HashMap::new).get(&path).cloned());
        let (first_sight, tally) = poll_path(&path, offsets, started, now, anchor, &mut last_host);
        if let (Some(h), Some(host)) = (hosts.as_mut(), last_host) {
            h.get_or_insert_with(HashMap::new)
                .insert(path.clone(), host);
        }
        if (!first_sight || started) && !tally.is_empty() {
            out.push((path, tally));
        }
    }
    out
}

fn poll_path(
    path: &Path,
    offsets: &mut HashMap<PathBuf, LogCursor>,
    started: bool,
    now: Option<crate::utils::LocalClock>,
    anchor: Instant,
    last_host: &mut Option<String>,
) -> (bool, Tally) {
    let first_sight = !offsets.contains_key(path);
    let from = offsets.get(path).cloned().or_else(|| started.then(LogCursor::default));
    let (next, tally) = scan_cursor(path, from, now, anchor, last_host);
    offsets.insert(path.to_path_buf(), next);
    (first_sight, tally)
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestLogCursor {
    offsets: HashMap<PathBuf, LogCursor>,
    last_host: Option<String>,
}

#[cfg(test)]
pub(crate) fn test_poll_log(
    cursor: &mut TestLogCursor,
    path: &Path,
    now: Option<crate::utils::LocalClock>,
    anchor: Instant,
) -> Tally {
    poll_path(path, &mut cursor.offsets, true, now, anchor, &mut cursor.last_host).1
}

/// Reads `path` from `from` (or from its end, when it has never been read) and
/// tallies the complete lines appended since. Returns where the next read
/// starts: just past the last complete line, so a line the logger's buffer
/// flush split across two passes is read once, whole, on the second.
///
/// Pure in the sense that matters for a test: no static, one file, one answer.
#[cfg(test)]
fn scan(
    path: &Path,
    from: Option<u64>,
    now: Option<crate::utils::LocalClock>,
    last_host: &mut Option<String>,
) -> (u64, Tally) {
    scan_with_anchor(path, from, now, Instant::now(), last_host)
}

#[cfg(test)]
pub(crate) fn test_scan_log(
    path: &Path,
    from: Option<u64>,
    now: Option<crate::utils::LocalClock>,
    anchor: Instant,
) -> (u64, Tally) {
    scan_with_anchor(path, from, now, anchor, &mut None)
}

fn scan_with_anchor(
    path: &Path,
    from: Option<u64>,
    now: Option<crate::utils::LocalClock>,
    anchor: Instant,
    last_host: &mut Option<String>,
) -> (u64, Tally) {
    let cursor = from.map(|offset| LogCursor { offset, ..LogCursor::default() });
    let (next, tally) = scan_cursor(path, cursor, now, anchor, last_host);
    (next.offset, tally)
}

fn scan_cursor(
    path: &Path,
    cursor: Option<LogCursor>,
    now: Option<crate::utils::LocalClock>,
    anchor: Instant,
    last_host: &mut Option<String>,
) -> (LogCursor, Tally) {
    let from = cursor.as_ref().map(|c| c.offset);
    let failed = || LogCursor { offset: from.unwrap_or(0), ..LogCursor::default() };
    let Ok(mut f) = File::open(path) else {
        return (failed(), Tally::default());
    };
    let Ok(metadata) = f.metadata() else {
        return (failed(), Tally::default());
    };
    let len = metadata.len();
    let source = source_id(&f, &metadata);
    let Some(from) = from else {
        // Never seen: history is not news.
        return (LogCursor { offset: len, source, continuous: false }, Tally::default());
    };
    // Shrunk means rotated or restarted, and everything in it is new.
    let mut start = if len < from { 0 } else { from };
    if len == start {
        let continuous = cursor.as_ref().is_some_and(|c| c.continuous && c.source.is_some() && c.source == source && len == from);
        return (LogCursor { offset: len, source, continuous }, Tally::default());
    }
    let skipped = len - start > MAX_READ;
    if skipped {
        start = len - MAX_READ;
    }
    let mut starts_at_boundary = start == 0;
    if start > 0 && f.seek(SeekFrom::Start(start - 1)).is_ok() {
        let mut prior = [0u8; 1];
        starts_at_boundary = f.read_exact(&mut prior).is_ok() && prior[0] == b'\n';
    }
    if f.seek(SeekFrom::Start(start)).is_err() {
        return (failed(), Tally::default());
    }
    let mut buf = Vec::with_capacity((len - start) as usize);
    if (&mut f).take(len - start).read_to_end(&mut buf).is_err() {
        return (failed(), Tally::default());
    }
    let full_read = buf.len() as u64 == len - start;
    let continues = full_read && starts_at_boundary && !skipped && start == from && source.is_some()
        && cursor.as_ref().is_some_and(|c| c.continuous && c.source == source);
    let Some(last_nl) = buf.iter().rposition(|b| *b == b'\n') else {
        // No complete line yet. Wait for the rest - unless the slice is the
        // whole read budget, which is one line nobody will ever finish.
        if buf.len() as u64 >= MAX_READ {
            return (LogCursor { offset: len, source, continuous: false }, Tally::default());
        }
        return (LogCursor { offset: start, source, continuous: continues }, Tally::default());
    };
    let complete = &buf[..=last_nl];
    let tally = tally_signals(complete, now, last_host, start, anchor, source.clone(), starts_at_boundary, continues);
    // A delivered fenced signal establishes the start of a fresh observed run.
    // An unconsumed suffix is reread from the last complete-record boundary.
    let continuous = full_read && source.is_some() && (continues || !tally.direct_signals.is_empty());
    (LogCursor { offset: start + last_nl as u64 + 1, source, continuous }, tally)
}

/// Refusals and answers in a stretch of complete lines, with the newest of each
/// placed against `now` by the line's own stamp.
fn tally(
    chunk: &[u8],
    now: Option<crate::utils::LocalClock>,
    last_host: &mut Option<String>,
) -> Tally {
    tally_signals(chunk, now, last_host, 0, Instant::now(), None, false, false)
}

fn tally_signals(
    chunk: &[u8],
    now: Option<crate::utils::LocalClock>,
    last_host: &mut Option<String>,
    offset: u64,
    anchor: Instant,
    source: Option<LogSourceId>,
    first_complete: bool,
    continues: bool,
) -> Tally {
    let mut out = Tally::default();
    let mut position = offset;
    let mut boundary = first_complete;
    let mut prior_record = continues;
    for record in chunk.split_inclusive(|b| *b == b'\n') {
        let end = position + record.len() as u64;
        let line = record.strip_suffix(b"\n").unwrap_or(record);
        let named = url_host(line);
        if named.is_some() {
            *last_host = named.clone();
        }
        let refusals = count_refusals(line);
        let answered = is_answer(line);
        let dropped = is_stream_drop(line);
        let kind_count = usize::from(refusals > 0) + usize::from(answered) + usize::from(dropped);
        let ago = now.and_then(|now| {
            let text = String::from_utf8_lossy(line);
            parse_stamp(&text)
                .and_then(|at| age_secs(at, now))
                .map(|s| Duration::from_secs(s as u64))
        });
        if boundary && record.ends_with(b"\n") {
            let marker = b"URL:";
            let unique_url = match_offsets_ci(line, marker).count() == 1;
            let signal_host = if unique_url { named.clone() } else { None };
            let continuity = if source.is_some() && prior_record { SignalContinuity::Proven } else { SignalContinuity::Fence };
            for (present, kind) in [(dropped, DirectSignalKind::Drop), (answered, DirectSignalKind::Answer), (refusals > 0, DirectSignalKind::Refusal)] {
                if present {
                    out.direct_signals.push(DirectSignal {
                        kind, at: ago.and_then(|age| anchor.checked_sub(age)), host: signal_host.clone(),
                        source: source.clone(), record_start: position, record_end: end,
                        continuity, conflicting_record: kind_count > 1,
                    });
                }
            }
            if kind_count > 0 { prior_record = true; }
        }
        position = end;
        boundary = record.ends_with(b"\n");
        if refusals == 0 && !answered && !dropped {
            continue;
        }
        if refusals > 0 {
            out.add(Tally {
                refusals,
                refused_ago: ago,
                refused_host: last_host.clone(),
                refused_endpoint: ago.map(|age| EndpointEvent { age, host: named.clone() }),
                ..Tally::default()
            });
        }
        if dropped {
            out.add(Tally {
                drops: 1,
                dropped_ago: ago,
                dropped_host: last_host.clone(),
                ..Tally::default()
            });
        }
        if answered {
            out.add(Tally {
                answers: 1,
                answered_ago: ago,
                answered_host: named.clone().or_else(|| last_host.clone()),
                answered_endpoint: ago.map(|age| EndpointEvent { age, host: named }),
                ..Tally::default()
            });
        }
    }
    out
}

/// The host of a `URL: https://<host>/…` line, lower-cased; `None` for any
/// other line or a host that is not one of ours.
fn url_host(line: &[u8]) -> Option<String> {
    const MARK: &[u8] = b"URL: https://";
    let at = match_offsets_ci(line, MARK).next()? + MARK.len();
    let rest = &line[at..];
    let end = rest
        .iter()
        .position(|b| *b == b'/' || *b == b':' || b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let host = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
    let port = if rest.get(end) == Some(&b':') {
        let suffix = &rest[end + 1..];
        let length = suffix.iter().position(|b| *b == b'/' || b.is_ascii_whitespace()).unwrap_or(suffix.len());
        std::str::from_utf8(&suffix[..length]).ok()?.parse::<u16>().ok()?
    } else { 443 };
    crate::gate_hosts::is_public_dns_target(&host, port).then_some(host)
}

/// Whether a line is one failed generation attempt the connection died under.
fn is_stream_drop(line: &[u8]) -> bool {
    if !(contains_ci(line, DROP_ATTEMPT.as_bytes()) && contains_ci(line, DROP_FAILED.as_bytes())) {
        return false;
    }
    contains_ci(line, DROP_STREAM_EOF.as_bytes())
        || (contains_ci(line, ANSWER_CALL.as_bytes())
            && (contains_ci(line, b"eof") || contains_ci(line, DROP_CLOSED_CONN.as_bytes())))
}

/// Whether a line is a model answer that started streaming.
fn is_answer(line: &[u8]) -> bool {
    contains_ci(line, ANSWER_CALL.as_bytes()) && contains_ci(line, ANSWER_ID.as_bytes())
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    match_offsets_ci(hay, needle).next().is_some()
}

fn match_offsets_ci<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    assert!(!needle.is_empty(), "window size must be non-zero");
    let starts = match hay.len().checked_sub(needle.len()) {
        Some(last) => &hay[..=last],
        None => &hay[..0],
    };
    let lower = needle[0].to_ascii_lowercase();
    let upper = needle[0].to_ascii_uppercase();
    let one = (lower == upper).then(|| memchr::memchr_iter(lower, starts));
    let two = (lower != upper).then(|| memchr::memchr2_iter(lower, upper, starts));

    // The first byte only rules out impossible starts. The original whole
    // window comparison is authoritative, and overlapping offsets are kept.
    one.into_iter().flatten().chain(two.into_iter().flatten())
        .filter(move |&start| hay[start..start + needle.len()].eq_ignore_ascii_case(needle))
}

/// Occurrences of the refusal in a chunk of log, case-insensitively. Byte-wise,
/// because the log is a stream of glog lines that a partial last line may cut
/// anywhere, and a UTF-8 boundary is not something worth failing on.
fn count_refusals(buf: &[u8]) -> usize {
    buf.split(|byte| *byte == b'\n').map(count_refusal_line).sum()
}

fn count_refusal_line(buf: &[u8]) -> usize {
    let needle = REGION_400.as_bytes();
    let legacy = match_offsets_ci(buf, needle).count();
    if legacy != 0 { return legacy; }
    let key = b"\"reason\"";
    let structured = match_offsets_ci(buf, key).filter(|index| {
        let mut tail = &buf[*index + key.len()..];
        while tail.first().is_some_and(u8::is_ascii_whitespace) { tail = &tail[1..]; }
        if !tail.starts_with(b":") { return false; }
        tail = &tail[1..];
        while tail.first().is_some_and(u8::is_ascii_whitespace) { tail = &tail[1..]; }
        if !tail.starts_with(b"\"") { return false; }
        let Some(end) = tail[1..].iter().position(|byte| *byte == b'"') else { return false; };
        std::str::from_utf8(&tail[1..1 + end]).ok().is_some_and(is_region_reason)
    }).count();
    let json_start = buf.iter().find(|byte| !byte.is_ascii_whitespace());
    if structured == 0 && matches!(json_start, Some(b'{') | Some(b'[')) && json_region_reason(buf) { 1 } else { structured }
}

fn json_region_reason(body: &[u8]) -> bool {
    fn contains_reason(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(fields) => fields.iter().any(|(key, value)|
                (key.eq_ignore_ascii_case("reason") && value.as_str().is_some_and(is_region_reason))
                    || contains_reason(value)),
            serde_json::Value::Array(items) => items.iter().any(contains_reason),
            _ => false,
        }
    }
    serde_json::from_slice::<serde_json::Value>(body).ok().is_some_and(|value| contains_reason(&value))
}

pub(crate) fn is_region_refusal(body: &[u8]) -> bool {
    count_refusals(body) != 0 || json_region_reason(body)
}

/// The language-server logs of every Antigravity product under the user's
/// roaming profile, and the CLI's.
///
/// Desktop writes `<product>\logs\language_server.log`; the IDE, a VS Code
/// fork, writes `<product>\logs\<session stamp>\ls-main.log`, one folder per
/// launch - so for it only the newest session is watched. Product folders are
/// matched by prefix rather than listed, so a rebranded build is picked up too.
/// The CLI (`agy`) and the extension backend write the same glog format
/// to `~/.gemini/antigravity-cli/log` and `~/.gemini/antigravity/log`,
/// respectively. Watch the newest `cli-*.log` from each.
/// Public because the window holds the list rather than rebuilding it: this
/// walks `%APPDATA%` and then the IDE's `logs` folder, which has one sub-folder
/// per launch, and a window ticking every three seconds must not do that.
pub fn candidate_logs() -> Vec<PathBuf> {
    let root = profile_root();
    #[cfg(target_os = "macos")]
    let macos_logs = std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join("Library").join("Logs"));
    #[cfg(not(target_os = "macos"))]
    let macos_logs: Option<PathBuf> = None;

    let gemini_root = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(|home| PathBuf::from(home).join(".gemini"));
    candidate_logs_in(
        root.as_deref(),
        macos_logs.as_deref(),
        gemini_root.as_deref(),
        cfg!(not(target_os = "macos")),
    )
    .unwrap_or_default()
}

fn candidate_logs_in(
    profile_root: Option<&Path>,
    macos_logs: Option<&Path>,
    gemini_root: Option<&Path>,
    require_profile: bool,
) -> Option<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries = match profile_root.and_then(|root| fs::read_dir(root).ok()) {
        Some(entries) => Some(entries),
        None if require_profile => return None,
        None => None,
    };
    if let Some(entries) = entries {
            let mut products = 0usize;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.to_ascii_lowercase().starts_with("antigravity") {
                    continue;
                }
                products += 1;
                if products > MAX_PRODUCTS {
                    break;
                }
                let logs = entry.path().join("logs");
                let desktop = logs.join("language_server.log");
                if desktop.is_file() {
                    out.push(desktop);
                }
                if let Some(session) = newest_session(&logs) {
                    let ide = session.join("ls-main.log");
                    if ide.is_file() {
                        out.push(ide);
                    }
                }
            }
    }
    if let Some(logs_dir) = macos_logs {
        if let Ok(entries) = fs::read_dir(logs_dir) {
            let mut products = 0usize;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.to_ascii_lowercase().starts_with("antigravity") {
                    continue;
                }
                products += 1;
                if products > MAX_PRODUCTS {
                    break;
                }
                let desktop = entry.path().join("language_server.log");
                if desktop.is_file() && !out.contains(&desktop) {
                    out.push(desktop);
                }
            }
        }
    }
    if let Some(gemini_root) = gemini_root {
        for product in ["antigravity-cli", "antigravity"] {
            if let Some(log) = newest_cli_log(&gemini_root.join(product).join("log")) {
                out.push(log);
            }
        }
    }
    Some(out)
}

/// One backend's current session log: the newest `cli-*.log`.
fn newest_cli_log(dir: &Path) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with("cli-") && n.ends_with(".log")
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max_by(|(ma, pa), (mb, pb)| ma.cmp(mb).then_with(|| pa.cmp(pb)))
        .map(|(_, p)| p)
}

/// The most recently modified sub-folder of `logs`, i.e. the IDE's current
/// session.
fn newest_session(logs: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(logs).ok()?;
    entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((modified, e.path()))
        })
        // Ties - same second on a coarse filesystem - go to the later stamp:
        // the folder names are timestamps and sort chronologically.
        .max_by(|(ma, pa), (mb, pb)| ma.cmp(mb).then_with(|| pa.cmp(pb)))
        .map(|(_, p)| p)
}

#[cfg(target_os = "windows")]
fn profile_root() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn profile_root() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
}

/// Linux keeps the same layout under `~/.config`; nothing tails it there yet
/// because the DNS layer it would steer is not ported, but the path is right.
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn profile_root() -> Option<PathBuf> {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => Some(PathBuf::from(x)),
        _ => std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".config")),
    }
}

// ---------------------------------------------------------------------------
// Reading the same log the other way round: what is *there*, not what is new.
// ---------------------------------------------------------------------------

/// The newest refusal a client log carries, as the window needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    /// How long ago the newest one was written, by the log's own stamp.
    pub ago: Duration,
    /// How many fall inside the window asked for.
    pub count: usize,
}

/// How much of a log's tail is read looking for one. A session's worth of glog
/// is a few hundred kilobytes an hour, and the window asked for is minutes.
const HISTORY_TAIL: u64 = 256 * 1024;

/// A stamp a second or two ahead of our own read of the clock is *now*, not a
/// line from the future: the logger and this process read the same clock at
/// slightly different moments, and `GetLocalTime` has whole-second resolution.
const CLOCK_SLACK: u32 = 5;

/// The newest refusal in any client log inside `within`, and how many there are.
///
/// `poll` above answers "what is new since I last looked", which is the right
/// question for the relay and the wrong one for a window: a user who hits the
/// gate and *then* opens this tool would be told nothing had happened. So this
/// reads the log's own timestamps rather than a saved position, and it is the
/// only place in the tool that parses them.
///
/// `None` without a local clock to compare against (non-Windows): an age nobody
/// can compute is not one to guess at.
#[cfg_attr(not(test), allow(dead_code))]
pub fn newest_refusal(paths: &[PathBuf], within: Duration) -> Option<Sighting> {
    // Occurrences, not lines: one line can carry more than one, and
    // `Episode.count` on the relay's side counts them the same way.
    newest_matching(paths, within, |line| count_refusals(line.as_bytes()))
}

/// The newest model answer any client log carries inside `within`, and how many
/// there are. The window's proof that the bypass works right now.
#[cfg_attr(not(test), allow(dead_code))]
pub fn newest_answer(paths: &[PathBuf], within: Duration) -> Option<Sighting> {
    newest_matching(paths, within, |line| is_answer(line.as_bytes()) as usize)
}

/// Everything the window asks of the logs, in one read of each tail.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    /// Refusals inside `recent`: the newest, and how many.
    pub refused_recent: Option<Sighting>,
    /// The newest refusal inside `horizon`, however old.
    pub refused: Option<Sighting>,
    /// The newest model answer inside `horizon`, and how many.
    pub answered: Option<Sighting>,
    /// The newest account-verification demand inside `horizon`.
    pub verify: Option<Verification>,
    /// Google out of capacity for the chosen model (503) inside `recent`.
    pub overloaded: Option<Overload>,
    /// The account's credentials refused (401) inside `recent`.
    pub unauthorized: Option<Sighting>,
    /// Every Google-side failure (503, 429, 500, "high traffic") inside
    /// `horizon`: the newest and how many. The report's 12 h line; `overloaded`
    /// is the ten-minute one the card is drawn from.
    pub server_errors: Option<Sighting>,
}

/// The newest 503 "no capacity" a client log carries, and for which model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overload {
    pub ago: Duration,
    pub count: usize,
    /// The model named in the newest line; empty when the line names none.
    pub model: String,
}

/// A line that says Google had no room for the request.
fn is_overload(line: &[u8]) -> bool {
    [OVERLOAD_503, OVERLOAD_429, OVERLOAD_TRAFFIC]
        .iter()
        .any(|n| contains_ci(line, n.as_bytes()))
}

/// The model a 503 line names (`… for model <name> on the server`).
fn overload_model(line: &[u8]) -> String {
    let lower = line.to_ascii_lowercase();
    let Some(at) = find(&lower, OVERLOAD_MODEL) else {
        return String::new();
    };
    let rest = &line[at + OVERLOAD_MODEL.len()..];
    let end = rest
        .iter()
        .position(|&c| !(c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')))
        .unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// `newest_refusal` and `newest_answer` over two windows, from a single pass:
/// the window asked three questions of the same tail every time the log grew,
/// and a busy Desktop log grows every second.
pub fn history(paths: &[PathBuf], recent: Duration, horizon: Duration) -> History {
    let Some(now) = crate::utils::local_clock() else {
        return History::default();
    };
    let mut out = History::default();
    let bump = |slot: &mut Option<Sighting>, ago: Duration, hits: usize| {
        *slot = Some(match *slot {
            Some(s) => Sighting {
                ago: s.ago.min(ago),
                count: s.count + hits,
            },
            None => Sighting { ago, count: hits },
        });
    };
    for path in paths {
        let Some(text) = tail(path, HISTORY_TAIL) else {
            continue;
        };
        for line in text.lines() {
            let refusals = count_refusals(line.as_bytes());
            let answered = is_answer(line.as_bytes());
            let overloaded = is_overload(line.as_bytes());
            let server_error = overloaded || contains_ci(line.as_bytes(), SERVER_500.as_bytes());
            let unauthorized = contains_ci(line.as_bytes(), UNAUTH_401.as_bytes());
            if refusals == 0 && !answered && !server_error && !unauthorized {
                continue;
            }
            let Some(ago) = parse_stamp(line).and_then(|at| age_secs(at, now)) else {
                continue;
            };
            let ago = Duration::from_secs(ago as u64);
            if ago > horizon {
                continue;
            }
            if server_error {
                bump(&mut out.server_errors, ago, 1);
            }
            if overloaded && ago <= recent {
                let newest = out.overloaded.as_ref().is_none_or(|o| ago <= o.ago);
                let o = out.overloaded.get_or_insert(Overload {
                    ago,
                    count: 0,
                    model: String::new(),
                });
                o.count += 1;
                if newest {
                    o.ago = ago;
                    let model = overload_model(line.as_bytes());
                    if !model.is_empty() {
                        o.model = model;
                    }
                }
            }
            if unauthorized && ago <= recent {
                bump(&mut out.unauthorized, ago, 1);
            }
            if refusals > 0 {
                bump(&mut out.refused, ago, refusals);
                if ago <= recent {
                    bump(&mut out.refused_recent, ago, refusals);
                }
            }
            if answered {
                bump(&mut out.answered, ago, 1);
            }
        }
        if let Some(v) = newest_verification(&text, now, horizon) {
            if out.verify.as_ref().is_none_or(|o| v.ago < o.ago) {
                out.verify = Some(v);
            }
        }
    }
    out
}

fn newest_matching(
    paths: &[PathBuf],
    within: Duration,
    hits_in: impl Fn(&str) -> usize,
) -> Option<Sighting> {
    let now = crate::utils::local_clock()?;
    let mut newest: Option<Duration> = None;
    let mut count = 0usize;
    for path in paths {
        let Some(text) = tail(path, HISTORY_TAIL) else {
            continue;
        };
        for line in text.lines() {
            let hits = hits_in(line);
            if hits == 0 {
                continue;
            }
            // A line whose stamp will not parse is one the tail cut in half, or
            // one some future build writes differently. Either way it cannot be
            // placed in time, and an unplaceable refusal is not evidence of
            // anything happening *now*.
            let Some(ago) = parse_stamp(line).and_then(|at| age_secs(at, now)) else {
                continue;
            };
            let ago = Duration::from_secs(ago as u64);
            if ago > within {
                continue;
            }
            count += hits;
            if newest.is_none_or(|n| ago < n) {
                newest = Some(ago);
            }
        }
    }
    newest.map(|ago| Sighting { ago, count })
}

/// Google asking the signed-in account to prove itself before it may use the
/// model: a `403` whose `google.rpc.ErrorInfo` says `VALIDATION_REQUIRED` and
/// carries the page to do it on in `metadata.validation_url` (the same field
/// arrives as `validationUrl` on an ineligible tier at sign-in). The client is
/// meant to show «Complete verification» for it, and does not always - the
/// link is then only in its log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// How long ago, by the log's own stamp.
    pub ago: Duration,
    /// The page, decoded from the JSON it came in and checked to be Google's.
    pub url: String,
}

/// The reason code, as the client itself matches it (`reason ===
/// "VALIDATION_REQUIRED"` in the workbench).
const VERIFY_REASON: &[u8] = b"VALIDATION_REQUIRED";
/// How far from the link its reason may be and still be the same error body.
/// Google pretty-prints the body, and `details` holds a handful of short
/// entries; a few kilobytes covers it without reaching a neighbouring error.
const VERIFY_REACH: usize = 4096;
/// How many lines back from the link its entry's stamp is looked for: the body
/// spans lines of its own, and only the line that opens the entry is stamped.
const VERIFY_STAMP_LINES: usize = 200;

/// The newest verification demand in `text` inside `horizon`.
///
/// Searched by bytes, not parsed as JSON, and that is forced by the file: the
/// IDE writes the server's stderr in chunks, with blank lines and its own
/// `[LS Main stderr]` prefix wherever a chunk starts, so a body that spans lines
/// does not survive as one JSON document. The one value needed is short and
/// never broken across lines, so it is read as a JSON string where it stands.
fn newest_verification(
    text: &str,
    now: crate::utils::LocalClock,
    horizon: Duration,
) -> Option<Verification> {
    let bytes = text.as_bytes();
    // ASCII lowercasing keeps every byte offset where it was.
    let lower = text.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let mut best: Option<Verification> = None;
    let mut from = 0usize;
    while let Some(off) = find(&lb[from..], b"validation") {
        let key = from + off;
        from = key + 1;
        let Some(value_at) = url_value_start(lb, key) else {
            continue;
        };
        let lo = key.saturating_sub(VERIFY_REACH);
        let hi = (key + VERIFY_REACH).min(bytes.len());
        if !has_reason(&bytes[lo..hi]) {
            continue;
        }
        let Some(url) = read_value(bytes, value_at).filter(|u| is_google_page(u)) else {
            continue;
        };
        let Some(ago) = stamp_before(text, key).and_then(|at| age_secs(at, now)) else {
            continue;
        };
        let ago = Duration::from_secs(ago as u64);
        if ago > horizon {
            continue;
        }
        // `<=`: of two in the same second, the later one in the file.
        if best.as_ref().is_none_or(|b| ago <= b.ago) {
            best = Some(Verification { ago, url });
        }
    }
    best
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Where the value of a link key starting at `key` begins, or `None` if the
/// word there is not one. Takes `validation_url` and `validationUrl` (and Go's
/// `ValidationURL`) - lowercased by the caller - but not
/// `validation_url_link_text`, which is the button's caption.
fn url_value_start(lower: &[u8], key: usize) -> Option<usize> {
    let rest = &lower[key..];
    let len = if rest.starts_with(b"validation_url") {
        14
    } else if rest.starts_with(b"validationurl") {
        13
    } else {
        return None;
    };
    if key > 0 && is_word(lower[key - 1]) {
        return None;
    }
    let mut i = key + len;
    if lower.get(i).is_some_and(|&c| is_word(c)) {
        return None;
    }
    // The key's own closing quote, escaped once when the body was logged as a
    // quoted string.
    if lower.get(i) == Some(&b'\\') {
        i += 1;
    }
    if lower.get(i) == Some(&b'"') {
        i += 1;
    }
    while lower.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
        i += 1;
    }
    if lower.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while lower.get(i).is_some_and(|c| *c == b' ' || *c == b'\t') {
        i += 1;
    }
    Some(i)
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// `VALIDATION_REQUIRED` as a word of its own, so an enum listing it among
/// others still counts but a longer name that merely contains it does not.
fn has_reason(window: &[u8]) -> bool {
    let mut from = 0usize;
    while let Some(off) = find(&window[from..], VERIFY_REASON) {
        let at = from + off;
        let end = at + VERIFY_REASON.len();
        let before = at == 0 || !is_word(window[at - 1]);
        let after = window.get(end).is_none_or(|&c| !is_word(c));
        if before && after {
            return true;
        }
        from = at + 1;
    }
    false
}

/// The link at `at`, in whichever of the three shapes it was logged: a JSON
/// string (`"https:…&…"`), that string escaped once more because the whole
/// body was logged as a quoted string (`\"https:…\\u0026…\"`), or bare, as Go
/// prints a struct (`ValidationURL:https://… `). JSON escapes are decoded - a
/// link with `&` left in it opens a page with its parameters broken.
fn read_value(bytes: &[u8], at: usize) -> Option<String> {
    let rest = bytes.get(at..)?;
    if rest.starts_with(b"\\\"") {
        // Undo the outer quoting, then read what is left as the JSON string it was.
        let end = find(&rest[2..], b"\\\"")? + 2;
        let mut inner = Vec::with_capacity(end);
        let mut i = 2;
        while i < end {
            if rest[i] == b'\\' && i + 1 < end {
                inner.push(rest[i + 1]);
                i += 2;
            } else {
                inner.push(rest[i]);
                i += 1;
            }
        }
        let lit = format!("\"{}\"", String::from_utf8(inner).ok()?);
        return serde_json::from_str::<String>(&lit).ok();
    }
    if rest.first() == Some(&b'"') {
        let mut i = 1;
        while i < rest.len() {
            match rest[i] {
                b'\\' => i += 2,
                b'"' => {
                    let lit = std::str::from_utf8(&rest[..=i]).ok()?;
                    return serde_json::from_str::<String>(lit).ok();
                }
                b'\n' | b'\r' => return None,
                _ => i += 1,
            }
        }
        return None;
    }
    if rest.starts_with(b"https://") {
        let end = rest
            .iter()
            .position(|c| c.is_ascii_whitespace() || *c == b'}' || *c == b'"')
            .unwrap_or(rest.len());
        return String::from_utf8(rest[..end].to_vec()).ok();
    }
    None
}

/// Only a Google page over HTTPS is ever opened: the link comes out of a log
/// file, and a button that opens whatever a log line says is a button anyone
/// who can write a line there controls.
fn is_google_page(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if url.len() > 8192 || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest[..host_end].to_ascii_lowercase();
    // No userinfo and no port: `https://google.com@evil/` names `evil`.
    if host.contains(['@', ':', '\\']) {
        return false;
    }
    host == "google.com" || host.ends_with(".google.com")
}

/// The stamp of the entry holding byte `pos`: the nearest stamped line at or
/// above it.
fn stamp_before(text: &str, pos: usize) -> Option<(u16, u16, u32)> {
    let line_end = text[pos..].find('\n').map_or(text.len(), |i| pos + i);
    text[..line_end]
        .rsplit('\n')
        .take(VERIFY_STAMP_LINES)
        .find_map(parse_stamp)
}

/// Total size of the given logs. The cheap half of "is Antigravity doing
/// anything" - one `metadata` per file and no read at all - which is what the
/// window gates both its scans and its VPN measurement on. A log that has not
/// grown cannot have gained a refusal, and a client that is not writing is not
/// one whose route can have changed under us.
pub fn bytes_of(paths: &[PathBuf]) -> u64 {
    paths
        .iter()
        .filter_map(|p| fs::metadata(p).ok().map(|m| m.len()))
        .sum()
}

/// The last `max` bytes of a file, as text. The first line usually comes back
/// cut; that is the caller's problem and it handles it by refusing to place a
/// line it cannot parse.
fn tail(path: &Path, max: u64) -> Option<String> {
    let len = fs::metadata(path).ok()?.len();
    let start = len.saturating_sub(max);
    let mut f = File::open(path).ok()?;
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.take(len - start).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// glog's header — a level letter, `MMDD`, a space, then local `HH:MM:SS.ffffff`
/// — wherever in the line it sits.
///
/// Searched for rather than sliced off the front, and that is not defensive
/// programming: measured on both real logs, it is never at the front. The
/// Desktop server prefixes *every* line with `ERROR: logging before
/// google.Init: `, and the IDE wraps that same text again in its own
/// `2026-09-12 03:57:46.735 [error] [LS Main stderr] `. Anchoring at byte 0
/// found a stamp in neither file, so the window would have shown "тихо" while
/// the user was staring at the error.
///
/// Returns `(month, day, second of day)`; there is no year in it, which is why
/// `age_secs` only ever places a line today or yesterday.
fn parse_stamp(line: &str) -> Option<(u16, u16, u32)> {
    let b = line.as_bytes();
    let limit = b.len().min(HEADER_SEARCH).saturating_sub(STAMP_LEN);
    (0..=limit).find_map(|i| stamp_at(line, i))
}

/// How far into a line the header is looked for. Both wrappers measured above
/// fit in well under a hundred bytes; the bound is what keeps a stamp-shaped
/// run of text deep inside a message from being read as one.
const HEADER_SEARCH: usize = 200;
/// `E0901 15:09:24` — the part that has to be there.
const STAMP_LEN: usize = 14;

/// The header if it starts exactly at `at`, and nothing otherwise. A slice that
/// lands mid-character answers `None` rather than panicking (`str::get`), which
/// is what makes scanning a line of arbitrary bytes safe.
fn stamp_at(line: &str, at: usize) -> Option<(u16, u16, u32)> {
    let b = line.as_bytes();
    if b.len() < at + STAMP_LEN {
        return None;
    }
    // glog's four levels. `is_ascii_alphabetic` would match the `E` of a word
    // followed by four digits, which is exactly the kind of thing a log message
    // contains.
    if !matches!(b[at], b'I' | b'W' | b'E' | b'F') {
        return None;
    }
    if b[at + 5] != b' ' || b[at + 8] != b':' || b[at + 11] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| line.get(r).and_then(|s| s.parse::<u32>().ok());
    let (month, day) = (num(at + 1..at + 3)?, num(at + 3..at + 5)?);
    let (h, m, s) = (
        num(at + 6..at + 8)?,
        num(at + 9..at + 11)?,
        num(at + 12..at + 14)?,
    );
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 23 || m > 59 || s > 59 {
        return None;
    }
    Some((month as u16, day as u16, h * 3600 + m * 60 + s))
}

/// How long ago a stamp was, against the local clock now.
///
/// Only today and yesterday can be placed: the header carries no year, and the
/// window this is asked about is minutes. Anything else answers `None`, which
/// reads as "not recent" - the safe direction, since the cost of missing an old
/// refusal is nothing and the cost of inventing a fresh one is a false alarm.
fn age_secs(at: (u16, u16, u32), now: crate::utils::LocalClock) -> Option<u32> {
    let (month, day, sod) = at;
    if month == now.month && day == now.day {
        return if sod <= now.second_of_day {
            Some(now.second_of_day - sod)
        } else if sod - now.second_of_day <= CLOCK_SLACK {
            Some(0)
        } else {
            None
        };
    }
    if is_day_before((month, day), now) {
        return Some(now.second_of_day + 86_400 - sod);
    }
    None
}

fn is_day_before(at: (u16, u16), now: crate::utils::LocalClock) -> bool {
    if at.0 == now.month {
        return at.1 + 1 == now.day;
    }
    // The first of a month: yesterday is the last day of the one before, whose
    // number the header does not carry a year to settle. February is therefore
    // allowed both its lengths, and the only stamp that can be misplaced is a
    // 28 February read on 1 March of a leap year - in the first minutes after
    // midnight, once every four years, and the cost is one line of the window
    // saying "a few minutes ago" about a day-old refusal.
    now.day == 1 && at.0 == month_before(now.month) && is_last_day(at.0, at.1)
}

fn is_last_day(month: u16, day: u16) -> bool {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => day == 31,
        4 | 6 | 9 | 11 => day == 30,
        2 => day == 28 || day == 29,
        _ => false,
    }
}

fn month_before(m: u16) -> u16 {
    if m <= 1 {
        12
    } else {
        m - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn ascii_case_offsets_match_scalar_windows() {
        let mut false_hits = b"aX".repeat(128);
        false_hits.extend_from_slice(b"AB");
        let cases: &[(&[u8], &[u8])] = &[
            (b"xxAbCyy aBc", b"aBc"),
            (b"--Ab", b"aB"),
            (b"aAaA", b"AA"),
            (b"__!!", b"!"),
            (b"", b"a"),
            (b"a", b"ab"),
            (&[0xee, b'A', 0xee, b'a', 0xce, b'A'], &[0xee, b'a']),
            (&[0xc0, b'A'], &[0xe0, b'a']),
            (&false_hits, b"aB"),
        ];
        for &(hay, needle) in cases {
            let expected: Vec<_> = hay.windows(needle.len()).enumerate()
                .filter_map(|(at, window)| window.eq_ignore_ascii_case(needle).then_some(at)).collect();
            let actual: Vec<_> = match_offsets_ci(hay, needle).collect();
            assert!(actual == expected, "ASCII-case offset mismatch");
            assert!(contains_ci(hay, needle) == !expected.is_empty(), "ASCII-case containment mismatch");
        }
    }

    #[test]
    #[should_panic(expected = "window size must be non-zero")]
    fn ascii_case_search_preserves_empty_needle_panic() {
        let _ = contains_ci(b"", b"");
    }

    #[cfg(windows)]
    #[test]
    fn windows_open_handle_file_identity_is_stable_and_distinct() {
        let first_path = temp_log("identity-first");
        let second_path = temp_log("identity-second");
        append(&first_path, SIGNAL_A);
        append(&second_path, SIGNAL_A);
        let first = File::open(&first_path).unwrap();
        let same = File::open(&first_path).unwrap();
        let second = File::open(&second_path).unwrap();
        let a = source_id(&first, &first.metadata().unwrap()).expect("native file identity");
        let b = source_id(&same, &same.metadata().unwrap()).expect("same native file identity");
        let c = source_id(&second, &second.metadata().unwrap()).expect("distinct native file identity");
        assert_eq!(a, b);
        assert_ne!(a, c);
        drop((first, same, second));
        let _ = fs::remove_file(first_path);
        let _ = fs::remove_file(second_path);
    }

    const SIGNAL_A: &str = "I0901 15:09:24.000000 URL: https://aicode.googleapis.com/v1 streamGenerateContent ResponseID: a\n";
    const SIGNAL_B: &str = "I0901 15:09:25.000000 URL: https://cloudcode-pa.googleapis.com/v1 streamGenerateContent ResponseID: b\n";
    const SIGNAL_DROP: &str = "I0901 15:09:23.000000 URL: https://aicode.googleapis.com/v1 streamGenerateContent attempt failed (EOF)\n";

    #[test]
    fn poll_budget_skip_preserves_complete_boundary_refusal_and_fences_cut_prefix() {
        const REFUSAL_LINE: &[u8] = b"I0901 15:09:24.000000 URL: https://aicode.googleapis.com/v1 user location is not supported\n";
        for (name, prefix, tail_prefix) in [
            ("budget-boundary", &b"noise\n"[..], &b""[..]),
            ("budget-cut", &b"abcdef"[..], &b"partial\n"[..]),
        ] {
            let path = temp_log(name);
            let mut cursor = TestLogCursor::default();
            let anchor = Instant::now();
            append(&path, SIGNAL_DROP);
            let seed = test_poll_log(&mut cursor, &path, None, anchor);
            assert_eq!(seed.direct_signals.len(), 1);
            let mut tail = Vec::new();
            tail.extend_from_slice(tail_prefix);
            tail.extend_from_slice(REFUSAL_LINE);
            tail.resize(MAX_READ as usize, b'x');
            let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(prefix).unwrap();
            file.write_all(&tail).unwrap();
            drop(file);
            let result = test_poll_log(&mut cursor, &path, None, anchor);
            assert_eq!(result.refusals, 1);
            assert_eq!(result.direct_signals.len(), 1);
            assert_eq!(result.direct_signals[0].kind, DirectSignalKind::Refusal);
            assert_eq!(result.direct_signals[0].continuity, SignalContinuity::Fence);
            assert_eq!(result.direct_signals[0].record_start,
                SIGNAL_DROP.len() as u64 + prefix.len() as u64 + tail_prefix.len() as u64);
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn poll_cursor_proves_separate_appends_and_preserves_answer_order() {
        let path = temp_log("poll-cursor");
        let mut offsets = HashMap::new();
        let mut host = None;
        let anchor = Instant::now();
        append(&path, SIGNAL_DROP);
        let (_, first) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        append(&path, SIGNAL_DROP);
        let (_, second) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert_eq!(first.direct_signals[0].continuity, SignalContinuity::Fence);
        if first.direct_signals[0].source.is_some() {
            assert_eq!(second.direct_signals[0].continuity, SignalContinuity::Proven);
        } else { assert_eq!(second.direct_signals[0].continuity, SignalContinuity::Fence); }
        assert_eq!(first.direct_signals[0].record_end, second.direct_signals[0].record_start);
        append(&path, SIGNAL_A);
        let (_, answer) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        append(&path, SIGNAL_DROP);
        let (_, drop_after) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert_eq!(answer.direct_signals[0].kind, DirectSignalKind::Answer);
        assert_eq!(drop_after.direct_signals[0].kind, DirectSignalKind::Drop);
        if answer.direct_signals[0].source.is_some() {
            assert_eq!(answer.direct_signals[0].continuity, SignalContinuity::Proven);
            assert_eq!(drop_after.direct_signals[0].continuity, SignalContinuity::Proven);
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn poll_cursor_preserves_partial_and_fences_missing_truncation_and_replay() {
        let path = temp_log("poll-gaps");
        let mut offsets = HashMap::new();
        let mut host = None;
        let anchor = Instant::now();
        append(&path, SIGNAL_DROP);
        let (_, first) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        let original = offsets.get(&path).unwrap().clone();
        let half = SIGNAL_A.len() / 2;
        append(&path, &SIGNAL_A[..half]);
        let (_, partial) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert!(partial.direct_signals.is_empty());
        append(&path, &SIGNAL_A[half..]);
        let (_, complete) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        let expected = if first.direct_signals[0].source.is_some() { SignalContinuity::Proven } else { SignalContinuity::Fence };
        assert_eq!(complete.direct_signals[0].continuity, expected);
        // A replayed cursor is not generated by poll; receiver must deduplicate
        // its actual source/span if a previously delivered batch is redelivered.
        assert_eq!(first.direct_signals[0].record_start, 0);
        assert!(original.offset > 0);
        fs::remove_file(&path).unwrap();
        let (_, missing) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert!(missing.direct_signals.is_empty());
        append(&path, SIGNAL_DROP);
        let (_, replacement) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert_eq!(replacement.direct_signals[0].continuity, SignalContinuity::Fence);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn poll_cursor_preserves_empty_and_partial_but_retains_undelivered_gap() {
        let path = temp_log("poll-pending-gap");
        let mut offsets = HashMap::new();
        let mut host = None;
        let anchor = Instant::now();
        append(&path, SIGNAL_DROP);
        let (_, first) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        let (_, empty) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert!(empty.direct_signals.is_empty());
        append(&path, "ordinary line\n");
        let (_, noise) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert!(noise.direct_signals.is_empty());
        let half = SIGNAL_DROP.len() / 2;
        append(&path, &SIGNAL_DROP[..half]);
        for _ in 0..2 {
            let (_, partial) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
            assert!(partial.direct_signals.is_empty());
        }
        append(&path, &SIGNAL_DROP[half..]);
        let (_, completed) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        let expected = if first.direct_signals[0].source.is_some() { SignalContinuity::Proven } else { SignalContinuity::Fence };
        assert_eq!(completed.direct_signals[0].continuity, expected);

        fs::remove_file(&path).unwrap();
        let _ = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        append(&path, "ordinary line\n");
        let (_, after_gap) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert!(after_gap.direct_signals.is_empty());
        append(&path, "another line\n");
        let (_, more_noise) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert!(more_noise.direct_signals.is_empty());
        append(&path, SIGNAL_DROP);
        let (_, fenced) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert_eq!(fenced.direct_signals[0].continuity, SignalContinuity::Fence);
        append(&path, SIGNAL_DROP);
        let (_, after_fence) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        if fenced.direct_signals[0].source.is_some() {
            assert_eq!(after_fence.direct_signals[0].continuity, SignalContinuity::Proven);
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn poll_cursor_fences_missing_identity_and_skipped_bytes() {
        let path = temp_log("poll-skip");
        let mut offsets = HashMap::new();
        let mut host = None;
        let anchor = Instant::now();
        append(&path, SIGNAL_DROP);
        let _ = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        // Simulate an unavailable prior OS identity; the next real scan still
        // obtains its own identity from the opened handle.
        offsets.get_mut(&path).unwrap().source = None;
        append(&path, SIGNAL_DROP);
        let (_, missing_id) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert_eq!(missing_id.direct_signals[0].continuity, SignalContinuity::Fence);
        let mut data = vec![b'x'; MAX_READ as usize + 1];
        data.push(b'\n');
        data.extend_from_slice(SIGNAL_A.as_bytes());
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&data).unwrap();
        drop(f);
        let (_, skipped) = poll_path(&path, &mut offsets, true, None, anchor, &mut host);
        assert_eq!(skipped.direct_signals.len(), 1);
        assert_eq!(skipped.direct_signals[0].continuity, SignalContinuity::Fence);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn same_poll_anchor_preserves_equal_second_tie_across_files() {
        let first = temp_log("anchor-first");
        let second = temp_log("anchor-second");
        append(&first, SIGNAL_A);
        append(&second, SIGNAL_A);
        let anchor = Instant::now();
        let now = Some(clock(9, 1, 15, 9, 30));
        let (_, a) = scan_with_anchor(&first, Some(0), now, anchor, &mut None);
        let (_, b) = scan_with_anchor(&second, Some(0), now, anchor, &mut None);
        assert!(a.direct_signals[0].at.is_some());
        assert_eq!(a.direct_signals[0].at, b.direct_signals[0].at);
        if let Some(id) = a.direct_signals[0].source.clone() {
            let mut ids = std::collections::HashSet::new();
            assert!(ids.insert(id.clone()));
            assert!(!ids.insert(id));
        }
        let _ = fs::remove_file(first);
        let _ = fs::remove_file(second);
    }

    #[test]
    fn direct_scan_keeps_distinct_records_and_order() {
        let path = temp_log("direct-order");
        append(&path, SIGNAL_DROP);
        append(&path, SIGNAL_A);
        append(&path, SIGNAL_DROP);
        append(&path, SIGNAL_B);
        append(&path, SIGNAL_A);
        let (_, tally) = scan(&path, Some(0), Some(clock(9, 1, 15, 9, 30)), &mut None);
        assert_eq!(tally.answers, 3);
        assert_eq!(tally.drops, 2);
        let signals = &tally.direct_signals;
        assert_eq!(signals.iter().map(|s| &s.kind).collect::<Vec<_>>(), vec![&DirectSignalKind::Drop, &DirectSignalKind::Answer, &DirectSignalKind::Drop, &DirectSignalKind::Answer, &DirectSignalKind::Answer]);
        assert_eq!(signals[1].host.as_deref(), Some("aicode.googleapis.com"));
        assert_eq!(signals[3].host.as_deref(), Some("cloudcode-pa.googleapis.com"));
        assert!(signals.windows(2).all(|pair| pair[0].record_end == pair[1].record_start));
        assert_eq!(signals[0].continuity, SignalContinuity::Fence);
        if signals[0].source.is_some() { assert_eq!(signals[1].continuity, SignalContinuity::Proven); }
        else { assert!(signals.iter().all(|s| s.continuity == SignalContinuity::Fence)); }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn direct_scan_fences_partial_replay_truncation_and_conflicts() {
        let path = temp_log("direct-boundaries");
        let half = SIGNAL_A.len() / 2;
        append(&path, &SIGNAL_A[..half]);
        let (offset, first) = scan(&path, Some(0), None, &mut None);
        assert!(first.direct_signals.is_empty());
        append(&path, &SIGNAL_A[half..]);
        let (end, complete) = scan(&path, Some(offset), None, &mut None);
        assert_eq!(complete.direct_signals.len(), 1);
        assert_eq!(complete.direct_signals[0].continuity, SignalContinuity::Fence);
        assert!(complete.direct_signals[0].at.is_none());
        let (_, replay) = scan(&path, Some(offset), None, &mut None);
        assert_eq!(complete.direct_signals, replay.direct_signals);
        append(&path, SIGNAL_A);
        let (longer_end, appended) = scan(&path, Some(end), None, &mut None);
        assert_eq!(appended.direct_signals.len(), 1);
        fs::write(&path, SIGNAL_DROP).unwrap();
        assert!(fs::metadata(&path).unwrap().len() < longer_end, "fixture must shrink");
        let (_, truncated) = scan(&path, Some(longer_end), None, &mut None);
        assert_eq!(truncated.direct_signals.len(), 1);
        assert_eq!(truncated.direct_signals[0].continuity, SignalContinuity::Fence);
        let conflict = b"URL: https://aicode.googleapis.com/v1 streamGenerateContent ResponseID: a attempt failed (EOF)\n";
        let tally = tally_signals(conflict, None, &mut None, 0, Instant::now(), None, true, false);
        assert_eq!(tally.direct_signals.len(), 2);
        assert!(tally.direct_signals.iter().all(|s| s.conflicting_record && s.source.is_none() && s.continuity == SignalContinuity::Fence));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn direct_scan_skips_cut_prefix_and_never_inherits_host() {
        let path = temp_log("direct-cut");
        append(&path, SIGNAL_A);
        append(&path, "user location is not supported\n");
        let (_, tally) = scan(&path, Some(1), None, &mut Some("aicode.googleapis.com".into()));
        assert_eq!(tally.direct_signals.len(), 1);
        assert_eq!(tally.direct_signals[0].kind, DirectSignalKind::Refusal);
        assert_eq!(tally.direct_signals[0].host, None);
        assert_eq!(tally.direct_signals[0].continuity, SignalContinuity::Fence);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn direct_scan_fences_rotation_and_budget_skip() {
        let path = temp_log("direct-rotation");
        append(&path, SIGNAL_A);
        let (offset, _) = scan(&path, Some(0), None, &mut None);
        fs::remove_file(&path).unwrap();
        append(&path, SIGNAL_B);
        let (_, rotated) = scan(&path, Some(offset + 1), None, &mut None);
        assert_eq!(rotated.direct_signals[0].continuity, SignalContinuity::Fence);
        let mut data = vec![b'x'; MAX_READ as usize + 1];
        data.extend_from_slice(b"\n");
        data.extend_from_slice(SIGNAL_A.as_bytes());
        fs::write(&path, data).unwrap();
        let (_, skipped) = scan(&path, Some(0), None, &mut None);
        assert_eq!(skipped.direct_signals.len(), 1);
        assert_eq!(skipped.direct_signals[0].continuity, SignalContinuity::Fence);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn direct_tally_add_retains_all_record_spans() {
        let left = tally_signals(SIGNAL_A.as_bytes(), None, &mut None, 0, Instant::now(), None, true, false);
        let right = tally_signals(SIGNAL_B.as_bytes(), None, &mut None, SIGNAL_A.len() as u64, Instant::now(), None, true, false);
        let mut combined = left;
        combined.add(right);
        assert_eq!(combined.answers, 2);
        assert_eq!(combined.direct_signals.len(), 2);
        assert_ne!(combined.direct_signals[0].host, combined.direct_signals[1].host);
        assert_eq!(combined.direct_signals[0].record_end, combined.direct_signals[1].record_start);
    }

    #[test]
    fn missing_profile_retains_non_macos_early_return() {
        assert!(candidate_logs_in(None, None, None, true).is_none());
        assert_eq!(candidate_logs_in(None, None, None, false), Some(Vec::new()));
    }

    #[test]
    fn candidate_logs_select_one_current_cli_log_per_backend() {
        use std::fs::FileTimes;
        use std::time::SystemTime;

        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("ag_cli_log_candidates_{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let profile = root.join("profile");
        fs::create_dir(&profile).unwrap();
        let gemini_root = root.join(".gemini");
        let cli_logs = gemini_root.join("antigravity-cli").join("log");
        let extension_logs = gemini_root.join("antigravity").join("log");
        let candidates = || candidate_logs_in(Some(&profile), None, Some(&gemini_root), true).unwrap();
        let missing = candidates();
        fs::create_dir_all(&cli_logs).unwrap();
        let empty = candidates();

        let write_log = |path: &Path, seconds_since_epoch| {
            let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(seconds_since_epoch);
            File::create(path)
                .unwrap()
                .set_times(FileTimes::new().set_modified(modified))
                .unwrap();
        };
        let cli_old = cli_logs.join("cli-old.log");
        let cli_current = cli_logs.join("cli-current.log");
        write_log(&cli_old, 1_600_000_000);
        write_log(&cli_current, 1_600_000_060);
        let cli_only = candidates();

        fs::create_dir_all(&extension_logs).unwrap();
        let extension_current = extension_logs.join("cli-current.log");
        write_log(&extension_current, 1_600_000_000);
        write_log(&extension_logs.join("cli-archive.log"), 1_600_000_000);
        let both = candidates();
        let macos_without_profile = candidate_logs_in(None, None, Some(&gemini_root), false);
        let windows_without_profile = candidate_logs_in(None, None, Some(&gemini_root), true);
        fs::remove_file(&cli_current).unwrap();
        fs::remove_file(&cli_old).unwrap();
        fs::remove_dir(&cli_logs).unwrap();
        let extension_only = candidates();
        fs::remove_dir_all(root).unwrap();

        assert!(missing.is_empty());
        assert!(empty.is_empty());
        assert_eq!(cli_only, [cli_current.clone()]);
        assert_eq!(extension_only, [extension_current.clone()]);
        assert_eq!(both, [cli_current, extension_current]);
        assert_eq!(macos_without_profile, Some(both));
        assert_eq!(windows_without_profile, None);
    }

    fn temp_log(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("ag_unlocker_ls_log_tests");
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(format!("{}-{}.log", name, std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    fn append(path: &Path, text: &str) {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open");
        f.write_all(text.as_bytes()).expect("write");
    }

    const REFUSAL: &str = "E0901 15:09:24.614939 1 stream_handler.go:101] FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n";
    const NOISE: &str = "I0901 15:09:24.639090 1 server.go:427] Setting GOMAXPROCS to 4\n";

    /// The two shapes the real logs are actually written in, copied off this
    /// machine. Neither starts with the glog header: the Desktop server prefixes
    /// every line, and the IDE wraps the prefixed line again.
    const DESKTOP_LINE: &str = "ERROR: logging before google.Init: E0901 15:09:24.614939       1 stream_handler.go:101] FAILED_PRECONDITION (code 400): User location is not supported for the API use.";
    const IDE_LINE: &str = "2026-09-12 03:57:46.735 [error] [LS Main stderr] ERROR: logging before google.Init: E0901 15:09:24.614939       1 stream_handler.go:101] FAILED_PRECONDITION (code 400): User location is not supported for the API use.";

    #[test]
    fn counts_the_refusal_case_insensitively_and_nothing_else() {
        assert_eq!(count_refusals(br#"{"reason": "UNSUPPORTED_LOCATION"}"#), 1);
        assert_eq!(count_refusals(br#"{"reason": "LOCATION_NOT_ELIGIBLE"}"#), 1);
        assert_eq!(count_refusals(br#"{"other": "unsupported_location"}"#), 0);
        assert_eq!(count_refusals(br#"user location is not supported {"reason":"unsupported_location"}"#), 1);
        assert_eq!(count_refusals(b"user location is not supported\n{\"reason\":\"unsupported_location\"}"), 2);
        assert!(is_region_refusal(br#"{"error":{"reason":"unsupported_\u006cocation"}}"#));
        assert_eq!(url_host(b"URL: https://AICODE.GOOGLEAPIS.COM.:443/v1"), Some("aicode.googleapis.com.".into()));
        assert!(url_host(b"URL: https://aicode.googleapis.com:8443/v1").is_none());
        assert!(url_host(b"URL: https://x.aicode.googleapis.com/v1").is_none());
        assert_eq!(count_refusals(REFUSAL.as_bytes()), 1);
        assert_eq!(count_refusals(NOISE.as_bytes()), 0);
        assert_eq!(
            count_refusals(b"USER LOCATION IS NOT SUPPORTED x user location is not supported"),
            2
        );
        assert_eq!(
            count_refusals(b"FAILED_PRECONDITION (code 400): something else"),
            0,
            "the status alone is not the region gate"
        );
        assert_eq!(count_refusals(b""), 0);
    }

    #[test]
    fn endpoint_feedback_never_inherits_a_previous_url() {
        let mut last = Some("cloudcode-pa.googleapis.com".to_owned());
        let missing = tally(b"user location is not supported\n", None, &mut last);
        assert_eq!(missing.refused_host.as_deref(), Some("cloudcode-pa.googleapis.com"));
        assert_eq!(missing.refused_endpoint, None);
        let explicit = tally(b"URL: https://aicode.googleapis.com/x user location is not supported\n", None, &mut last);
        assert_eq!(explicit.refused_endpoint, None, "an unplaceable line cannot authorize endpoint feedback");
        assert_eq!(url_host(b"URL: https://aicode.googleapis.com/x"), Some("aicode.googleapis.com".into()));
    }

    #[test]
    fn endpoint_events_never_borrow_an_older_or_conflicting_host() {
        let newer = EndpointEvent { age: Duration::from_secs(1), host: None };
        let older = EndpointEvent { age: Duration::from_secs(2), host: Some("cloudcode-pa.googleapis.com".into()) };
        for answer in [false, true] {
            let mut tally = Tally::default();
            let make = |event: Option<EndpointEvent>| if answer {
                Tally { answers: 1, answered_ago: event.as_ref().map(|event| event.age), answered_endpoint: event, ..Tally::default() }
            } else {
                Tally { refusals: 1, refused_ago: event.as_ref().map(|event| event.age), refused_endpoint: event, ..Tally::default() }
            };
            tally.add(make(Some(newer.clone())));
            tally.add(make(Some(older.clone())));
            let mut unplaceable = make(None);
            if answer { unplaceable.answered_host = Some("aicode.googleapis.com".into()); }
            else { unplaceable.refused_host = Some("aicode.googleapis.com".into()); }
            tally.add(unplaceable);
            let selected = if answer { &tally.answered_endpoint } else { &tally.refused_endpoint };
            assert_eq!(selected.as_ref(), Some(&newer));
            tally.add(make(Some(EndpointEvent { age: newer.age, host: Some("aicode.googleapis.com".into()) })));
            let selected = if answer { &tally.answered_endpoint } else { &tally.refused_endpoint };
            assert_eq!(selected.as_ref(), Some(&newer));
        }
    }

    #[test]
    fn endpoint_url_requires_https_exact_host_and_port() {
        for host in ["cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com", "aicode.googleapis.com"] {
            assert!(url_host(format!("URL: https://{host}:443/v1").as_bytes()).is_some());
            assert!(url_host(format!("URL: https://{host}:8443/v1").as_bytes()).is_none());
            assert!(url_host(format!("URL: http://{host}/v1").as_bytes()).is_none());
            assert!(url_host(format!("URL: https://x.{host}/v1").as_bytes()).is_none());
        }
        assert_eq!(url_host(b"URL: HTTPS://AICODE.GOOGLEAPIS.COM.:443/v1"), Some("aicode.googleapis.com.".into()));
    }

    fn refusals_in(path: &Path, from: Option<u64>) -> (u64, usize) {
        let (off, t) = scan(path, from, None, &mut None);
        (off, t.refusals)
    }

    #[test]
    fn history_is_not_news_but_what_is_appended_is() {
        let path = temp_log("append");
        append(&path, REFUSAL);
        append(&path, REFUSAL);
        // First sight: taken from the end, old refusals ignored.
        let (off, hits) = refusals_in(&path, None);
        assert_eq!(hits, 0);
        assert_eq!(off, fs::metadata(&path).unwrap().len());
        // Nothing appended: nothing found, offset unchanged.
        assert_eq!(refusals_in(&path, Some(off)), (off, 0));
        // Appended: found once, and only once.
        append(&path, NOISE);
        append(&path, REFUSAL);
        let (off2, hits) = refusals_in(&path, Some(off));
        assert_eq!(hits, 1);
        assert_eq!(refusals_in(&path, Some(off2)), (off2, 0));
        // A refusal split by a buffer flush: half in one pass, half in the next.
        let cut = REFUSAL.len() / 2;
        append(&path, &REFUSAL[..cut]);
        let (off3, hits) = refusals_in(&path, Some(off2));
        assert_eq!(hits, 0);
        append(&path, &REFUSAL[cut..]);
        let (off4, hits) = refusals_in(&path, Some(off3));
        assert_eq!(hits, 1, "the halves must be read together");
        assert_eq!(
            refusals_in(&path, Some(off4)),
            (off4, 0),
            "and not counted again"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_file_that_shrank_is_read_from_the_start() {
        let path = temp_log("shrink");
        for _ in 0..8 {
            append(&path, NOISE);
        }
        let (off, _) = refusals_in(&path, None);
        assert!(
            off > REFUSAL.len() as u64,
            "the rewrite below must shrink it"
        );
        // The app restarted and truncated its log; the new content is news.
        fs::write(&path, REFUSAL).expect("truncate");
        let (off2, hits) = refusals_in(&path, Some(off));
        assert_eq!(hits, 1);
        assert_eq!(off2, REFUSAL.len() as u64);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_missing_file_changes_nothing() {
        let path = temp_log("missing");
        assert_eq!(refusals_in(&path, None), (0, 0));
        assert_eq!(refusals_in(&path, Some(42)), (42, 0));
    }

    /// The two real success lines, copied off this machine (Desktop wraps glog in
    /// its own prefix; the CLI writes bare glog). The refused turn in the IDE log
    /// of 2026-09-12 had no such line at all, and the calls that are logged on a
    /// refused session too must not count.
    #[test]
    fn a_model_answer_is_the_generation_call_with_a_response_id() {
        const DESKTOP_OK: &str = "ERROR: logging before google.Init: I0918 17:07:13.969105    1230 http_helpers.go:296] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0xbf323913e34d92f8 ResponseID: kUWtatHf";
        const CLI_OK: &str = "I0918 18:56:33.939879     359 http_helpers.go:299] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0x26e77a0ae05c274c ResponseID: MV-taof4GP2TvdIPieiCmQs";
        const LOAD: &str = "I0918 17:12:08.722720    2138 http_helpers.go:296] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist Trace: 0x65704d0ab55a0ef7";
        assert!(is_answer(DESKTOP_OK.as_bytes()));
        assert!(is_answer(CLI_OK.as_bytes()));
        assert!(!is_answer(LOAD.as_bytes()));
        assert!(!is_answer(REFUSAL.as_bytes()));
        // The stamp of a success line is placed like a refusal's.
        assert!(parse_stamp(DESKTOP_OK).is_some());
        assert!(parse_stamp(CLI_OK).is_some());

        let mut host = None;
        let t = tally(
            format!("{DESKTOP_OK}\n{LOAD}\n{REFUSAL}{CLI_OK}\n").as_bytes(),
            Some(clock(9, 18, 18, 57, 0)),
            &mut host,
        );
        assert_eq!(t.answers, 2);
        assert_eq!(t.refusals, 1);
        // Newest answer: the CLI line at 18:56:33, 27 s before the clock.
        assert_eq!(t.answered_ago, Some(Duration::from_secs(27)));
        // The refusal's stamp is 1 September, not today: unplaceable.
        assert_eq!(t.refused_ago, None);
        // Hosts: the answer names its own; the refusal takes the last URL line
        // before it, the `loadCodeAssist` one.
        assert_eq!(
            t.answered_host.as_deref(),
            Some("daily-cloudcode-pa.googleapis.com")
        );
        assert_eq!(
            t.refused_host.as_deref(),
            Some("daily-cloudcode-pa.googleapis.com")
        );
        assert_eq!(host.as_deref(), Some("daily-cloudcode-pa.googleapis.com"));
        // A URL line for some other host is not a gate host and changes nothing.
        assert_eq!(
            url_host(b"I0918 x] URL: https://oauth2.googleapis.com/token"),
            None
        );
        assert_eq!(
            url_host(b"I0918 x] URL: https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist Trace"),
            Some("cloudcode-pa.googleapis.com".to_string())
        );
    }

    fn clock(month: u16, day: u16, h: u32, m: u32, s: u32) -> crate::utils::LocalClock {
        crate::utils::LocalClock {
            month,
            day,
            second_of_day: h * 3600 + m * 60 + s,
        }
    }

    /// The window's reader, end to end: tail, stamp, age, count. Written with
    /// the machine's own clock so the stamps are the shape the language server
    /// would have written a moment ago.
    #[test]
    fn a_refusal_is_found_by_its_own_stamp_and_an_old_one_is_not() {
        let Some(now) = crate::utils::local_clock() else {
            return; // no local clock (non-Windows): the reader answers None by design
        };
        // Not within the first hour after midnight: the stamps below are built
        // by subtracting from the clock, and "yesterday" is a different test.
        if now.second_of_day < 3600 {
            return;
        }
        // Written the way the real Desktop log writes it, prefix and all, so
        // this exercises the search rather than a shape only a test produces.
        let stamp = |back: u32| {
            let sod = now.second_of_day - back;
            format!(
                "ERROR: logging before google.Init: E{:02}{:02} {:02}:{:02}:{:02}.123456       1 stream_handler.go:101] ",
                now.month,
                now.day,
                sod / 3600,
                (sod / 60) % 60,
                sod % 60
            )
        };
        let path = temp_log("recent");
        append(&path, &format!("{}Setting GOMAXPROCS to 4\n", stamp(30)));
        append(&path, &format!("{}FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n", stamp(1500)));
        append(&path, &format!("{}FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n", stamp(300)));
        append(&path, &format!("{}FAILED_PRECONDITION (code 400): User location is not supported for the API use.\n", stamp(120)));

        let files = [path.clone()];
        let seen = newest_refusal(&files, Duration::from_secs(600)).expect("two are in the window");
        assert_eq!(seen.count, 2, "the 25-minute-old one is outside it");
        assert!(
            (115..=135).contains(&seen.ago.as_secs()),
            "newest was two minutes ago, got {:?}",
            seen.ago
        );
        // A window narrower than the newest refusal finds nothing at all.
        assert_eq!(newest_refusal(&files, Duration::from_secs(60)), None);
        // And a log with nothing in it says so rather than guessing.
        let quiet = temp_log("quiet");
        append(&quiet, &format!("{}Setting GOMAXPROCS to 4\n", stamp(10)));
        assert_eq!(
            newest_refusal(std::slice::from_ref(&quiet), Duration::from_secs(600)),
            None
        );
        assert!(bytes_of(&files) > 0);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&quiet);
    }

    /// The window's one-pass reader must agree with the two single-question ones
    /// it replaced, window by window.
    #[test]
    fn one_pass_history_matches_the_single_questions() {
        let Some(now) = crate::utils::local_clock() else {
            return;
        };
        if now.second_of_day < 3600 {
            return;
        }
        let stamp = |back: u32, level: char| {
            let sod = now.second_of_day - back;
            format!(
                "{}{:02}{:02} {:02}:{:02}:{:02}.123456       1 x.go:1] ",
                level,
                now.month,
                now.day,
                sod / 3600,
                (sod / 60) % 60,
                sod % 60
            )
        };
        let path = temp_log("history");
        let refusal =
            "FAILED_PRECONDITION (code 400): User location is not supported for the API use.";
        let answer = "URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0x1 ResponseID: abc";
        append(
            &path,
            &format!(
                "{}{}
",
                stamp(1800, 'E'),
                refusal
            ),
        );
        append(
            &path,
            &format!(
                "{}{}
",
                stamp(900, 'I'),
                answer
            ),
        );
        append(
            &path,
            &format!(
                "{}{}
",
                stamp(120, 'E'),
                refusal
            ),
        );
        append(
            &path,
            &format!(
                "{}{}
",
                stamp(60, 'E'),
                refusal
            ),
        );
        let files = [path.clone()];
        let h = history(&files, Duration::from_secs(600), Duration::from_secs(3600));
        assert_eq!(
            h.refused_recent,
            newest_refusal(&files, Duration::from_secs(600))
        );
        assert_eq!(h.refused, newest_refusal(&files, Duration::from_secs(3600)));
        assert_eq!(h.answered, newest_answer(&files, Duration::from_secs(3600)));
        assert_eq!(h.refused_recent.map(|s| s.count), Some(2));
        assert_eq!(h.refused.map(|s| s.count), Some(3));
        assert_eq!(h.answered.map(|s| s.count), Some(1));
        let _ = fs::remove_file(&path);
    }

    /// What the machine has right now. Reads, never asserts: the point is that
    /// the paths and the parse work against a real client log.
    ///
    ///     cargo test reads_what_the_client_actually_logged -- --ignored --nocapture
    #[test]
    #[ignore = "reads the real Antigravity logs on this machine; run with --ignored"]
    fn reads_what_the_client_actually_logged() {
        let logs = candidate_logs();
        println!("логов: {}, байт: {}", logs.len(), bytes_of(&logs));
        for path in &logs {
            println!("  {}", path.display());
        }
        println!(
            "последняя region-400 за сутки: {:?}",
            newest_refusal(&logs, Duration::from_secs(24 * 3600))
        );
    }

    /// The regression this parser was rewritten for: measured on the machine's
    /// own logs, the header is never at the start of the line. Anchored at byte
    /// 0 it matched neither real file, and the window would have reported
    /// silence while the user watched the error.
    #[test]
    fn the_header_is_found_under_both_wrappers_the_real_logs_use() {
        let expected = Some((9, 1, 15 * 3600 + 9 * 60 + 24));
        assert_eq!(parse_stamp(DESKTOP_LINE), expected);
        assert_eq!(parse_stamp(IDE_LINE), expected);
        // The IDE's own `2026-09-12 03:57:46.735` must not be mistaken for it:
        // what is read is the language server's stamp, inside the wrapper.
        assert_eq!(
            parse_stamp("2026-09-12 03:57:46.735 [info] [LS Main] Args"),
            None
        );
        // And a stamp-shaped run deep inside a message is out of reach.
        let deep = format!("{}E0102 03:04:05.000000 x", "y".repeat(HEADER_SEARCH));
        assert_eq!(parse_stamp(&deep), None);
    }

    #[test]
    fn a_glog_header_is_read_and_anything_else_refused() {
        assert_eq!(parse_stamp(REFUSAL), Some((9, 1, 15 * 3600 + 9 * 60 + 24)));
        assert_eq!(parse_stamp(NOISE), Some((9, 1, 15 * 3600 + 9 * 60 + 24)));
        // The tail cuts the first line anywhere, and half a header is not one.
        assert_eq!(parse_stamp("24.614939 1 stream_handler.go:101] blah"), None);
        assert_eq!(parse_stamp(""), None);
        assert_eq!(parse_stamp("E0901 15:09"), None);
        // Not a date and not a time.
        assert_eq!(parse_stamp("E1301 15:09:24.1 x"), None, "month 13");
        assert_eq!(parse_stamp("E0932 15:09:24.1 x"), None, "day 32");
        assert_eq!(parse_stamp("E0901 25:09:24.1 x"), None, "hour 25");
        // A Cyrillic first byte must not panic the slicing.
        assert_eq!(parse_stamp("Э0901 15:09:24.614939 x"), None);
    }

    /// The header carries no year, so only today and yesterday can be placed -
    /// and "yesterday" is what makes a refusal at 23:58 still readable at 00:02.
    #[test]
    fn a_stamp_is_placed_against_the_local_clock() {
        let now = clock(9, 1, 15, 10, 0);
        assert_eq!(age_secs((9, 1, 15 * 3600 + 9 * 60), now), Some(60));
        assert_eq!(age_secs((9, 1, 15 * 3600 + 10 * 60), now), Some(0));
        // A stamp a second ahead of our own read of the clock is now.
        assert_eq!(age_secs((9, 1, 15 * 3600 + 10 * 60 + 2), now), Some(0));
        // Further ahead than that is not a line about now.
        assert_eq!(age_secs((9, 1, 15 * 3600 + 20 * 60), now), None);
        // Another day, and not the one before: unplaceable.
        assert_eq!(age_secs((8, 20, 0), now), None);
        // Just after midnight, looking back over it.
        let midnight = clock(9, 2, 0, 2, 0);
        assert_eq!(age_secs((9, 1, 23 * 3600 + 58 * 60), midnight), Some(240));
        // And over the end of a month.
        let first = clock(9, 1, 0, 1, 0);
        assert_eq!(age_secs((8, 31, 23 * 3600 + 59 * 60), first), Some(120));
        // Not the last day of August, so not the day before 1 September.
        assert_eq!(age_secs((8, 30, 23 * 3600 + 59 * 60), first), None);
        // February is allowed both its lengths.
        assert!(is_last_day(2, 28) && is_last_day(2, 29) && !is_last_day(2, 27));
    }

    #[test]
    fn the_newest_session_folder_wins() {
        let dir = std::env::temp_dir().join(format!("ag_unlocker_sessions_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let old = dir.join("20260101T000000");
        let new = dir.join("20260901T191103");
        fs::create_dir_all(&old).unwrap();
        // A pause, so the two folders cannot share a timestamp; and the names
        // sort the same way, which is the tie-break either way.
        std::thread::sleep(std::time::Duration::from_millis(40));
        fs::create_dir_all(&new).unwrap();
        assert_eq!(newest_session(&dir), Some(new));
        let _ = fs::remove_dir_all(&dir);
    }

    const NOW: (u16, u16, u32, u32, u32) = (9, 25, 12, 0, 0);

    fn verify_in(text: &str) -> Option<Verification> {
        let (mo, d, h, mi, s) = NOW;
        newest_verification(text, clock(mo, d, h, mi, s), Duration::from_secs(3600))
    }

    /// Google's own shape: a pretty-printed body, `&` escaped as `\u0026`, in
    /// the IDE's framing with a blank line in the middle of it.
    #[test]
    fn a_verification_link_is_read_from_a_pretty_printed_body() {
        let log = concat!(
            "2026-09-25 11:58:00.100 [error] [LS Main stderr] ERROR: logging before google.Init: E0925 11:58:00.100000 1 http_helpers.go:88] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent Status: 403 Body: {\n",
            "  \"error\": {\n",
            "    \"code\": 403,\n",
            "    \"message\": \"Verify your account to continue.\",\n",
            "    \"status\": \"PERMISSION_DENIED\",\n",
            "\n",
            "    \"details\": [\n",
            "      {\n",
            "        \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\",\n",
            "        \"reason\": \"VALIDATION_REQUIRED\",\n",
            "        \"metadata\": {\n",
            "          \"validation_url_link_text\": \"Verify\",\n",
            "          \"validation_url\": \"https://accounts.google.com/signin/continue?sarp=1\\u0026continue=https%3A%2F%2Fx\\u0026plt=AKgn\"\n",
            "        }\n",
            "      }\n",
            "    ]\n",
            "  }\n",
            "}\n",
            "I0925 11:58:01.000000 1 server.go:1] after\n",
        );
        let v = verify_in(log).expect("found");
        assert_eq!(
            v.url,
            "https://accounts.google.com/signin/continue?sarp=1&continue=https%3A%2F%2Fx&plt=AKgn"
        );
        assert_eq!(v.ago, Duration::from_secs(120));
    }

    /// The body logged as one quoted string, and Go's struct printing.
    #[test]
    fn a_verification_link_is_read_escaped_once_more_and_bare() {
        let quoted = "E0925 11:59:00.000000 1 x.go:1] details: \"{\\\"error\\\":{\\\"details\\\":[{\\\"reason\\\":\\\"VALIDATION_REQUIRED\\\",\\\"metadata\\\":{\\\"validation_url\\\":\\\"https://accounts.google.com/v?a=1\\\\u0026b=2\\\"}}]}}\"\n";
        assert_eq!(
            verify_in(quoted).map(|v| v.url).as_deref(),
            Some("https://accounts.google.com/v?a=1&b=2")
        );
        let bare = "E0925 11:59:30.000000 1 x.go:1] {Reason:VALIDATION_REQUIRED Metadata:{ValidationURL:https://accounts.google.com/v?a=1&b=2 UIMessage:}}\n";
        let v = verify_in(bare).expect("found");
        assert_eq!(v.url, "https://accounts.google.com/v?a=1&b=2");
        assert_eq!(v.ago, Duration::from_secs(30));
    }

    /// The camelCase field of an ineligible tier at sign-in, newest wins.
    #[test]
    fn the_newest_verification_link_wins() {
        let log = concat!(
            "E0925 11:10:00.000000 1 x.go:1] {\"reasonCode\": \"VALIDATION_REQUIRED\", \"validationUrl\": \"https://accounts.google.com/old\"}\n",
            "E0925 11:50:00.000000 1 x.go:1] {\"reasonCode\": \"VALIDATION_REQUIRED\", \"validationUrl\": \"https://accounts.google.com/new\"}\n",
        );
        assert_eq!(
            verify_in(log).map(|v| v.url).as_deref(),
            Some("https://accounts.google.com/new")
        );
    }

    /// Only a Google page, only next to its reason, only a page that can be
    /// placed in time.
    #[test]
    fn a_link_that_is_not_a_verification_demand_is_ignored() {
        let foreign = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com.evil.example/x\"}\n";
        assert_eq!(verify_in(foreign), None);
        let userinfo = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com@evil.example/x\"}\n";
        assert_eq!(verify_in(userinfo), None);
        let plain = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"http://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(plain), None);
        let other_reason = "E0925 11:58:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED_SOON\", \"validation_url\": \"https://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(other_reason), None);
        let unstamped = "{\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(unstamped), None);
        let old = "E0925 09:00:00.000000 1 x.go:1] {\"reason\": \"VALIDATION_REQUIRED\", \"validation_url\": \"https://accounts.google.com/x\"}\n";
        assert_eq!(verify_in(old), None);
    }

    /// A 503 and a 401 are read out with the newest 503's model, and only
    /// inside the recent window.
    #[test]
    fn history_reads_overload_and_unauthorized() {
        let Some(now) = crate::utils::local_clock() else {
            return;
        };
        if now.second_of_day < 3600 {
            return;
        }
        let stamp = |back: u32| {
            let sod = now.second_of_day - back;
            format!(
                "ERROR: logging before google.Init: I{:02}{:02} {:02}:{:02}:{:02}.368290    4601 run.go:395] ",
                now.month,
                now.day,
                sod / 3600,
                (sod / 60) % 60,
                sod % 60
            )
        };
        let path = temp_log("overload");
        let busy = |m: &str| {
            format!("Run: attempt 1 failed (UNAVAILABLE (code 503): No capacity available for model {m} on the server), retrying in 4s\n")
        };
        append(&path, &format!("{}{}", stamp(1500), busy("old-model")));
        append(
            &path,
            &format!("{}{}", stamp(200), busy("gemini-3.6-flash-high")),
        );
        append(
            &path,
            &format!("{}{}", stamp(100), busy("gemini-3.8-flash-high")),
        );
        append(
            &path,
            &format!(
                "{}UNAUTHENTICATED (code 401): Request had invalid authentication credentials.\n",
                stamp(50)
            ),
        );
        append(
            &path,
            &format!(
                "{}UNAUTHENTICATED (code 401): Request had invalid authentication credentials.\n",
                stamp(40)
            ),
        );

        let h = history(
            std::slice::from_ref(&path),
            Duration::from_secs(600),
            Duration::from_secs(3600),
        );
        let o = h.overloaded.expect("two 503s inside the window");
        assert_eq!(o.count, 2, "the 25-minute-old one is outside it");
        assert_eq!(o.model, "gemini-3.8-flash-high");
        assert!((95..=115).contains(&o.ago.as_secs()), "{:?}", o.ago);
        let u = h.unauthorized.expect("two 401s");
        assert_eq!(u.count, 2);
        assert!(h.refused.is_none() && h.answered.is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_dead_connection_under_a_generation_attempt_is_a_drop() {
        let a = b"Run: attempt 3 failed (request failed: Post \"https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse\": EOF), retrying in 11s";
        let b = b"Run: attempt 1 failed (stream reading error: unexpected EOF), retrying in 4s";
        assert!(is_stream_drop(a) && is_stream_drop(b));
        // The final report repeats it without the attempt; the cache refreshers
        // log EOF too and are not a generation.
        assert!(!is_stream_drop(b"E1010 errorreport.go:224] generating and executing: request failed: Post \".../streamGenerateContent?alt=sse\": EOF"));
        assert!(!is_stream_drop(b"W1010 cache.go:163] Failed to refresh cache in background: Post \".../fetchAvailableModels\": EOF"));
        assert!(!is_stream_drop(b"Run: attempt 1 failed (INTERNAL (code 500): Internal error encountered.), retrying in 4s"));
    }

    /// Field log 2026-10-15: one EOF, then five retries each failing on the
    /// client's own dead socket to our proxy - the streak must keep growing.
    #[test]
    fn a_closed_connection_retry_is_a_drop_too() {
        let a = b"Run: attempt 2 failed (request failed: Post \"https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse\": write tcp 127.0.0.1:1834->127.0.0.1:53129: use of closed network connection), retrying in 6.9s";
        assert!(is_stream_drop(a));
        assert!(!is_stream_drop(b"Run: attempt 2 failed (request failed: Post \".../fetchAvailableModels\": write tcp 127.0.0.1:1->127.0.0.1:2: use of closed network connection), retrying in 4s"));
    }

    #[test]
    fn overload_names_and_server_errors() {
        assert!(is_overload(
            b"Run: attempt 2 failed (RESOURCE_EXHAUSTED (code 429): quota)"
        ));
        assert!(is_overload(
            b"Error Our servers are experiencing high traffic right now"
        ));
        assert!(!is_overload(
            b"Run: attempt 1 failed (INTERNAL (code 500): Internal error encountered.)"
        ));
        assert!(contains_ci(
            b"attempt 1 failed (INTERNAL (code 500): x",
            SERVER_500.as_bytes()
        ));
    }

    #[test]
    fn overload_model_is_read_up_to_the_name_end() {
        assert_eq!(
            overload_model(b"(UNAVAILABLE (code 503): No capacity available for model gemini-3.8-flash-low on the server"),
            "gemini-3.8-flash-low"
        );
        assert_eq!(
            overload_model(b"UNAVAILABLE (code 503): The service is currently unavailable."),
            ""
        );
    }
}
