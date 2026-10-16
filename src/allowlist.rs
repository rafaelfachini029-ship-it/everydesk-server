use hbb_common::log;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// ID of the synthetic peer hbbs registers with itself every second as a
/// liveness self-check (`test_hbbs`); hbbs exits if it gets no answer. It is
/// not exempt here: the server gate exempts it only when sent from loopback.
pub const TEST_HBBS_ID: &str = "(:test_hbbs:)";

/// IDs allowed to use this server, read from a file with one ID per line
/// (`#` starts a comment, surrounding whitespace is ignored). The file is
/// re-read whenever its mtime changes; if it cannot be read, everyone is denied.
pub struct Allowlist {
    path: PathBuf,
    cache: Mutex<(Option<SystemTime>, HashSet<String>)>,
}

impl Allowlist {
    pub fn new(path: &Path) -> Allowlist {
        Allowlist {
            path: path.to_owned(),
            cache: Mutex::new((None, HashSet::new())),
        }
    }

    /// `None` when `ALLOWLIST_FILE` is unset or empty: the feature is off.
    pub fn from_env() -> Option<Allowlist> {
        let path = std::env::var("ALLOWLIST_FILE").ok()?;
        if path.is_empty() {
            return None;
        }
        Some(Allowlist::new(Path::new(&path)))
    }

    pub fn is_allowed(&self, id: &str) -> bool {
        let mut cache = self.cache.lock().unwrap();
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        if mtime.is_none() || mtime != cache.0 {
            *cache = match (mtime, std::fs::read_to_string(&self.path)) {
                (Some(mtime), Ok(content)) => {
                    let ids = parse(&content);
                    log::info!("allowlist: loaded {} ids from {:?}", ids.len(), self.path);
                    (Some(mtime), ids)
                }
                _ => (None, HashSet::new()),
            };
        }
        cache.1.contains(id)
    }
}

fn parse(content: &str) -> HashSet<String> {
    content
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect()
}

const PENDING_CAP: usize = 500;

/// Pure update of the pending list: `None` when `id` is already present
/// (dedupe), otherwise the new content with `"<id> <ts> <ip>\n"` appended and
/// the oldest lines dropped beyond `cap`. Older `"<id> <ts>"` lines are kept
/// as they are (the panel reads both forms).
fn update_pending(content: &str, id: &str, ts: u64, ip: IpAddr, cap: usize) -> Option<String> {
    let mut lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines
        .iter()
        .any(|l| l.split_whitespace().next() == Some(id))
    {
        return None;
    }
    let new_line = format!("{} {} {}", id, ts, ip);
    lines.push(&new_line);
    let start = lines.len().saturating_sub(cap);
    let mut out = lines[start..].join("\n");
    out.push('\n');
    Some(out)
}

/// Panel-compatible id: `^[a-z0-9][a-z0-9_-]{5,15}$|^[0-9]{6,16}$`, after
/// lowercasing. Anything else is dropped, never rewritten into another id.
fn pending_id(id: &str) -> Option<String> {
    let id = id.to_ascii_lowercase();
    let b = id.as_bytes();
    let ok = (6..=16).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-');
    if ok {
        Some(id)
    } else {
        None
    }
}

const PENDING_WINDOW_SECS: u64 = 600;
const PENDING_PER_IP: usize = 5;
const PENDING_GLOBAL: usize = 60;

/// Rate limiter for new pending ids: at most `PENDING_PER_IP` per source IP
/// and `PENDING_GLOBAL` overall per window. Ids already accepted in the
/// window are not accepted again (they are already queued/written).
#[derive(Default)]
struct PendingLimiter {
    per_ip: HashMap<IpAddr, Vec<u64>>,
    global: Vec<u64>,
    seen: HashMap<String, u64>,
}

impl PendingLimiter {
    fn allow(&mut self, id: &str, ip: IpAddr, now: u64) -> bool {
        let fresh = |t: &u64| now.saturating_sub(*t) < PENDING_WINDOW_SECS;
        self.global.retain(fresh);
        self.seen.retain(|_, t| fresh(t));
        self.per_ip.retain(|_, v| {
            v.retain(fresh);
            !v.is_empty()
        });
        if self.seen.contains_key(id) || self.global.len() >= PENDING_GLOBAL {
            return false;
        }
        let v = self.per_ip.entry(ip).or_default();
        if v.len() >= PENDING_PER_IP {
            return false;
        }
        v.push(now);
        self.global.push(now);
        self.seen.insert(id.to_owned(), now);
        true
    }
}

lazy_static::lazy_static! {
    static ref PENDING_LIMITER: Mutex<PendingLimiter> = Mutex::new(PendingLimiter::default());
    static ref PENDING_IO: Mutex<()> = Mutex::new(());
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes `content` to `path` via temp file + rename, keeping the original
/// file's mode and owner (when we are allowed to set it).
fn write_preserving(path: &Path, content: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp-hbbs");
    std::fs::write(&tmp, content)?;
    #[cfg(unix)]
    if let Ok(m) = std::fs::metadata(path) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(m.mode() & 0o7777));
        let _ = std::os::unix::fs::chown(&tmp, Some(m.uid()), Some(m.gid()));
    }
    std::fs::rename(&tmp, path)
}

fn write_pending(path: &str, id: &str, ts: u64, ip: IpAddr) {
    let _io = PENDING_IO.lock().unwrap();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            log::warn!("pending: cannot read {}: {}", path, e);
            return;
        }
    };
    if let Some(new) = update_pending(&content, id, ts, ip, PENDING_CAP) {
        if let Err(e) = write_preserving(Path::new(path), &new) {
            log::warn!("pending: cannot write {}: {}", path, e);
        }
    }
}

/// EveryDesk: remember an id denied by the allow-list in the file named by
/// `PENDING_FILE` so the admin panel can offer it for approval. Never blocks
/// the caller: validation and rate limiting are in memory, file I/O runs on
/// the blocking pool. Best effort: errors are logged and ignored.
pub fn record_pending(id: &str, ip: IpAddr) {
    let path = match std::env::var("PENDING_FILE") {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    let Some(id) = pending_id(id) else {
        log::debug!("pending: dropped invalid id");
        return;
    };
    let ts = unix_now();
    if !PENDING_LIMITER.lock().unwrap().allow(&id, ip, ts) {
        log::debug!("pending: rate limited {}", id);
        return;
    }
    // the source address hbbs saw (IPv4-mapped IPv6 shown as plain IPv4)
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    hbb_common::tokio::task::spawn_blocking(move || write_pending(&path, &id, ts, ip));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    struct TmpFile(PathBuf);

    impl TmpFile {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).ok();
        }
    }

    fn write_tmp(content: &str) -> TmpFile {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "allowlist-test-{}-{}.txt",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&path, content).unwrap();
        TmpFile(path)
    }

    fn touch_mtime_forward(path: &Path) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() + Duration::from_secs(10))
            .unwrap();
    }

    #[test]
    fn allows_listed_id_and_ignores_comments_and_spaces() {
        let f = write_tmp("# amigos\n 123456789 \n987654321\n");
        let a = Allowlist::new(f.path());
        assert!(a.is_allowed("123456789"));
        assert!(a.is_allowed("987654321"));
        assert!(!a.is_allowed("111"));
    }

    #[test]
    fn reloads_when_file_changes() {
        let f = write_tmp("1\n");
        let a = Allowlist::new(f.path());
        assert!(!a.is_allowed("2"));
        std::fs::write(f.path(), "1\n2\n").unwrap();
        touch_mtime_forward(f.path());
        assert!(a.is_allowed("2"));
    }

    #[test]
    fn internal_test_peer_not_exempt_in_allowlist() {
        let f = write_tmp("");
        let a = Allowlist::new(f.path());
        assert!(!a.is_allowed(TEST_HBBS_ID));
        assert!(!a.is_allowed("123456789"));
    }

    #[test]
    fn missing_file_denies_everyone() {
        let a = Allowlist::new(std::path::Path::new("/nonexistent/x.txt"));
        assert!(!a.is_allowed("1"));
    }

    #[test]
    fn pending_dedupes_and_caps() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let a = update_pending("", "abc123", 1, ip, 3).unwrap();
        assert_eq!(a, "abc123 1 1.2.3.4\n");
        assert!(update_pending(&a, "abc123", 2, ip, 3).is_none());
        let b = update_pending(&a, "def456", 2, ip, 3).unwrap();
        let c = update_pending(&b, "ghi789", 3, ip, 3).unwrap();
        let d = update_pending(&c, "jkl012", 4, "::1".parse().unwrap(), 3).unwrap();
        assert_eq!(d, "def456 2 1.2.3.4\nghi789 3 1.2.3.4\njkl012 4 ::1\n");
    }

    #[test]
    fn pending_keeps_old_two_field_lines() {
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        let old = "abc123 1\n";
        // an id already present in the old format is still deduped
        assert!(update_pending(old, "abc123", 2, ip, 10).is_none());
        assert_eq!(
            update_pending(old, "def456", 2, ip, 10).unwrap(),
            "abc123 1\ndef456 2 5.6.7.8\n"
        );
    }

    #[test]
    fn pending_rate_limited_per_ip() {
        let mut l = PendingLimiter::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for i in 0..5 {
            assert!(l.allow(&format!("id{}0000", i), ip, 100));
        }
        assert!(!l.allow("idx00000", ip, 101));
        // another IP is fine, and the window expires
        assert!(l.allow("idx00000", "5.6.7.8".parse().unwrap(), 101));
        assert!(l.allow("idy00000", ip, 100 + PENDING_WINDOW_SECS));
        // same id is not accepted twice in the window
        assert!(!l.allow("idy00000", "9.9.9.9".parse().unwrap(), 100 + PENDING_WINDOW_SECS + 1));
        // global cap
        let mut g = PendingLimiter::default();
        for i in 0..PENDING_GLOBAL {
            let ip: IpAddr = format!("10.0.{}.{}", i / 200, i % 200).parse().unwrap();
            assert!(g.allow(&format!("g{:06}", i), ip, 5));
        }
        assert!(!g.allow("late0000", "11.0.0.1".parse().unwrap(), 6));
    }

    #[test]
    fn pending_drops_invalid_ids() {
        assert_eq!(pending_id("ABC123").as_deref(), Some("abc123"));
        assert_eq!(pending_id("123456789").as_deref(), Some("123456789"));
        for bad in ["", "abc", "a b c d e f", "ab\ncdef", "-abcdef", "abc.def", "x".repeat(17).as_str(), "(:test_hbbs:)"] {
            assert!(pending_id(bad).is_none(), "{:?}", bad);
        }
    }
}
