use hbb_common::log;
use std::collections::HashSet;
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
/// (dedupe), otherwise the new content with `"<id> <ts>\n"` appended and the
/// oldest lines dropped beyond `cap`.
fn update_pending(content: &str, id: &str, ts: u64, cap: usize) -> Option<String> {
    let mut lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines
        .iter()
        .any(|l| l.split_whitespace().next() == Some(id))
    {
        return None;
    }
    let new_line = format!("{} {}", id, ts);
    lines.push(&new_line);
    let start = lines.len().saturating_sub(cap);
    let mut out = lines[start..].join("\n");
    out.push('\n');
    Some(out)
}

/// EveryDesk: remember an id denied by the allow-list in the file named by
/// `PENDING_FILE` so the admin panel can offer it for approval. Best effort:
/// I/O errors are logged and ignored.
pub fn record_pending(id: &str) {
    let path = match std::env::var("PENDING_FILE") {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    let id = crate::requester_auth::sanitize_id(id);
    if id.is_empty() {
        return;
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            log::warn!("pending: cannot read {}: {}", path, e);
            return;
        }
    };
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(new) = update_pending(&content, &id, ts, PENDING_CAP) {
        if let Err(e) = std::fs::write(&path, new) {
            log::warn!("pending: cannot write {}: {}", path, e);
        }
    }
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
        let a = update_pending("", "abc123", 1, 3).unwrap();
        assert_eq!(a, "abc123 1\n");
        assert!(update_pending(&a, "abc123", 2, 3).is_none());
        let b = update_pending(&a, "def456", 2, 3).unwrap();
        let c = update_pending(&b, "ghi789", 3, 3).unwrap();
        let d = update_pending(&c, "jkl012", 4, 3).unwrap();
        assert_eq!(d, "def456 2\nghi789 3\njkl012 4\n");
    }
}
