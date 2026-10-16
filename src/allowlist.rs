use hbb_common::log;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// ID of the synthetic peer hbbs registers with itself every second as a
/// liveness self-check (`test_hbbs`); hbbs exits if it gets no answer, so the
/// allow-list must never deny it.
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
        if id == TEST_HBBS_ID {
            return true;
        }
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
    fn internal_test_peer_is_never_denied() {
        let f = write_tmp("");
        let a = Allowlist::new(f.path());
        assert!(a.is_allowed(TEST_HBBS_ID));
        assert!(!a.is_allowed("123456789"));
    }

    #[test]
    fn missing_file_denies_everyone() {
        let a = Allowlist::new(std::path::Path::new("/nonexistent/x.txt"));
        assert!(!a.is_allowed("1"));
    }
}
