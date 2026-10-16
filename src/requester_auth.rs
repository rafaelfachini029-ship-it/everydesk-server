//! EveryDesk requester authentication (see docs/protocolo-everydesk.md).
//!
//! The requester of a punch/relay puts a signed envelope in `licence_key`:
//! `<server_key>;v1;<my_id>;<unix_ts>;<base64 sig>`, where `sig` is the
//! ed25519 detached signature of `ed-punch-v1|<my_id>|<target_id>|<ts>` made
//! with the requester's own key pair (the pk it registered with hbbs).
//!
//! The relay uuid hbbs hands out is `<random>.<hmac>`, with
//! `hmac = HMAC-SHA256(SHA256(RELAY_SECRET), random)` (url-safe base64, no
//! padding), so hbbr only pairs sockets for sessions hbbs authorized.

use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256, sign};
use std::collections::HashMap;
use std::sync::Mutex;

pub const VERSION_TAG: &str = "v1";
pub const SIGN_CONTEXT: &str = "ed-punch-v1";
/// Maximum |now - ts|, in seconds.
pub const MAX_SKEW_SECS: i64 = 30;
/// How long a (my_id, ts) pair is remembered, in seconds.
pub const REPLAY_TTL_SECS: i64 = 60;

pub struct Envelope {
    pub server_key: String,
    pub my_id: String,
    pub ts: i64,
    pub sig: Vec<u8>,
}

/// The message the requester signs.
pub fn signed_message(my_id: &str, target_id: &str, ts: i64) -> String {
    format!("{SIGN_CONTEXT}|{my_id}|{target_id}|{ts}")
}

/// Splits `licence_key` into its five parts; `None` when it is not a v1 envelope.
pub fn parse_envelope(s: &str) -> Option<Envelope> {
    let parts: Vec<&str> = s.split(';').collect();
    if parts.len() != 5 || parts[1] != VERSION_TAG || parts[2].is_empty() {
        return None;
    }
    let ts = parts[3].parse::<i64>().ok()?;
    let sig = base64::decode(parts[4]).ok()?;
    if sig.len() != sign::SIGNATUREBYTES {
        return None;
    }
    Some(Envelope {
        server_key: parts[0].to_owned(),
        my_id: parts[2].to_owned(),
        ts,
        sig,
    })
}

/// The server-key part of `licence_key`: the whole string when it is not an
/// envelope (so a stock client's plain key is compared as before).
pub fn server_key_part(licence_key: &str) -> &str {
    if licence_key.contains(';') {
        licence_key.split(';').next().unwrap_or_default()
    } else {
        licence_key
    }
}

/// Timestamp window and signature; `Err` carries the reason for the log.
pub fn check(env: &Envelope, target_id: &str, pk: &[u8], now: i64) -> Result<(), &'static str> {
    if (now - env.ts).abs() > MAX_SKEW_SECS {
        return Err("timestamp out of window");
    }
    let pk = sign::PublicKey::from_slice(pk).ok_or("requester has no valid pk")?;
    let sig = sign::Signature::from_bytes(&env.sig).map_err(|_| "bad signature")?;
    let msg = signed_message(&env.my_id, target_id, env.ts);
    if sign::verify_detached(&sig, msg.as_bytes(), &pk) {
        Ok(())
    } else {
        Err("bad signature")
    }
}

pub fn verify(env: &Envelope, target_id: &str, pk: &[u8], now: i64) -> bool {
    check(env, target_id, pk, now).is_ok()
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Remembers accepted (my_id, ts) pairs for `REPLAY_TTL_SECS`. Only envelopes
/// that already passed `check` are inserted, so its size is bounded by what
/// authorized requesters send.
#[derive(Default)]
pub struct ReplayGuard {
    seen: Mutex<HashMap<(String, i64), i64>>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// True (and remembered) when the pair was not seen in the last 60 s.
    pub fn check_and_insert(&self, my_id: &str, ts: i64, now: i64) -> bool {
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, expiry| *expiry > now);
        let key = (my_id.to_owned(), ts);
        if seen.contains_key(&key) {
            return false;
        }
        seen.insert(key, now + REPLAY_TTL_SECS);
        true
    }
}

/// The part of a relay uuid before the first `.` (the whole uuid when it has none,
/// which is every uuid a stock deploy produces).
pub fn relay_uuid_base(uuid: &str) -> &str {
    uuid.split('.').next().unwrap_or_default()
}

pub struct RelayKey(hmacsha256::Key);

impl RelayKey {
    pub fn from_secret(secret: &str) -> Self {
        let digest = sha256::hash(secret.as_bytes());
        RelayKey(hmacsha256::Key(digest.0))
    }

    /// `None` when `RELAY_SECRET` is unset or empty (upstream behaviour).
    pub fn from_env() -> Option<Self> {
        match std::env::var("RELAY_SECRET") {
            Ok(s) if !s.is_empty() => Some(Self::from_secret(&s)),
            _ => None,
        }
    }

    /// `<base>.<hmac>`; any previous tag on `base` is dropped first.
    pub fn sign_uuid(&self, base: &str) -> String {
        let base = relay_uuid_base(base);
        let tag = hmacsha256::authenticate(base.as_bytes(), &self.0);
        format!("{base}.{}", base64::encode_config(tag.0, base64::URL_SAFE_NO_PAD))
    }

    pub fn verify_uuid(&self, uuid: &str) -> bool {
        let mut parts = uuid.splitn(2, '.');
        let (Some(base), Some(tag)) = (parts.next(), parts.next()) else {
            return false;
        };
        let Ok(tag) = base64::decode_config(tag, base64::URL_SAFE_NO_PAD) else {
            return false;
        };
        let Some(tag) = hmacsha256::Tag::from_slice(&tag) else {
            return false;
        };
        hmacsha256::verify(&tag, base.as_bytes(), &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign;

    const NOW: i64 = 1_800_000_000;

    fn envelope(sk: &sign::SecretKey, my_id: &str, target: &str, ts: i64) -> String {
        let msg = format!("ed-punch-v1|{my_id}|{target}|{ts}");
        let sig = sign::sign_detached(msg.as_bytes(), sk);
        format!("SRVKEY;v1;{my_id};{ts};{}", base64::encode(sig.as_ref()))
    }

    #[test]
    fn valid_envelope_passes() {
        let (pk, sk) = sign::gen_keypair();
        let env = parse_envelope(&envelope(&sk, "111", "222", NOW)).expect("parses");
        assert_eq!(env.server_key, "SRVKEY");
        assert_eq!(env.my_id, "111");
        assert_eq!(env.ts, NOW);
        assert!(verify(&env, "222", pk.as_ref(), NOW + 5));
    }

    #[test]
    fn expired_timestamp_fails() {
        let (pk, sk) = sign::gen_keypair();
        let env = parse_envelope(&envelope(&sk, "111", "222", NOW - 31)).unwrap();
        assert!(!verify(&env, "222", pk.as_ref(), NOW));
        let env = parse_envelope(&envelope(&sk, "111", "222", NOW + 31)).unwrap();
        assert!(!verify(&env, "222", pk.as_ref(), NOW));
        let env = parse_envelope(&envelope(&sk, "111", "222", NOW - 30)).unwrap();
        assert!(verify(&env, "222", pk.as_ref(), NOW));
    }

    #[test]
    fn wrong_signature_fails() {
        let (pk, sk) = sign::gen_keypair();
        let (other_pk, _) = sign::gen_keypair();
        let env = parse_envelope(&envelope(&sk, "111", "222", NOW)).unwrap();
        // signed for another target
        assert!(!verify(&env, "333", pk.as_ref(), NOW));
        // checked against another key
        assert!(!verify(&env, "222", other_pk.as_ref(), NOW));
        // claims another requester id
        let forged = envelope(&sk, "111", "222", NOW).replacen(";111;", ";999;", 1);
        let env = parse_envelope(&forged).unwrap();
        assert!(!verify(&env, "222", pk.as_ref(), NOW));
        // garbage pk
        let env = parse_envelope(&envelope(&sk, "111", "222", NOW)).unwrap();
        assert!(!verify(&env, "222", b"short", NOW));
    }

    #[test]
    fn malformed_envelopes_rejected() {
        assert!(parse_envelope("SRVKEY").is_none());
        assert!(parse_envelope("").is_none());
        assert!(parse_envelope("K;v2;111;1;AAAA").is_none());
        assert!(parse_envelope("K;v1;111;notanumber;AAAA").is_none());
        assert!(parse_envelope("K;v1;;1;AAAA").is_none());
        assert!(parse_envelope("K;v1;111;1;!!!").is_none());
        assert!(parse_envelope("K;v1;111;1;AAAA;extra").is_none());
    }

    #[test]
    fn replay_within_60s_fails() {
        let guard = ReplayGuard::new();
        assert!(guard.check_and_insert("111", NOW, NOW));
        assert!(!guard.check_and_insert("111", NOW, NOW + 1));
        assert!(!guard.check_and_insert("111", NOW, NOW + 59));
        // other requester / other ts are independent
        assert!(guard.check_and_insert("222", NOW, NOW + 1));
        assert!(guard.check_and_insert("111", NOW + 1, NOW + 1));
        // after the window the entry has expired (the 30 s skew check rejects it anyway)
        assert!(guard.check_and_insert("111", NOW, NOW + 61));
    }

    #[test]
    fn relay_uuid_hmac_roundtrip() {
        let key = RelayKey::from_secret("s3cret");
        let uuid = key.sign_uuid("7c9e6679-7425-40de-944b-e07fc1f90ae7");
        assert!(uuid.starts_with("7c9e6679-7425-40de-944b-e07fc1f90ae7."));
        assert!(key.verify_uuid(&uuid));
        assert_eq!(relay_uuid_base(&uuid), "7c9e6679-7425-40de-944b-e07fc1f90ae7");
    }

    #[test]
    fn tampered_uuid_fails() {
        let key = RelayKey::from_secret("s3cret");
        let uuid = key.sign_uuid("7c9e6679-7425-40de-944b-e07fc1f90ae7");
        let tampered = uuid.replacen("7c9e", "7c9f", 1);
        assert!(!key.verify_uuid(&tampered));
        assert!(!key.verify_uuid("7c9e6679-7425-40de-944b-e07fc1f90ae7"));
        assert!(!key.verify_uuid("7c9e6679-7425-40de-944b-e07fc1f90ae7.AAAA"));
        assert!(!RelayKey::from_secret("other").verify_uuid(&uuid));
    }
}
