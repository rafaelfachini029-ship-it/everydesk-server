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
use std::net::SocketAddr;
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

/// True when the key part of `licence_key` is the server's key (or the server has none).
pub fn server_key_matches(key: &str, licence_key: &str) -> bool {
    key.is_empty() || server_key_part(licence_key) == key
}

/// The single gate for putting a requester's sink into hbbs' `tcp_punch`: only a
/// request with the right server key whose envelope authenticated. Anything that
/// reaches `tcp_punch` can receive a tagged relay uuid, so nothing else may.
pub fn sink_insert_allowed(key: &str, licence_key: &str, authenticated: bool) -> bool {
    server_key_matches(key, licence_key) && authenticated
}

/// Attacker-controlled ids for the log: `[A-Za-z0-9_-]` only, at most 32 chars.
pub fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(32)
        .collect()
}

/// Requester sockets that authenticated in the last `AUTHED_TTL_SECS`. A relay
/// uuid from a `RelayResponse` is tagged only when it is addressed to one of them.
pub const AUTHED_TTL_SECS: i64 = 60;

#[derive(Default)]
pub struct AuthedRequesters {
    map: Mutex<HashMap<SocketAddr, i64>>,
}

impl AuthedRequesters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn authorize(&self, addr: SocketAddr, now: i64) {
        let mut map = self.map.lock().unwrap();
        map.retain(|_, expiry| *expiry > now);
        map.insert(addr, now + AUTHED_TTL_SECS);
    }

    pub fn is_authorized(&self, addr: SocketAddr, now: i64) -> bool {
        matches!(self.map.lock().unwrap().get(&addr), Some(expiry) if *expiry > now)
    }
}

/// The uuid hbbs forwards in a `RelayResponse` to `addr_b`: tagged only when a
/// relay key is set and `addr_b` is an authenticated requester; otherwise unchanged
/// (an untagged or forged-tag uuid pairs with nothing in hbbr when the secret is set).
pub fn relay_response_uuid(
    key: Option<&RelayKey>,
    authed: &AuthedRequesters,
    addr_b: SocketAddr,
    uuid: &str,
    now: i64,
) -> String {
    match key {
        Some(k) if !uuid.is_empty() && authed.is_authorized(addr_b, now) => k.sign_uuid(uuid),
        _ => uuid.to_owned(),
    }
}

/// Timestamp window and signature; `Err` carries the reason for the log.
pub fn check(env: &Envelope, target_id: &str, pk: &[u8], now: i64) -> Result<(), &'static str> {
    if now.abs_diff(env.ts) > MAX_SKEW_SECS as u64 {
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
    fn extreme_timestamp_does_not_panic() {
        let (pk, sk) = sign::gen_keypair();
        for ts in [i64::MIN, i64::MAX, i64::MIN + 1] {
            let env = parse_envelope(&envelope(&sk, "111", "222", ts)).unwrap();
            assert!(!verify(&env, "222", pk.as_ref(), NOW));
            // far ends of the range must not overflow either
            let _ = verify(&env, "222", pk.as_ref(), i64::MIN);
            let _ = verify(&env, "222", pk.as_ref(), i64::MAX);
        }
    }

    #[test]
    fn key_mismatch_does_not_insert_sink() {
        let (_, sk) = sign::gen_keypair();
        let env = envelope(&sk, "111", "222", NOW);
        // wrong server key: never inserted, even if authentication were to succeed
        assert!(!sink_insert_allowed("OTHERKEY", &env, true));
        assert!(!sink_insert_allowed("OTHERKEY", "OTHERKEYX", true));
        // right key but not authenticated
        assert!(!sink_insert_allowed("SRVKEY", &env, false));
        // stock client with the right plain key: still needs authentication
        assert!(!sink_insert_allowed("SRVKEY", "SRVKEY", false));
        assert!(sink_insert_allowed("SRVKEY", &env, true));
        assert!(sink_insert_allowed("", &env, true));
    }

    #[test]
    fn relay_response_cannot_tag_unissued_uuid() {
        let key = RelayKey::from_secret("s3cret");
        let authed = AuthedRequesters::new();
        let a: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let b: SocketAddr = "5.6.7.8:6000".parse().unwrap();
        let uuid = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
        // nobody authenticated: passes through untagged
        let out = relay_response_uuid(Some(&key), &authed, a, uuid, NOW);
        assert_eq!(out, uuid);
        assert!(!key.verify_uuid(&out));
        authed.authorize(a, NOW);
        // to the authenticated requester: tagged
        let out = relay_response_uuid(Some(&key), &authed, a, uuid, NOW + 1);
        assert!(key.verify_uuid(&out));
        // to another socket: untagged
        assert_eq!(relay_response_uuid(Some(&key), &authed, b, uuid, NOW + 1), uuid);
        // after the window: untagged
        assert_eq!(
            relay_response_uuid(Some(&key), &authed, a, uuid, NOW + AUTHED_TTL_SECS),
            uuid
        );
        // no secret: upstream behaviour
        authed.authorize(a, NOW);
        assert_eq!(relay_response_uuid(None, &authed, a, uuid, NOW), uuid);
    }

    #[test]
    fn sanitize_id_limits_log_input() {
        assert_eq!(sanitize_id("abc-DEF_123"), "abc-DEF_123");
        assert_eq!(sanitize_id("a\nb;c\x1b[31m"), "abc31m");
        assert_eq!(sanitize_id(&"x".repeat(100)).len(), 32);
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
