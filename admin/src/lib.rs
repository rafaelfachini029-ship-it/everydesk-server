//! EveryDesk admin panel: approve / block / remove machine ids.
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const COOKIE: &str = "ed_session";
const MAX_FAILS: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(600);
const SESSION_TTL: Duration = Duration::from_secs(86400);
const MAX_SESSIONS: usize = 100;

pub struct AppState {
    password: String,
    allow: PathBuf,
    pending: PathBuf,
    blocked: PathBuf,
    /// session token -> csrf token
    sessions: Mutex<HashMap<String, (String, Instant)>>,
    /// client key -> (failures, locked until, last failure)
    fails: Mutex<HashMap<String, (u32, Option<Instant>, Instant)>>,
    /// serializes read-modify-write on the files
    io: Mutex<()>,
}

impl AppState {
    pub fn new(password: String, allow: PathBuf, pending: PathBuf) -> AppState {
        let blocked = allow.with_file_name("blocked.txt");
        AppState {
            password,
            allow,
            pending,
            blocked,
            sessions: Mutex::new(HashMap::new()),
            fails: Mutex::new(HashMap::new()),
            io: Mutex::new(()),
        }
    }
}

type St = Arc<AppState>;

pub fn router(state: St) -> Router {
    Router::new()
        .route("/login", get(login_page).post(login))
        .route("/", get(index))
        .route("/approve", post(approve_manual))
        .route("/approve/:id", post(approve))
        .route("/block/:id", post(block))
        .route("/remove/:id", post(remove))
        .route("/logout", post(logout))
        .with_state(state)
}

// ---------- helpers ----------

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    let numeric = (6..=16).contains(&b.len()) && b.iter().all(|c| c.is_ascii_digit());
    let named = (6..=16).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-');
    numeric || named
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().max(b.len());
    let mut diff = (a.len() ^ b.len()) as u32;
    for i in 0..n {
        diff |= (a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0)) as u32;
    }
    diff == 0
}

fn token() -> String {
    let b: [u8; 32] = rand::random();
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn fmt_ts(ts: u64) -> String {
    let (y, m, d) = civil((ts / 86400) as i64);
    let s = ts % 86400;
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m, d, s / 3600, s % 3600 / 60)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read(p: &PathBuf) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn first_token(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

fn contains_id(content: &str, id: &str) -> bool {
    content.lines().any(|l| first_token(l) == id)
}

/// Appends a line, making sure the previous content ends with a newline.
fn append_line(p: &PathBuf, line: &str) -> std::io::Result<()> {
    let mut c = read(p);
    if !c.is_empty() && !c.ends_with('\n') {
        c.push('\n');
    }
    c.push_str(line);
    c.push('\n');
    write_atomic(p, &c)
}

/// Drops lines whose id is `id` (those starting with that id token); keeps the rest verbatim.
fn remove_id(p: &PathBuf, id: &str) -> std::io::Result<()> {
    let c = match std::fs::read_to_string(p) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    if !contains_id(&c, id) && !c.lines().any(|l| l.split_whitespace().next() == Some(id)) {
        return Ok(());
    }
    let mut out = String::new();
    for l in c.lines() {
        if first_token(l) == id || l.split_whitespace().next() == Some(id) {
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    write_atomic(p, &out)
}

fn write_atomic(p: &PathBuf, content: &str) -> std::io::Result<()> {
    let tmp = p.with_extension("tmp-admin");
    std::fs::write(&tmp, content)?;
    // keep the original mode and owner (the panel may run as root over hbbs-owned files)
    if let Ok(m) = std::fs::metadata(p) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(m.mode() & 0o7777));
        let _ = std::os::unix::fs::chown(&tmp, Some(m.uid()), Some(m.gid()));
    }
    std::fs::rename(&tmp, p)
}

fn client_key(h: &HeaderMap) -> String {
    h.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "local".into())
}

fn session_of(st: &AppState, h: &HeaderMap) -> Option<(String, String)> {
    let raw = h.get(header::COOKIE)?.to_str().ok()?;
    let tok = raw
        .split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)?
        .1;
    let mut s = st.sessions.lock().unwrap();
    match s.get(tok) {
        Some((csrf, created)) if created.elapsed() < SESSION_TTL => {
            Some((tok.to_string(), csrf.clone()))
        }
        Some(_) => {
            s.remove(tok);
            None
        }
        None => None,
    }
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{}</title><style>\
body{{font-family:system-ui,sans-serif;margin:0;padding:16px;max-width:720px;margin:auto;background:#f6f7f9;color:#1b1f24}}\
h1{{font-size:1.3rem}}h2{{font-size:1.05rem;margin-top:1.6rem}}\
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px}}\
td,th{{padding:8px;border-bottom:1px solid #e3e6ea;text-align:left;font-size:.9rem;word-break:break-all}}\
form{{display:inline}}button{{padding:8px 12px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-size:.9rem;cursor:pointer}}\
button.red{{background:#dc2626}}button.gray{{background:#6b7280}}\
input{{padding:10px;font-size:1rem;width:100%;box-sizing:border-box;margin:8px 0}}\
.empty{{color:#6b7280;font-size:.9rem}}</style></head><body>{}</body></html>",
        esc(title),
        body
    ))
}

// ---------- login ----------

async fn login_page() -> Html<String> {
    login_html("")
}

fn login_html(msg: &str) -> Html<String> {
    page(
        "EveryDesk - Entrar",
        &format!(
            "<h1>EveryDesk - Painel</h1><p>{}</p><form method=\"post\" action=\"/login\" style=\"display:block\">\
<input type=\"password\" name=\"password\" placeholder=\"Senha\" autofocus required>\
<button type=\"submit\">Entrar</button></form>",
            esc(msg)
        ),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login(State(st): State<St>, headers: HeaderMap, Form(f): Form<LoginForm>) -> Response {
    let key = client_key(&headers);
    {
        let fails = st.fails.lock().unwrap();
        if let Some((_, Some(until), _)) = fails.get(&key) {
            if Instant::now() < *until {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    login_html("Muitas tentativas. Tente novamente em alguns minutos."),
                )
                    .into_response();
            }
        }
    }
    if !ct_eq(f.password.as_bytes(), st.password.as_bytes()) {
        let mut fails = st.fails.lock().unwrap();
        let now = Instant::now();
        fails.retain(|_, (_, lock, last)| match lock {
            Some(u) => now < *u,
            None => now.duration_since(*last) < LOCKOUT,
        });
        let e = fails.entry(key).or_insert((0, None, now));
        e.2 = now;
        if matches!(e.1, Some(u) if Instant::now() >= u) {
            *e = (0, None, now);
        }
        e.0 += 1;
        if e.0 >= MAX_FAILS {
            e.1 = Some(Instant::now() + LOCKOUT);
        }
        return (StatusCode::UNAUTHORIZED, login_html("Senha incorreta.")).into_response();
    }
    st.fails.lock().unwrap().remove(&key);
    let tok = token();
    {
        let mut s = st.sessions.lock().unwrap();
        if s.len() >= MAX_SESSIONS {
            s.clear();
        }
        s.retain(|_, (_, t)| t.elapsed() < SESSION_TTL);
        s.insert(tok.clone(), (token(), Instant::now()));
    }
    let cookie = format!(
        "{}={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
        COOKIE, tok
    );
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

async fn logout(State(st): State<St>, headers: HeaderMap, Form(f): Form<CsrfForm>) -> Response {
    match session_of(&st, &headers) {
        Some((tok, csrf)) if ct_eq(csrf.as_bytes(), f.csrf.as_bytes()) => {
            st.sessions.lock().unwrap().remove(&tok);
            let mut resp = Redirect::to("/login").into_response();
            resp.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&format!(
                    "{}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
                    COOKIE
                ))
                .unwrap(),
            );
            resp
        }
        Some(_) => StatusCode::FORBIDDEN.into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

// ---------- index ----------

fn btn(action: &str, id: &str, csrf: &str, label: &str, class: &str) -> String {
    format!(
        "<form method=\"post\" action=\"/{}/{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<button class=\"{}\" type=\"submit\">{}</button></form> ",
        action,
        esc(id),
        esc(csrf),
        class,
        label
    )
}

#[derive(Debug, PartialEq)]
struct PendingEntry {
    id: String,
    ts: u64,
    /// Source IP hbbs recorded; absent in the older `"<id> <ts>"` lines.
    ip: Option<IpAddr>,
}

/// Lines `"<id> <ts>"` (old) or `"<id> <ts> <ip>"`; invalid ids and malformed
/// lines are skipped, an unparsable ip is shown as absent.
fn parse_pending(content: &str) -> Vec<PendingEntry> {
    content
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let id = it.next()?;
            let ts = it.next()?.parse().ok()?;
            let ip = it.next().and_then(|s| s.parse().ok());
            valid_id(id).then(|| PendingEntry { id: id.to_string(), ts, ip })
        })
        .collect()
}

async fn index(State(st): State<St>, headers: HeaderMap) -> Response {
    let Some((_, csrf)) = session_of(&st, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let _g = st.io.lock().unwrap();
    let allow = read(&st.allow);
    let blocked = read(&st.blocked);
    let pending = read(&st.pending);
    let mut b = String::from("<h1>EveryDesk - Máquinas</h1>");

    b.push_str(&format!(
        "<h2>Aprovar ID</h2><form method=\"post\" action=\"/approve\" style=\"display:block\">\
<input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<input type=\"text\" name=\"id\" placeholder=\"ID da máquina (ex.: 123456789)\" \
autocomplete=\"off\" required maxlength=\"16\">\
<button type=\"submit\">Aprovar ID</button></form>",
        esc(&csrf)
    ));

    b.push_str("<h2>Pendentes</h2>");
    let mut rows = String::new();
    let mut pend: Vec<PendingEntry> = parse_pending(&pending)
        .into_iter()
        .filter(|p| !contains_id(&allow, &p.id) && !contains_id(&blocked, &p.id))
        .collect();
    pend.reverse();
    for p in &pend {
        let ip = p.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "-".into());
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
            esc(&p.id),
            fmt_ts(p.ts),
            esc(&ip),
            btn("approve", &p.id, &csrf, "Aprovar", ""),
            btn("block", &p.id, &csrf, "Bloquear", "red")
        ));
    }
    if rows.is_empty() {
        b.push_str("<p class=\"empty\">Nenhuma máquina pendente.</p>");
    } else {
        b.push_str(&format!(
            "<table><tr><th>ID</th><th>Quando</th><th>Origem (IP)</th><th></th></tr>{}</table>",
            rows
        ));
    }

    b.push_str("<h2>Aprovados</h2>");
    let mut rows = String::new();
    for l in allow.lines() {
        let id = first_token(l);
        if id.is_empty() {
            continue;
        }
        let comment = l.split_once('#').map(|x| x.1.trim()).unwrap_or("");
        let buttons = if valid_id(id) {
            format!(
                "{}{}",
                btn("remove", id, &csrf, "Remover", "gray"),
                btn("block", id, &csrf, "Bloquear", "red")
            )
        } else {
            "<span class=\"empty\">edite o arquivo</span>".to_string()
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(id),
            esc(comment),
            buttons
        ));
    }
    if rows.is_empty() {
        b.push_str("<p class=\"empty\">Nenhuma máquina aprovada.</p>");
    } else {
        b.push_str(&format!(
            "<table><tr><th>ID</th><th>Comentário</th><th></th></tr>{}</table>",
            rows
        ));
    }

    b.push_str("<h2>Bloqueados</h2>");
    let mut rows = String::new();
    for l in blocked.lines() {
        let id = first_token(l);
        if id.is_empty() {
            continue;
        }
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            esc(id),
            btn("approve", id, &csrf, "Aprovar (desbloquear)", "")
        ));
    }
    if rows.is_empty() {
        b.push_str("<p class=\"empty\">Nenhuma máquina bloqueada.</p>");
    } else {
        b.push_str(&format!("<table>{}</table>", rows));
    }

    b.push_str(&format!(
        "<p><form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
<button class=\"gray\" type=\"submit\">Sair</button></form></p>",
        esc(&csrf)
    ));
    let mut resp = page("EveryDesk - Máquinas", &b).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

// ---------- actions ----------

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

#[derive(Clone, Copy)]
enum Act {
    Approve,
    Block,
    Remove,
}

fn act(st: &AppState, headers: &HeaderMap, id: &str, csrf: &str, a: Act) -> Response {
    let Some((_, expected)) = session_of(st, headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !ct_eq(expected.as_bytes(), csrf.as_bytes()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !valid_id(id) {
        return (StatusCode::BAD_REQUEST, "id inválido").into_response();
    }
    let _g = st.io.lock().unwrap();
    let r: std::io::Result<()> = (|| {
        match a {
            Act::Approve => {
                if !contains_id(&read(&st.allow), id) {
                    let (y, m, d) = civil((now() / 86400) as i64);
                    append_line(&st.allow, &format!("{} # aprovado {:04}-{:02}-{:02}", id, y, m, d))?;
                }
                remove_id(&st.pending, id)?;
                remove_id(&st.blocked, id)?;
            }
            Act::Block => {
                if !contains_id(&read(&st.blocked), id) {
                    append_line(&st.blocked, id)?;
                }
                remove_id(&st.pending, id)?;
                remove_id(&st.allow, id)?;
            }
            Act::Remove => remove_id(&st.allow, id)?,
        }
        Ok(())
    })();
    match r {
        Ok(()) => Redirect::to("/").into_response(),
        Err(e) => {
            eprintln!("io error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn approve(
    State(st): State<St>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    act(&st, &headers, &id, &f.csrf, Act::Approve)
}

#[derive(Deserialize)]
struct ManualForm {
    csrf: String,
    id: String,
}

/// "Aprovar ID": same session, CSRF and id checks as the per-row buttons, for
/// an id that never showed up in the pending list.
async fn approve_manual(
    State(st): State<St>,
    headers: HeaderMap,
    Form(f): Form<ManualForm>,
) -> Response {
    act(&st, &headers, f.id.trim(), &f.csrf, Act::Approve)
}

async fn block(
    State(st): State<St>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    act(&st, &headers, &id, &f.csrf, Act::Block)
}

async fn remove(
    State(st): State<St>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<CsrfForm>,
) -> Response {
    act(&st, &headers, &id, &f.csrf, Act::Remove)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn setup(name: &str) -> (St, PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ed-admin-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).unwrap();
        let allow = dir.join("allowed.txt");
        let pending = dir.join("pending.txt");
        std::fs::write(&allow, "# amigos\n111111 # Joao\n222222\n").unwrap();
        std::fs::write(&pending, "abc123 1700000000\n").unwrap();
        (
            Arc::new(AppState::new("segredo".into(), allow.clone(), pending.clone())),
            allow,
            pending,
        )
    }

    /// Logs in and returns (cookie header value, csrf token scraped from `/`).
    async fn login_ok(st: &St) -> (String, String) {
        let resp = router(st.clone())
            .oneshot(
                Request::post("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("password=segredo"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let sc = resp.headers()[header::SET_COOKIE].to_str().unwrap().to_string();
        assert!(sc.contains("HttpOnly") && sc.contains("Secure") && sc.contains("SameSite=Strict"));
        let cookie = sc.split(';').next().unwrap().to_string();
        let resp = router(st.clone())
            .oneshot(Request::get("/").header("cookie", &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        let i = html.find("name=\"csrf\" value=\"").unwrap() + 19;
        (cookie, html[i..i + 64].to_string())
    }

    async fn post(st: &St, uri: &str, cookie: &str, csrf: &str) -> StatusCode {
        router(st.clone())
            .oneshot(
                Request::post(uri)
                    .header("cookie", cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("csrf={}", csrf)))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn unauthenticated_is_401_or_redirect() {
        let (st, allow, _) = setup("unauth");
        let r = router(st.clone()).oneshot(Request::get("/").body(Body::empty()).unwrap()).await.unwrap();
        assert!(r.status() == StatusCode::SEE_OTHER || r.status() == StatusCode::UNAUTHORIZED);
        let s = post(&st, "/approve/abc123", "", "x").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(!read(&allow).contains("abc123"));
    }

    #[tokio::test]
    async fn approve_appends_to_allowed() {
        let (st, allow, pending) = setup("approve");
        let (cookie, csrf) = login_ok(&st).await;
        // wrong csrf is rejected
        assert_eq!(post(&st, "/approve/abc123", &cookie, "bad").await, StatusCode::FORBIDDEN);
        assert_eq!(post(&st, "/approve/abc123", &cookie, &csrf).await, StatusCode::SEE_OTHER);
        let a = read(&allow);
        assert!(a.contains("abc123 # aprovado 20"), "{}", a);
        assert!(a.ends_with('\n'));
        assert!(!read(&pending).contains("abc123"));
    }

    #[tokio::test]
    async fn approve_rejects_invalid_id() {
        let (st, allow, _) = setup("invalid");
        let (cookie, csrf) = login_ok(&st).await;
        for id in ["ab", "ABCDEF", "a%0Ab%20cdef", "12345", "-abcdef"] {
            let s = post(&st, &format!("/approve/{}", id), &cookie, &csrf).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{}", id);
        }
        assert_eq!(read(&allow), "# amigos\n111111 # Joao\n222222\n");
    }

    async fn post_body(st: &St, uri: &str, cookie: &str, body: &str) -> StatusCode {
        router(st.clone())
            .oneshot(
                Request::post(uri)
                    .header("cookie", cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn manual_approve_form() {
        let (st, allow, _) = setup("manual");
        // not logged in
        assert_eq!(
            post_body(&st, "/approve", "", "csrf=x&id=987654321").await,
            StatusCode::UNAUTHORIZED
        );
        let (cookie, csrf) = login_ok(&st).await;
        // wrong csrf
        assert_eq!(
            post_body(&st, "/approve", &cookie, "csrf=bad&id=987654321").await,
            StatusCode::FORBIDDEN
        );
        // invalid ids
        for id in ["ab", "ABCDEF", "a%0Ab%20cdef", "12345", "-abcdef", "a%23b%20cdef"] {
            let body = format!("csrf={}&id={}", csrf, id);
            assert_eq!(post_body(&st, "/approve", &cookie, &body).await, StatusCode::BAD_REQUEST, "{}", id);
        }
        assert!(!read(&allow).contains("987654321"));
        // valid (surrounding spaces trimmed)
        let body = format!("csrf={}&id=%20987654321%20", csrf);
        assert_eq!(post_body(&st, "/approve", &cookie, &body).await, StatusCode::SEE_OTHER);
        assert!(read(&allow).contains("987654321 # aprovado 20"));
        // the form is on the index page
        let resp = router(st.clone())
            .oneshot(Request::get("/").header("cookie", &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(html.contains("action=\"/approve\"") && html.contains("name=\"id\""));
    }

    #[test]
    fn pending_parses_old_and_new_lines() {
        let p = parse_pending(
            "abc123 1700000000\nbbb222 1700000001 203.0.113.9\nccc333 1700000002 ::1\n\
ddd444 1700000003 <script>\nBAD 1\nnots 1700000004\neee555 x 1.1.1.1\n",
        );
        assert_eq!(
            p,
            vec![
                PendingEntry { id: "abc123".into(), ts: 1700000000, ip: None },
                PendingEntry { id: "bbb222".into(), ts: 1700000001, ip: Some("203.0.113.9".parse().unwrap()) },
                PendingEntry { id: "ccc333".into(), ts: 1700000002, ip: Some("::1".parse().unwrap()) },
                PendingEntry { id: "ddd444".into(), ts: 1700000003, ip: None },
            ]
        );
    }

    #[tokio::test]
    async fn index_shows_pending_ip() {
        let (st, _, pending) = setup("ip");
        std::fs::write(&pending, "abc123 1700000000\nbbb222 1700000001 203.0.113.9\n").unwrap();
        let (cookie, _) = login_ok(&st).await;
        let resp = router(st.clone())
            .oneshot(Request::get("/").header("cookie", &cookie).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let html = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(html.contains("<td>bbb222</td><td>2023-11-14 22:13 UTC</td><td>203.0.113.9</td>"), "{}", html);
        assert!(html.contains("<td>abc123</td><td>2023-11-14 22:13 UTC</td><td>-</td>"), "{}", html);
    }

    #[tokio::test]
    async fn remove_keeps_other_lines() {
        let (st, allow, _) = setup("remove");
        let (cookie, csrf) = login_ok(&st).await;
        assert_eq!(post(&st, "/remove/111111", &cookie, &csrf).await, StatusCode::SEE_OTHER);
        assert_eq!(read(&allow), "# amigos\n222222\n");
    }

    #[tokio::test]
    async fn lockout_after_five_failures() {
        let (st, _, _) = setup("lock");
        for i in 0..6 {
            let r = router(st.clone())
                .oneshot(
                    Request::post("/login")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from("password=errada"))
                        .unwrap(),
                )
                .await
                .unwrap();
            let want = if i < 5 { StatusCode::UNAUTHORIZED } else { StatusCode::TOO_MANY_REQUESTS };
            assert_eq!(r.status(), want, "attempt {}", i);
        }
    }

    #[tokio::test]
    async fn write_keeps_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (st, allow, _) = setup("mode");
        std::fs::set_permissions(&allow, std::fs::Permissions::from_mode(0o640)).unwrap();
        let (cookie, csrf) = login_ok(&st).await;
        assert_eq!(post(&st, "/remove/111111", &cookie, &csrf).await, StatusCode::SEE_OTHER);
        let mode = std::fs::metadata(&allow).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
}
