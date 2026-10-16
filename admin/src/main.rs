use everydesk_admin::{router, AppState};
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let password = match std::env::var("ADMIN_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!("ADMIN_PASSWORD is required");
            std::process::exit(1);
        }
    };
    let allow = PathBuf::from(
        std::env::var("ALLOWLIST_FILE")
            .unwrap_or_else(|_| "/var/lib/rustdesk-server/allowed.txt".into()),
    );
    let pending = PathBuf::from(
        std::env::var("PENDING_FILE")
            .unwrap_or_else(|_| "/var/lib/rustdesk-server/pending.txt".into()),
    );
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:3300".into());
    let state = Arc::new(AppState::new(password, allow, pending));
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("cannot bind");
    eprintln!("everydesk-admin listening on {}", bind);
    axum::serve(listener, router(state)).await.unwrap();
}
