//! SQLite storage: single writer actor, WAL mode.
//!
//! All writes go through one writer thread. Modules never write directly.
//! Writes are direct autocommit in Phase 1; batched transactions land with
//! real volume in a later phase.
//! Every work unit has persisted state (pending/done/failed) for resume.

use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::thread;
use thiserror::Error;
use tracing::info;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const MIGRATION_001: &str = "
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    started INTEGER NOT NULL,
    finished INTEGER
);
CREATE TABLE IF NOT EXISTS work_units (
    scan_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    key TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    PRIMARY KEY (scan_id, stage, key)
);
CREATE TABLE IF NOT EXISTS facts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    sources_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_facts_scan_kind ON facts(scan_id, kind);
";

const MIGRATION_002: &str = "
CREATE TABLE IF NOT EXISTS ports (
    scan_id TEXT NOT NULL,
    host TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    latency_ms INTEGER NOT NULL,
    PRIMARY KEY (scan_id, ip, port)
);
CREATE TABLE IF NOT EXISTS http_services (
    scan_id TEXT NOT NULL,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    status INTEGER NOT NULL,
    title TEXT,
    server TEXT,
    body_hash INTEGER NOT NULL,
    time_ms INTEGER NOT NULL,
    PRIMARY KEY (scan_id, url)
);
CREATE TABLE IF NOT EXISTS tls_info (
    scan_id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    version TEXT,
    cipher TEXT,
    subject TEXT,
    issuer TEXT,
    expired INTEGER NOT NULL,
    self_signed INTEGER NOT NULL,
    validation_ok INTEGER NOT NULL,
    PRIMARY KEY (scan_id, host, port)
);
CREATE TABLE IF NOT EXISTS technologies (
    scan_id TEXT NOT NULL,
    host TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    confidence REAL NOT NULL,
    PRIMARY KEY (scan_id, host, name)
);
";

const MIGRATION_003: &str = "
CREATE TABLE IF NOT EXISTS urls (
    scan_id TEXT NOT NULL,
    canonical TEXT NOT NULL,
    template TEXT NOT NULL,
    sources TEXT NOT NULL,
    PRIMARY KEY (scan_id, canonical)
);
CREATE TABLE IF NOT EXISTS js_files (
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    hash INTEGER NOT NULL,
    parsed_ok INTEGER NOT NULL,
    PRIMARY KEY (scan_id, url)
);
CREATE TABLE IF NOT EXISTS endpoints (
    scan_id TEXT NOT NULL,
    template TEXT NOT NULL,
    methods TEXT NOT NULL,
    sources TEXT NOT NULL,
    PRIMARY KEY (scan_id, template)
);
CREATE TABLE IF NOT EXISTS parameters (
    scan_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    method TEXT NOT NULL,
    PRIMARY KEY (scan_id, endpoint, name, location)
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    confidence REAL NOT NULL,
    PRIMARY KEY (scan_id, kind, subject)
);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkState {
    Pending,
    Done,
    Failed,
}

impl WorkState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

// ---------------------------------------------------------------------------
// Writer actor
// ---------------------------------------------------------------------------

enum WriteOp {
    Execute { sql: String, params: Vec<String> },
    Shutdown,
}

pub struct Store {
    path: PathBuf,
    tx: std_mpsc::SyncSender<WriteOp>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        migrate(path)?;
        let (tx, rx) = std_mpsc::sync_channel::<WriteOp>(1024);
        let worker_path = path.to_path_buf();
        thread::spawn(move || {
            let conn = match Connection::open(&worker_path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("store writer failed to open db: {e}");
                    return;
                }
            };
            for op in rx {
                match op {
                    WriteOp::Shutdown => break,
                    WriteOp::Execute { sql, params } => {
                        let result = (|| -> rusqlite::Result<usize> {
                            let mut stmt = conn.prepare_cached(&sql)?;
                            stmt.execute(rusqlite::params_from_iter(params.iter()))
                        })();
                        if let Err(e) = result {
                            tracing::error!("store write failed: {e}");
                        }
                    }
                }
            }
        });
        Ok(Self {
            path: path.to_path_buf(),
            tx,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn send(&self, sql: &str, params: Vec<String>) {
        let _ = self.tx.send(WriteOp::Execute {
            sql: sql.to_string(),
            params,
        });
    }

    pub fn create_scan(&self, scan_id: &str, scope_json: &str, started: i64) {
        self.send(
            "INSERT OR IGNORE INTO scans (id, status, scope_json, started) VALUES (?1, 'running', ?2, ?3)",
            vec![
                scan_id.to_string(),
                scope_json.to_string(),
                started.to_string(),
            ],
        );
    }

    pub fn finish_scan(&self, scan_id: &str, finished: i64) {
        self.send(
            "UPDATE scans SET status='done', finished=?2 WHERE id=?1",
            vec![scan_id.to_string(), finished.to_string()],
        );
    }

    /// Persist one discovered fact. Duplicates merge by replacing the row
    /// with the union JSON the caller computed (see `Fact::merge`).
    pub fn insert_fact(&self, fact: &swiftrecon_core::Fact) {
        let sources = serde_json::to_string(&fact.sources).unwrap_or_else(|_| "[]".to_string());
        let evidence = serde_json::to_string(&fact.evidence).unwrap_or_else(|_| "[]".to_string());
        self.send(
            "INSERT INTO facts (id, scan_id, kind, value, sources_json, evidence_json, confidence, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (id) DO UPDATE SET sources_json=excluded.sources_json, evidence_json=excluded.evidence_json,
             confidence=excluded.confidence, last_seen=excluded.last_seen",
            vec![
                fact.id.clone(),
                fact.scan_id.clone(),
                fact.kind.clone(),
                fact.value.clone(),
                sources,
                evidence,
                fact.confidence.value().to_string(),
                fact.first_seen.to_string(),
                fact.last_seen.to_string(),
            ],
        );
    }

    pub fn insert_port(&self, scan_id: &str, host: &str, fact: &swiftrecon_engine::PortFact) {
        self.send(
            "INSERT INTO ports (scan_id, host, ip, port, state, reason, latency_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (scan_id, ip, port) DO UPDATE SET state=excluded.state, reason=excluded.reason",
            vec![
                scan_id.to_string(),
                host.to_string(),
                fact.ip.to_string(),
                fact.port.to_string(),
                fact.state.clone(),
                fact.reason.clone(),
                fact.latency_ms.to_string(),
            ],
        );
    }

    pub fn insert_http(&self, scan_id: &str, record: &swiftrecon_net::http::HttpRecord) {
        self.send(
            "INSERT INTO http_services (scan_id, host, url, status, title, server, body_hash, time_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (scan_id, url) DO UPDATE SET status=excluded.status, title=excluded.title",
            vec![
                scan_id.to_string(),
                record.host.clone(),
                record.final_url.clone(),
                record.status.to_string(),
                record.title.clone().unwrap_or_default(),
                record.server.clone().unwrap_or_default(),
                record.body_hash.to_string(),
                record.time_ms.to_string(),
            ],
        );
    }

    pub fn insert_tls(&self, scan_id: &str, record: &swiftrecon_net::tls::TlsRecord) {
        self.send(
            "INSERT INTO tls_info (scan_id, host, port, version, cipher, subject, issuer, expired, self_signed, validation_ok)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT (scan_id, host, port) DO UPDATE SET subject=excluded.subject",
            vec![
                scan_id.to_string(),
                record.host.clone(),
                record.port.to_string(),
                record.version.clone().unwrap_or_default(),
                record.cipher.clone().unwrap_or_default(),
                record.subject.clone().unwrap_or_default(),
                record.issuer.clone().unwrap_or_default(),
                (record.expired as u8).to_string(),
                (record.self_signed as u8).to_string(),
                (record.validation_ok as u8).to_string(),
            ],
        );
    }

    pub fn insert_tech(
        &self,
        scan_id: &str,
        host: &str,
        name: &str,
        version: Option<&str>,
        confidence: f64,
    ) {
        self.send(
            "INSERT INTO technologies (scan_id, host, name, version, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (scan_id, host, name) DO UPDATE SET confidence=excluded.confidence",
            vec![
                scan_id.to_string(),
                host.to_string(),
                name.to_string(),
                version.unwrap_or("").to_string(),
                confidence.to_string(),
            ],
        );
    }

    pub fn insert_url(&self, scan_id: &str, canonical: &str, template: &str, sources: &[String]) {
        let sources_json = serde_json::to_string(sources).unwrap_or_else(|_| "[]".to_string());
        self.send(
            "INSERT INTO urls (scan_id, canonical, template, sources)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (scan_id, canonical) DO NOTHING",
            vec![
                scan_id.to_string(),
                canonical.to_string(),
                template.to_string(),
                sources_json,
            ],
        );
    }

    pub fn insert_js(&self, scan_id: &str, url: &str, hash: u64, parsed_ok: bool) {
        self.send(
            "INSERT INTO js_files (scan_id, url, hash, parsed_ok)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (scan_id, url) DO NOTHING",
            vec![
                scan_id.to_string(),
                url.to_string(),
                hash.to_string(),
                (parsed_ok as u8).to_string(),
            ],
        );
    }

    pub fn insert_endpoint(
        &self,
        scan_id: &str,
        template: &str,
        methods: &[String],
        sources: &[String],
    ) {
        let methods_json = serde_json::to_string(methods).unwrap_or_else(|_| "[]".to_string());
        let sources_json = serde_json::to_string(sources).unwrap_or_else(|_| "[]".to_string());
        self.send(
            "INSERT INTO endpoints (scan_id, template, methods, sources)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (scan_id, template) DO NOTHING",
            vec![
                scan_id.to_string(),
                template.to_string(),
                methods_json,
                sources_json,
            ],
        );
    }

    pub fn insert_param(
        &self,
        scan_id: &str,
        endpoint: &str,
        name: &str,
        location: &str,
        method: &str,
    ) {
        self.send(
            "INSERT INTO parameters (scan_id, endpoint, name, location, method)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (scan_id, endpoint, name, location) DO NOTHING",
            vec![
                scan_id.to_string(),
                endpoint.to_string(),
                name.to_string(),
                location.to_string(),
                method.to_string(),
            ],
        );
    }

    /// Candidate finding. Values are never stored: `subject` carries the
    /// redacted kind only (e.g. `secret:aws_key@host`).
    pub fn insert_finding(&self, scan_id: &str, kind: &str, subject: &str, confidence: f64) {
        self.send(
            "INSERT INTO findings (scan_id, kind, subject, confidence)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (scan_id, kind, subject) DO NOTHING",
            vec![
                scan_id.to_string(),
                kind.to_string(),
                subject.to_string(),
                confidence.to_string(),
            ],
        );
    }

    pub fn upsert_work_unit(&self, scan_id: &str, stage: &str, key: &str, state: WorkState) {
        self.send(
            "INSERT INTO work_units (scan_id, stage, key, state, attempts) VALUES (?1, ?2, ?3, ?4, 0)
             ON CONFLICT (scan_id, stage, key) DO UPDATE SET state=excluded.state",
            vec![
                scan_id.to_string(),
                stage.to_string(),
                key.to_string(),
                state.as_str().to_string(),
            ],
        );
    }

    /// Keys already done for (scan, stage): resume skips exactly these.
    pub fn done_keys(&self, scan_id: &str, stage: &str) -> Vec<String> {
        let conn = match Connection::open(&self.path) {
            Ok(conn) => conn,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn
            .prepare("SELECT key FROM work_units WHERE scan_id=?1 AND stage=?2 AND state='done'")
        {
            Ok(stmt) => stmt,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![scan_id, stage], |row| row.get(0))
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// Count work units in a state (direct read for resume checks).
    pub fn count_work_units(&self, scan_id: &str, state: WorkState) -> Result<i64, StoreError> {
        // Flush ordering is best-effort in Phase 1; reads open a new connection.
        let conn = Connection::open(&self.path)?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM work_units WHERE scan_id=?1 AND state=?2",
            params![scan_id, state.as_str()],
            |row| row.get(0),
        )?;
        Ok(n)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.tx.send(WriteOp::Shutdown);
    }
}

pub fn migrate(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(MIGRATION_001)?;
    conn.execute_batch(MIGRATION_002)?;
    conn.execute_batch(MIGRATION_003)?;
    info!("store migrated at {}", path.display());
    Ok(())
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn migrate_creates_tables() {
        let file = NamedTempFile::new().unwrap();
        migrate(file.path()).unwrap();
        let conn = Connection::open(file.path()).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('scans','work_units','facts')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn empty_scan_persists_and_resumes() {
        let file = NamedTempFile::new().unwrap();
        let store = Store::open(file.path()).unwrap();
        store.create_scan("scan1", "{}", 1);
        store.upsert_work_unit("scan1", "discover", "a.example.com", WorkState::Done);
        store.upsert_work_unit("scan1", "discover", "b.example.com", WorkState::Pending);
        drop(store);
        // Reopen: completed work is still there (resume skips it).
        let conn = Connection::open(file.path()).unwrap();
        // Wait briefly for the background writer to flush.
        for _ in 0..50 {
            let done: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM work_units WHERE scan_id='scan1' AND state='done'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            if done >= 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let done: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM work_units WHERE scan_id='scan1' AND state='done'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(done, 1);
    }
}
