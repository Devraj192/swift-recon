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
    -- TEXT affinity: full-range u64 hashes overflow INTEGER and would
    -- otherwise round-trip through REAL. Pre-release schema; *.db is gitignored.
    body_hash TEXT NOT NULL DEFAULT '0',
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
    -- TEXT affinity for full-range u64 hashes (see body_hash above).
    hash TEXT NOT NULL DEFAULT '0',
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

/// Phase 5: full HTTP record columns for faithful export. Added
/// idempotently: ALTER fails if the column exists, so check first.
const HTTP_EXTRA_COLUMNS: &[(&str, &str)] = &[
    ("ip", "TEXT NOT NULL DEFAULT ''"),
    ("port", "INTEGER NOT NULL DEFAULT 0"),
    ("tls", "INTEGER NOT NULL DEFAULT 0"),
    ("content_type", "TEXT NOT NULL DEFAULT ''"),
    ("http_version", "TEXT NOT NULL DEFAULT ''"),
    ("length", "INTEGER NOT NULL DEFAULT 0"),
    ("headers_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("cookies", "TEXT NOT NULL DEFAULT '[]'"),
    ("chain", "TEXT NOT NULL DEFAULT '[]'"),
    ("excerpt", "TEXT NOT NULL DEFAULT ''"),
];

fn ensure_http_columns(conn: &Connection) -> Result<(), StoreError> {
    let mut stmt = conn.prepare("PRAGMA table_info(http_services)")?;
    let have: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .collect();
    for (name, ddl) in HTTP_EXTRA_COLUMNS {
        if !have.iter().any(|c| c == name) {
            conn.execute_batch(&format!(
                "ALTER TABLE http_services ADD COLUMN {name} {ddl}"
            ))?;
        }
    }
    Ok(())
}

/// Read models for history, compare, explain, and graph views.
pub use swiftrecon_core::{StoredEndpoint, StoredParam, StoredPort, StoredScan, StoredTech};

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
    tx: Option<std_mpsc::SyncSender<WriteOp>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        migrate(path)?;
        let (tx, rx) = std_mpsc::sync_channel::<WriteOp>(1024);
        let worker_path = path.to_path_buf();
        let worker = thread::spawn(move || {
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
            tx: Some(tx),
            worker: Some(worker),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn send(&self, sql: &str, params: Vec<String>) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(WriteOp::Execute {
                sql: sql.to_string(),
                params,
            });
        }
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
        let cookies = serde_json::json!({
            "names": record.cookie_names,
            "flags": record.cookie_secure_flags,
        })
        .to_string();
        let chain = serde_json::to_string(&record.chain).unwrap_or_else(|_| "[]".to_string());
        self.send(
            "INSERT INTO http_services
             (scan_id, host, url, status, title, server, body_hash, time_ms,
              ip, port, tls, content_type, http_version, length, headers_json, cookies, chain, excerpt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
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
                record.ip.clone(),
                record.port.to_string(),
                (record.tls as u8).to_string(),
                record.content_type.clone().unwrap_or_default(),
                record.http_version.clone(),
                record.length.to_string(),
                record.headers_json.clone(),
                cookies,
                chain,
                record.excerpt.clone(),
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

    fn read_conn(&self) -> Result<Connection, StoreError> {
        Ok(Connection::open(&self.path)?)
    }

    /// Scan history, newest first.
    pub fn list_scans(&self) -> Result<Vec<StoredScan>, StoreError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, status, scope_json, started, finished FROM scans ORDER BY started DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredScan {
                id: row.get(0)?,
                status: row.get(1)?,
                scope_json: row.get(2)?,
                started: row.get(3)?,
                finished: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// All facts of one scan, ordered by kind then value.
    pub fn get_facts(&self, scan_id: &str) -> Result<Vec<swiftrecon_core::Fact>, StoreError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, kind, value, sources_json, evidence_json, confidence, first_seen, last_seen
             FROM facts WHERE scan_id=?1 ORDER BY kind, value",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let sources_json: String = row.get(4)?;
            let evidence_json: String = row.get(5)?;
            Ok(swiftrecon_core::Fact {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                kind: row.get(2)?,
                value: row.get(3)?,
                sources: serde_json::from_str(&sources_json).unwrap_or_default(),
                evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
                confidence: swiftrecon_core::Confidence(row.get(6)?),
                first_seen: row.get(7)?,
                last_seen: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_ports(&self, scan_id: &str) -> Result<Vec<StoredPort>, StoreError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT host, ip, port, state, reason FROM ports WHERE scan_id=?1 ORDER BY ip, port",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(StoredPort {
                host: row.get(0)?,
                ip: row.get(1)?,
                port: row.get(2)?,
                state: row.get(3)?,
                reason: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_endpoints(&self, scan_id: &str) -> Result<Vec<StoredEndpoint>, StoreError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT template, methods, sources FROM endpoints WHERE scan_id=?1 ORDER BY template",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let methods: String = row.get(1)?;
            let sources: String = row.get(2)?;
            Ok(StoredEndpoint {
                template: row.get(0)?,
                methods: serde_json::from_str(&methods).unwrap_or_default(),
                sources: serde_json::from_str(&sources).unwrap_or_default(),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_params(&self, scan_id: &str) -> Result<Vec<StoredParam>, StoreError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT endpoint, name, location, method FROM parameters
             WHERE scan_id=?1 ORDER BY endpoint, name",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(StoredParam {
                endpoint: row.get(0)?,
                name: row.get(1)?,
                location: row.get(2)?,
                method: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_techs(&self, scan_id: &str) -> Result<Vec<StoredTech>, StoreError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT host, name, version, confidence FROM technologies
             WHERE scan_id=?1 ORDER BY host, name",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(StoredTech {
                host: row.get(0)?,
                name: row.get(1)?,
                version: row.get(2)?,
                confidence: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn get_http(
        &self,
        scan_id: &str,
    ) -> Result<Vec<swiftrecon_net::http::HttpRecord>, StoreError> {
        use rusqlite::types::Value;
        use rusqlite::Row;

        // Columns may hold INTEGER (affinity-converted numerics) or TEXT
        // (overflows like u64 hashes stay text). Accept both.
        fn cell(row: &Row<'_>, index: usize) -> String {
            match row.get::<_, Value>(index) {
                Ok(Value::Integer(n)) => n.to_string(),
                Ok(Value::Real(f)) => f.to_string(),
                Ok(Value::Text(s)) => s,
                _ => String::new(),
            }
        }
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT host, url, status, title, server, body_hash, time_ms,
                    ip, port, tls, content_type, http_version, length, headers_json, cookies, chain, excerpt
             FROM http_services WHERE scan_id=?1 ORDER BY url",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let cookies: String = row.get(14)?;
            let cookies: serde_json::Value =
                serde_json::from_str(&cookies).unwrap_or(serde_json::Value::Null);
            let chain: String = row.get(15)?;
            let title: String = row.get(3)?;
            let server: String = row.get(4)?;
            let content_type: String = row.get(10)?;
            let num = |index: usize| cell(row, index).parse::<u64>().unwrap_or(0);
            Ok(swiftrecon_net::http::HttpRecord {
                host: row.get(0)?,
                ip: row.get(7)?,
                port: num(8).min(u64::from(u16::MAX)) as u16,
                tls: num(9) != 0,
                final_url: row.get(1)?,
                chain: serde_json::from_str(&chain).unwrap_or_default(),
                status: num(2).min(999) as u16,
                length: num(12).min(usize::MAX as u64) as usize,
                title: if title.is_empty() { None } else { Some(title) },
                server: if server.is_empty() {
                    None
                } else {
                    Some(server)
                },
                headers_json: row.get(13)?,
                cookie_names: cookies
                    .get("names")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
                cookie_secure_flags: cookies
                    .get("flags")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
                content_type: if content_type.is_empty() {
                    None
                } else {
                    Some(content_type)
                },
                http_version: row.get(11)?,
                time_ms: num(6),
                body_hash: num(5),
                excerpt: row.get(16)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }
}

impl Drop for Store {
    /// Best-effort flush: queued writes drain before the process moves on,
    /// so `history` never misses a finished scan. The worker only reads the
    /// channel, so joining cannot deadlock.
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(WriteOp::Shutdown);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
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
    ensure_http_columns(&conn)?;
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

    /// History foundation: written rows read back identically.
    #[test]
    fn history_reads_round_trip() {
        use swiftrecon_core::{Confidence, Evidence, Fact};

        let file = NamedTempFile::new().unwrap();
        let store = Store::open(file.path()).unwrap();
        store.create_scan("scan9", "example.com", 1);
        let fact = Fact::new(
            "scan9",
            "subdomain",
            "a.example.com",
            vec!["crtsh".to_string()],
            vec![Evidence::observed("discovery", "source", "crtsh")],
            Confidence(0.6),
        );
        store.insert_fact(&fact);
        store.insert_tech("scan9", "a.example.com", "nginx", None, 0.7);
        drop(store);

        let probe = Store::open(file.path()).unwrap();
        let mut facts = Vec::new();
        for _ in 0..50 {
            facts = probe.get_facts("scan9").unwrap_or_default();
            if !facts.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].value, "a.example.com");
        assert_eq!(facts[0].sources, vec!["crtsh".to_string()]);
        assert_eq!(facts[0].evidence.len(), 1);
        let scans = probe.list_scans().unwrap();
        assert!(scans.iter().any(|s| s.id == "scan9"));
        let techs = probe.get_techs("scan9").unwrap();
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0].name, "nginx");
    }

    /// HTTP round trip preserves hashes above i64 range and cookie flags.
    #[test]
    fn http_reads_round_trip() {
        use swiftrecon_net::http::HttpRecord;

        let file = NamedTempFile::new().unwrap();
        let store = Store::open(file.path()).unwrap();
        let record = HttpRecord {
            host: "a.example.com".to_string(),
            ip: "1.2.3.4".to_string(),
            port: 443,
            tls: true,
            final_url: "https://a.example.com/".to_string(),
            chain: vec!["https://a.example.com/".to_string()],
            status: 200,
            length: 12,
            title: Some("Hi".to_string()),
            server: None,
            headers_json: "{}".to_string(),
            cookie_names: vec!["sess".to_string()],
            cookie_secure_flags: vec!["secure".to_string()],
            content_type: Some("text/html".to_string()),
            http_version: "HTTP/2".to_string(),
            time_ms: 42,
            body_hash: u64::MAX,
            excerpt: "Hi".to_string(),
        };
        store.insert_http("scan9", &record);
        drop(store);

        let probe = Store::open(file.path()).unwrap();
        let mut records = Vec::new();
        for _ in 0..50 {
            match probe.get_http("scan9") {
                Ok(rows) if !rows.is_empty() => {
                    records = rows;
                    break;
                }
                Err(e) => panic!("get_http failed: {e}"),
                Ok(_) => {}
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].body_hash, u64::MAX);
        assert_eq!(records[0].cookie_names, vec!["sess".to_string()]);
        assert_eq!(records[0].cookie_secure_flags, vec!["secure".to_string()]);
        assert!(records[0].tls);
    }

    /// Drop flushes the writer: a finished scan reads back done with no
    /// polling, so `history` never misses it.
    #[test]
    fn drop_flushes_finished_scan() {
        let file = NamedTempFile::new().unwrap();
        let store = Store::open(file.path()).unwrap();
        store.create_scan("scan-done", "{}", 1);
        store.finish_scan("scan-done", 2);
        drop(store);
        let probe = Store::open(file.path()).unwrap();
        let scans = probe.list_scans().unwrap();
        let scan = scans
            .iter()
            .find(|s| s.id == "scan-done")
            .expect("scan listed");
        assert_eq!(scan.status, "done");
    }
}
