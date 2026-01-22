-- Table principale des extensions
CREATE TABLE IF NOT EXISTS extensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_id TEXT NOT NULL,
    browser TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    manifest_version INTEGER,
    description TEXT,
    author TEXT,
    homepage_url TEXT,
    installed_path TEXT,
    profile TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_score INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT 1,
    UNIQUE(extension_id, browser, installed_path)
);

-- Table des permissions
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_fk INTEGER NOT NULL,
    permission TEXT NOT NULL,
    permission_type TEXT,
    is_dangerous BOOLEAN DEFAULT 0,
    FOREIGN KEY (extension_fk) REFERENCES extensions(id) ON DELETE CASCADE
);

-- Table des scans/collectes
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_extensions INTEGER,
    chrome_count INTEGER DEFAULT 0,
    firefox_count INTEGER DEFAULT 0,
    edge_count INTEGER DEFAULT 0,
    hostname TEXT,
    agent_version TEXT
);

-- Table des alertes
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_fk INTEGER NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_resolved BOOLEAN DEFAULT 0,
    FOREIGN KEY (extension_fk) REFERENCES extensions(id) ON DELETE CASCADE
);

-- Table des scans de code
CREATE TABLE IF NOT EXISTS code_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    extension_fk INTEGER NOT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    files_scanned INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    obfuscation_score INTEGER DEFAULT 0,
    scan_results TEXT,
    FOREIGN KEY (extension_fk) REFERENCES extensions(id) ON DELETE CASCADE
);

-- Index pour performances
CREATE INDEX IF NOT EXISTS idx_extension_id ON extensions(extension_id);
CREATE INDEX IF NOT EXISTS idx_browser ON extensions(browser);
CREATE INDEX IF NOT EXISTS idx_risk_score ON extensions(risk_score);
CREATE INDEX IF NOT EXISTS idx_permissions ON permissions(extension_fk);
CREATE INDEX IF NOT EXISTS idx_alerts_unresolved ON alerts(is_resolved, severity);
CREATE INDEX IF NOT EXISTS idx_code_scans_extension ON code_scans(extension_fk);
