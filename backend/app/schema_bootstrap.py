from sqlalchemy import inspect, text
from app.db.session import engine

COLUMN_SPECS = {
    "scans": {
        "assessment_name": "VARCHAR(300)",
        "target_url_snapshot": "VARCHAR(2000)",
        "mode": "VARCHAR(40)",
        "auth_mode": "VARCHAR(40)",
        "progress": "INTEGER DEFAULT 0",
        "log_cursor": "INTEGER DEFAULT 0",
    },
    "findings": {
        "cvss_v4": "VARCHAR(30)",
        "owasp_mapping": "VARCHAR(300)",
        "framework_mapping": "VARCHAR(500)",
        "cwe": "VARCHAR(200)",
        "status": "VARCHAR(32) DEFAULT 'open'",
        "created_at": "DATETIME",
        "updated_at": "DATETIME",
        "cvss_vector_v4": "VARCHAR(500)",
        "cvss_source": "VARCHAR(40) DEFAULT 'unknown'",
        "verification": "VARCHAR(32) DEFAULT 'unreviewed'",
        "classification": "VARCHAR(40) DEFAULT 'need_further_investigate'",
    }
}

def ensure_schema():
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, columns in COLUMN_SPECS.items():
            if not inspector.has_table(table):
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
