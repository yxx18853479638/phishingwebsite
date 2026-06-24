import os
from dotenv import load_dotenv
import re
import sqlite3
from urllib.parse import urlparse, urlunparse
load_dotenv()
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:  # pragma: no cover - only used when PostgreSQL dependency is missing.
    psycopg2 = None
    RealDictCursor = None


# Name of the fallback SQLite database file.
DATABASE_NAME = "phishing_platform.db"
DATABASE_URL = os.environ.get("DATABASE_URL")
POSTGRES_INSERT_TABLES = {"admins", "users", "scans", "activity_logs"}


SQLITE_TABLES = [
    """
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        submitted_url TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        score INTEGER NOT NULL,
        detected_features TEXT NOT NULL DEFAULT '[]',
        explanations TEXT NOT NULL,
        recommendations TEXT NOT NULL,
        ip_address TEXT,
        scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        action_type TEXT NOT NULL,
        action_details TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );
    """,
]


POSTGRES_TABLES = [
    """
    CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        submitted_url TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        score INTEGER NOT NULL,
        detected_features TEXT NOT NULL DEFAULT '[]',
        explanations TEXT NOT NULL,
        recommendations TEXT NOT NULL,
        ip_address TEXT,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES admins(id),
        action_type TEXT NOT NULL,
        action_details TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
]


class PostgresCursor:
    """Cursor wrapper that lets the app keep using SQLite-style ? placeholders."""

    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = None

    def execute(self, sql, params=None):
        self.lastrowid = None
        converted_sql = convert_placeholders(sql)
        converted_sql = self.add_returning_id_if_needed(converted_sql)
        self.cursor.execute(converted_sql, params or ())

        if converted_sql.strip().upper().endswith("RETURNING ID"):
            inserted_row = self.cursor.fetchone()
            if inserted_row:
                self.lastrowid = inserted_row["id"]

        return self

    def executemany(self, sql, params=None):
        self.lastrowid = None
        self.cursor.executemany(convert_placeholders(sql), params or [])
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def close(self):
        self.cursor.close()

    def __iter__(self):
        return iter(self.cursor)

    @staticmethod
    def add_returning_id_if_needed(sql):
        stripped_sql = sql.strip()
        if re.search(r"\bRETURNING\b", stripped_sql, re.IGNORECASE):
            return sql

        match = re.match(r"INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\b", stripped_sql, re.IGNORECASE)
        if not match:
            return sql

        table_name = match.group(1).lower()
        if table_name not in POSTGRES_INSERT_TABLES:
            return sql

        semicolon = ";" if stripped_sql.endswith(";") else ""
        sql_without_semicolon = stripped_sql[:-1] if semicolon else stripped_sql
        return f"{sql_without_semicolon} RETURNING id{semicolon}"


class PostgresConnection:
    """Connection wrapper that returns dict-like rows like sqlite3.Row."""

    def __init__(self, connection):
        self.connection = connection
        self.row_factory = None

    def cursor(self):
        return PostgresCursor(self.connection.cursor(cursor_factory=RealDictCursor))

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()



def is_postgres_enabled():
    """Return True when DATABASE_URL should be used for PostgreSQL."""
    return bool(DATABASE_URL)



def normalize_database_url(database_url):
    """Return a psycopg2-compatible database URL without exposing credentials."""
    parsed_url = urlparse(database_url)
    if parsed_url.scheme == "postgres":
        parsed_url = parsed_url._replace(scheme="postgresql")
    return urlunparse(parsed_url)



def convert_placeholders(sql):
    """Convert SQLite ? placeholders to PostgreSQL %s placeholders."""
    return sql.replace("?", "%s")



def create_connection():
    """Create and return a PostgreSQL connection when DATABASE_URL exists, otherwise SQLite."""
    if is_postgres_enabled():
        if psycopg2 is None:
            raise RuntimeError(
                "DATABASE_URL is set, but psycopg2-binary is not installed. "
                "Run: pip install -r requirements.txt"
            )
        postgres_connection = psycopg2.connect(normalize_database_url(DATABASE_URL))
        return PostgresConnection(postgres_connection)

    return sqlite3.connect(DATABASE_NAME)



def get_existing_columns(cursor, table_name):
    """Return a list of existing column names for either database engine."""
    if is_postgres_enabled():
        cursor.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = ? AND table_schema = 'public'
            """,
            (table_name,),
        )
        return [column["column_name"] for column in cursor.fetchall()]

    cursor.execute(f"PRAGMA table_info({table_name})")
    return [column[1] for column in cursor.fetchall()]



def add_column_if_missing(cursor, table_name, column_name, sqlite_definition, postgres_definition):
    """Add a missing column using the correct SQL type for the active database."""
    existing_columns = get_existing_columns(cursor, table_name)
    if column_name in existing_columns:
        return

    column_definition = postgres_definition if is_postgres_enabled() else sqlite_definition
    cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_definition}")



def initialize_database():
    """Create all database tables and add any columns needed by older databases."""
    connection = create_connection()
    cursor = connection.cursor()

    table_statements = POSTGRES_TABLES if is_postgres_enabled() else SQLITE_TABLES
    for table_sql in table_statements:
        cursor.execute(table_sql)

    add_column_if_missing(
        cursor,
        "users",
        "failed_login_attempts",
        "failed_login_attempts INTEGER DEFAULT 0",
        "failed_login_attempts INTEGER DEFAULT 0",
    )
    add_column_if_missing(
        cursor,
        "users",
        "locked_until",
        "locked_until DATETIME",
        "locked_until TIMESTAMP",
    )
    add_column_if_missing(
        cursor,
        "admins",
        "failed_login_attempts",
        "failed_login_attempts INTEGER DEFAULT 0",
        "failed_login_attempts INTEGER DEFAULT 0",
    )
    add_column_if_missing(
        cursor,
        "admins",
        "locked_until",
        "locked_until DATETIME",
        "locked_until TIMESTAMP",
    )
    add_column_if_missing(
        cursor,
        "scans",
        "user_id",
        "user_id INTEGER",
        "user_id INTEGER REFERENCES users(id)",
    )
    add_column_if_missing(
        cursor,
        "scans",
        "detected_features",
        "detected_features TEXT NOT NULL DEFAULT '[]'",
        "detected_features TEXT NOT NULL DEFAULT '[]'",
    )
    add_column_if_missing(
        cursor,
        "scans",
        "ip_address",
        "ip_address TEXT",
        "ip_address TEXT",
    )

    cursor.execute("UPDATE scans SET detected_features = '[]' WHERE detected_features IS NULL")

    connection.commit()
    connection.close()

    active_database = "PostgreSQL" if is_postgres_enabled() else "SQLite"
    print(f"Database initialized successfully using {active_database}.")


if __name__ == "__main__":
    initialize_database()
