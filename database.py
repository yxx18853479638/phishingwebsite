import sqlite3


# Name of the SQLite database file.
DATABASE_NAME = "phishing_platform.db"


# SQL commands used to create the project tables.
CREATE_ADMINS_TABLE = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    submitted_url TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    score INTEGER NOT NULL,
    explanations TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    ip_address TEXT,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""


CREATE_ACTIVITY_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action_type TEXT NOT NULL,
    action_details TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admins(id)
);
"""


# Put all table creation statements into one list
# so they can be executed one by one.
TABLES = [
    CREATE_ADMINS_TABLE,
    CREATE_USERS_TABLE,
    CREATE_SCANS_TABLE,
    CREATE_ACTIVITY_LOGS_TABLE,
]



def create_connection():
    """Create and return a connection to the SQLite database."""
    connection = sqlite3.connect(DATABASE_NAME)
    return connection



def initialize_database():
    """Create all database tables if they do not already exist."""
    connection = create_connection()
    cursor = connection.cursor()

    for table_sql in TABLES:
        cursor.execute(table_sql)

    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = [column[1] for column in cursor.fetchall()]

    if "user_id" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")

    if "ip_address" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN ip_address TEXT")

    connection.commit()
    connection.close()

    print("Database initialized successfully.")


if __name__ == "__main__":
    initialize_database()
