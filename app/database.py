import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vault.db"

def get_connection(db_path: str = None):
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = None):
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pengguna (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            dibuat_pada TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entri (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_terenkripsi TEXT NOT NULL,
            email TEXT,
            provider TEXT NOT NULL,
            url TEXT,
            keterangan TEXT,
            dibuat_pada TEXT NOT NULL,
            diubah_pada TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()
