import os
import pytest
from app.config import Settings
from app.database import init_db, get_connection


def test_config_loading_and_repr(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("FERNET_KEY=password-palsu-key\nSESSION_SECRET=password-palsu-secret\n")

    s = Settings(env_path=str(env_file))
    assert s.fernet_key == "password-palsu-key"
    assert s.session_secret == "password-palsu-secret"

    repr_str = repr(s)
    assert "password-palsu-key" not in repr_str
    assert "password-palsu-secret" not in repr_str
    assert "[REDACTED]" in repr_str


def test_config_parser_keeps_equals_in_value(tmp_path):
    # Nilai yang berakhiran "=" (padding base64) harus utuh, tidak terpotong.
    env_file = tmp_path / ".env"
    env_file.write_text("FERNET_KEY=abc==123==\nSESSION_SECRET=def=456=\n")

    s = Settings(env_path=str(env_file))
    assert s.fernet_key == "abc==123=="
    assert s.session_secret == "def=456="


def test_config_raises_if_fernet_key_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("FERNET_KEY", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text("FERNET_KEY=\nSESSION_SECRET=password-palsu-secret\n")

    with pytest.raises(ValueError, match="FERNET_KEY"):
        Settings(env_path=str(env_file))


def test_config_raises_if_session_secret_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("FERNET_KEY", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    env_file = tmp_path / ".env"
    env_file.write_text("FERNET_KEY=password-palsu-key\nSESSION_SECRET=\n")

    with pytest.raises(ValueError, match="SESSION_SECRET"):
        Settings(env_path=str(env_file))


def test_config_raises_if_env_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        Settings(env_path=str(tmp_path / "tidak-ada.env"))


def test_database_init_and_schema(tmp_path):
    db_file = tmp_path / "subdir" / "test_vault.db"
    init_db(str(db_file))

    assert db_file.exists()

    conn = get_connection(str(db_file))
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row["name"] for row in cursor.fetchall()}
    assert "pengguna" in tables
    assert "entri" in tables

    cursor.execute("PRAGMA table_info(pengguna)")
    pengguna_cols = {row["name"] for row in cursor.fetchall()}
    assert {"id", "username", "password_hash", "dibuat_pada"}.issubset(pengguna_cols)

    cursor.execute("PRAGMA table_info(entri)")
    entri_cols = {row["name"] for row in cursor.fetchall()}
    assert {
        "id",
        "username",
        "password_terenkripsi",
        "email",
        "provider",
        "url",
        "keterangan",
        "dibuat_pada",
        "diubah_pada",
    }.issubset(entri_cols)

    conn.close()
