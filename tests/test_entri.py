"""Tests for entry (entri) endpoints: create, list, and view a single entry.

Covers:
- All entry endpoints require authentication.
- Creating an entry stores an encrypted password (verified by reading the
  database directly and decrypting).
- Listing and detail endpoints never leak the password.
"""
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def test_settings(tmp_path):
    """Settings with a throwaway Fernet key and session secret."""
    from app.config import Settings

    env_file = tmp_path / "test.env"
    fernet_key = Fernet.generate_key().decode()
    session_secret = "test-session-secret-abcdef-1234567890"
    env_file.write_text(
        f"FERNET_KEY={fernet_key}\nSESSION_SECRET={session_secret}\n",
        encoding="utf-8",
    )
    return Settings(env_path=str(env_file))


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Point the app's default SQLite path to a per-test temp file."""
    db_path = tmp_path / "test_vault.db"
    monkeypatch.setattr("app.database.DEFAULT_DB_PATH", db_path)
    return db_path


@pytest.fixture
def app_instance(test_settings, test_db, monkeypatch):
    """Build the FastAPI app with test settings and a clean auth rate-limiter."""
    import app.auth as auth_module
    import app.config as config_module
    from app.main import create_app

    monkeypatch.setattr(config_module, "_settings", test_settings)
    auth_module.reset_failed_attempts()

    return create_app(settings=test_settings)


@pytest.fixture
def client(app_instance):
    from fastapi.testclient import TestClient

    with TestClient(app_instance) as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Client fixture that has created a user and logged in.

    Uses reduced scrypt parameters (still within the accepted range) to keep
    the tests fast; this only affects test speed, not the tested behavior.
    """
    from app.database import get_connection
    from app.security import hash_password

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO pengguna (username, password_hash, dibuat_pada) "
            "VALUES (?, ?, ?)",
            (
                "testuser",
                hash_password("test-password-palsu-123", n=2**14),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    r = client.post(
        "/auth/login",
        data={"username": "testuser", "password": "test-password-palsu-123"},
    )
    assert r.status_code == 200, r.text
    return client


# ---------------------------------------------------------------------------
# Auth requirement
# ---------------------------------------------------------------------------

def test_tambah_entri_tanpa_login(client):
    r = client.post(
        "/entri",
        json={"username": "user", "password": "rahasia-palsu", "provider": "contoh"},
    )
    assert r.status_code == 401


def test_daftar_entri_tanpa_login(client):
    r = client.get("/entri")
    assert r.status_code == 401


def test_lihat_entri_tanpa_login(client):
    r = client.get("/entri/1")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Create entry
# ---------------------------------------------------------------------------

def test_tambah_entri_berhasil(auth_client):
    r = auth_client.post(
        "/entri",
        json={
            "username": "user@contoh.example",
            "password": "password-palsu-123",
            "email": "user@contoh.example",
            "provider": "contoh",
            "url": "https://contoh.example",
            "keterangan": "akun uji",
        },
    )
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["id"] >= 1
    assert data["username"] == "user@contoh.example"
    assert data["provider"] == "contoh"
    assert data["email"] == "user@contoh.example"
    assert data["url"] == "https://contoh.example"
    assert data["keterangan"] == "akun uji"
    assert data["dibuat_pada"]
    assert data["diubah_pada"]
    # Must not leak the password in the response.
    assert "password" not in data
    assert "password_terenkripsi" not in data


def test_tambah_entri_tanpa_field_wajib(auth_client):
    r = auth_client.post("/entri", json={"username": "user"})
    assert r.status_code == 422


def test_tambah_entri_dengan_field_opsional_kosong(auth_client):
    r = auth_client.post(
        "/entri",
        json={
            "username": "user",
            "password": "password-palsu-999",
            "provider": "contoh",
        },
    )
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["email"] is None
    assert data["url"] is None
    assert data["keterangan"] is None


# ---------------------------------------------------------------------------
# List entries
# ---------------------------------------------------------------------------

def test_daftar_entri_kosong(auth_client):
    r = auth_client.get("/entri")
    assert r.status_code == 200
    assert r.json() == []


def test_daftar_entri_berisi_dan_tanpa_password(auth_client):
    for i in (1, 2):
        r = auth_client.post(
            "/entri",
            json={
                "username": f"user-{i}",
                "password": f"password-palsu-{i}",
                "provider": f"provider-{i}",
            },
        )
        assert r.status_code == 201, r.text

    r = auth_client.get("/entri")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 2
    for item in items:
        assert "password" not in item
        assert "password_terenkripsi" not in item
        assert item["id"] >= 1
        assert item["provider"].startswith("provider-")


# ---------------------------------------------------------------------------
# View single entry
# ---------------------------------------------------------------------------

def test_lihat_entri_berhasil(auth_client):
    r = auth_client.post(
        "/entri",
        json={
            "username": "user-1",
            "password": "password-palsu-1",
            "provider": "provider-1",
            "keterangan": "catatan",
        },
    )
    entri_id = r.json()["id"]

    r = auth_client.get(f"/entri/{entri_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == entri_id
    assert data["username"] == "user-1"
    assert data["provider"] == "provider-1"
    assert data["keterangan"] == "catatan"
    assert "password" not in data
    assert "password_terenkripsi" not in data


def test_lihat_entri_tidak_ada(auth_client):
    r = auth_client.get("/entri/999999")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Encryption at rest
# ---------------------------------------------------------------------------

def test_database_menyimpan_password_terenkripsi(auth_client, test_db):
    """The plaintext password must NOT be stored as-is in the database,
    and the stored ciphertext must decrypt back to the original plaintext."""
    from app.database import get_connection
    from app.security import decrypt_entry_password

    plaintext = "rahasia-palsu-987"
    r = auth_client.post(
        "/entri",
        json={
            "username": "user-enc",
            "password": plaintext,
            "provider": "contoh",
        },
    )
    assert r.status_code == 201, r.text
    entri_id = r.json()["id"]

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_terenkripsi FROM entri WHERE id = ?",
            (entri_id,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    stored = row["password_terenkripsi"]
    assert stored is not None
    assert stored != plaintext
    assert plaintext not in stored
    assert decrypt_entry_password(stored) == plaintext