"""Tests for the random password generator endpoint (Tahap 8).

Covers:
- The endpoint requires authentication.
- Default output length is 16 and the returned ``panjang`` matches.
- Custom length is honored; out-of-range lengths return 422.
- Disabling all character classes returns 400.
- Individual character classes are honored when the others are disabled.
- When multiple classes are enabled, every class appears at least once.
- Two consecutive calls produce different passwords (sanity check on
  randomness).
- Non-integer length returns 422.
"""
import string

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def test_settings(tmp_path):
    from app.config import Settings

    env_file = tmp_path / "test.env"
    env_file.write_text(
        f"FERNET_KEY={Fernet.generate_key().decode()}\n"
        "SESSION_SECRET=test-session-secret-abcdef-1234567890\n",
        encoding="utf-8",
    )
    return Settings(env_path=str(env_file))


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_vault.db"
    monkeypatch.setattr("app.database.DEFAULT_DB_PATH", db_path)
    return db_path


@pytest.fixture
def app_instance(test_settings, test_db, monkeypatch):
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
    """Client with a logged-in user (reduced scrypt cost for speed)."""
    from datetime import datetime, timezone

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


def test_password_acak_tanpa_login(client):
    r = client.get("/alat/password-acak")
    assert r.status_code == 401


def test_password_acak_default(auth_client):
    r = auth_client.get("/alat/password-acak")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["panjang"] == 16
    assert len(data["password"]) == 16


def test_password_acak_panjang_custom(auth_client):
    r = auth_client.get("/alat/password-acak", params={"panjang": 32})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["panjang"] == 32
    assert len(data["password"]) == 32


def test_password_acak_panjang_terlalu_pendek(auth_client):
    r = auth_client.get("/alat/password-acak", params={"panjang": 4})
    assert r.status_code == 422


def test_password_acak_panjang_terlalu_panjang(auth_client):
    r = auth_client.get("/alat/password-acak", params={"panjang": 500})
    assert r.status_code == 422


def test_password_acak_panjang_bukan_integer(auth_client):
    r = auth_client.get("/alat/password-acak", params={"panjang": "abc"})
    assert r.status_code == 422


def test_password_acak_semua_jenis_nonaktif(auth_client):
    r = auth_client.get(
        "/alat/password-acak",
        params={
            "huruf_kecil": "false",
            "huruf_besar": "false",
            "angka": "false",
            "simbol": "false",
        },
    )
    assert r.status_code == 400


def test_password_acak_hanya_huruf_kecil(auth_client):
    r = auth_client.get(
        "/alat/password-acak",
        params={
            "panjang": 24,
            "huruf_kecil": "true",
            "huruf_besar": "false",
            "angka": "false",
            "simbol": "false",
        },
    )
    assert r.status_code == 200, r.text
    pw = r.json()["password"]
    assert len(pw) == 24
    assert all(c in string.ascii_lowercase for c in pw)


def test_password_acak_hanya_huruf_besar(auth_client):
    r = auth_client.get(
        "/alat/password-acak",
        params={
            "panjang": 24,
            "huruf_kecil": "false",
            "huruf_besar": "true",
            "angka": "false",
            "simbol": "false",
        },
    )
    assert r.status_code == 200, r.text
    pw = r.json()["password"]
    assert all(c in string.ascii_uppercase for c in pw)


def test_password_acak_hanya_angka(auth_client):
    r = auth_client.get(
        "/alat/password-acak",
        params={
            "panjang": 20,
            "huruf_kecil": "false",
            "huruf_besar": "false",
            "angka": "true",
            "simbol": "false",
        },
    )
    assert r.status_code == 200, r.text
    pw = r.json()["password"]
    assert all(c in string.digits for c in pw)


def test_password_acak_hanya_simbol(auth_client):
    r = auth_client.get(
        "/alat/password-acak",
        params={
            "panjang": 12,
            "huruf_kecil": "false",
            "huruf_besar": "false",
            "angka": "false",
            "simbol": "true",
        },
    )
    assert r.status_code == 200, r.text
    pw = r.json()["password"]
    assert len(pw) == 12
    assert all(not c.isalnum() for c in pw)


def test_password_acak_setiap_jenis_terwakili(auth_client):
    """Each enabled character class must appear at least once."""
    r = auth_client.get("/alat/password-acak", params={"panjang": 16})
    assert r.status_code == 200, r.text
    pw = r.json()["password"]
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.ascii_uppercase for c in pw)
    assert any(c in string.digits for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_password_acak_panjang_minimal(auth_client):
    r = auth_client.get("/alat/password-acak", params={"panjang": 8})
    assert r.status_code == 200, r.text
    assert len(r.json()["password"]) == 8


def test_password_acak_acak_berbeda(auth_client):
    """Two consecutive calls should produce different passwords
    (collision probability is astronomically small)."""
    r1 = auth_client.get("/alat/password-acak")
    r2 = auth_client.get("/alat/password-acak")
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["password"] != r2.json()["password"]