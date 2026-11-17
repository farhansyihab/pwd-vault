"""Tests for entry (entri) endpoints: create, list, view, update, delete,
reveal password, and search.

Covers:
- All entry endpoints require authentication.
- Creating an entry stores an encrypted password (verified by reading the
  database directly and decrypting).
- Listing and detail endpoints never leak the password.
- Updating an entry: full/partial update, password re-encryption only when
  provided, timestamp handling, 404 for missing entries.
- Deleting an entry: removes the row, subsequent GET returns 404, 404 for
  missing entries.
- Revealing the password: returns the plaintext only via the dedicated
  endpoint, requires login, 404 for missing entries, and does not leak
  the password through list/detail endpoints.
- Searching entries: by provider, by username, case-insensitive, no
  matches, empty q, literal wildcard characters.
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


def test_ubah_entri_tanpa_login(client):
    r = client.put("/entri/1", json={"username": "user"})
    assert r.status_code == 401


def test_hapus_entri_tanpa_login(client):
    r = client.delete("/entri/1")
    assert r.status_code == 401


def test_lihat_password_tanpa_login(client):
    r = client.get("/entri/1/password")
    assert r.status_code == 401


def test_cari_entri_tanpa_login(client):
    r = client.get("/entri?q=gmail")
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
# Update entry
# ---------------------------------------------------------------------------

def test_ubah_entri_tidak_ada(auth_client):
    r = auth_client.put("/entri/999999", json={"username": "user"})
    assert r.status_code == 404


def test_ubah_entri_field_kosong_ditolak(auth_client):
    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": "password-palsu-1", "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.put(f"/entri/{entri_id}", json={"username": ""})
    assert r.status_code == 422


def test_ubah_entri_semua_field(auth_client):
    r = auth_client.post(
        "/entri",
        json={
            "username": "user-lama",
            "password": "password-lama-palsu",
            "email": "lama@contoh.example",
            "provider": "provider-lama",
            "url": "https://lama.example",
            "keterangan": "keterangan lama",
        },
    )
    entri_id = r.json()["id"]

    r = auth_client.put(
        f"/entri/{entri_id}",
        json={
            "username": "user-baru",
            "password": "password-baru-palsu",
            "email": "baru@contoh.example",
            "provider": "provider-baru",
            "url": "https://baru.example",
            "keterangan": "keterangan baru",
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["id"] == entri_id
    assert data["username"] == "user-baru"
    assert data["email"] == "baru@contoh.example"
    assert data["provider"] == "provider-baru"
    assert data["url"] == "https://baru.example"
    assert data["keterangan"] == "keterangan baru"
    assert "password" not in data
    assert "password_terenkripsi" not in data


def test_ubah_entri_sebagian_field(auth_client):
    r = auth_client.post(
        "/entri",
        json={
            "username": "user-tetap",
            "password": "password-tetap-palsu",
            "email": "tetap@contoh.example",
            "provider": "provider-lama",
        },
    )
    entri_id = r.json()["id"]

    r = auth_client.put(f"/entri/{entri_id}", json={"provider": "provider-baru"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["provider"] == "provider-baru"
    assert data["username"] == "user-tetap"
    assert data["email"] == "tetap@contoh.example"


def test_ubah_entri_password_baru_terenkripsi(auth_client, test_db):
    from app.database import get_connection
    from app.security import decrypt_entry_password

    plaintext_lama = "password-lama-palsu"
    plaintext_baru = "password-baru-palsu"

    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": plaintext_lama, "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.put(f"/entri/{entri_id}", json={"password": plaintext_baru})
    assert r.status_code == 200, r.text

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
    assert stored != plaintext_baru
    assert plaintext_baru not in stored
    assert decrypt_entry_password(stored) == plaintext_baru


def test_ubah_entri_tanpa_password_password_tetap(auth_client, test_db):
    from app.database import get_connection
    from app.security import decrypt_entry_password

    plaintext = "password-tetap-palsu"

    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": plaintext, "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.put(f"/entri/{entri_id}", json={"provider": "p-baru"})
    assert r.status_code == 200, r.text

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

    assert decrypt_entry_password(row["password_terenkripsi"]) == plaintext


def test_ubah_entri_password_null_tidak_mengubah(auth_client, test_db):
    """Sending password: null is treated as 'do not change password'."""
    from app.database import get_connection
    from app.security import decrypt_entry_password

    plaintext = "password-null-palsu"

    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": plaintext, "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.put(f"/entri/{entri_id}", json={"password": None})
    assert r.status_code == 200, r.text

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

    assert decrypt_entry_password(row["password_terenkripsi"]) == plaintext


def test_ubah_entri_timestamp(auth_client):
    import time

    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": "password-palsu-1", "provider": "p"},
    )
    data = r.json()
    entri_id = data["id"]
    dibuat_awal = data["dibuat_pada"]
    diubah_awal = data["diubah_pada"]

    time.sleep(0.001)

    r = auth_client.put(f"/entri/{entri_id}", json={"provider": "p-baru"})
    assert r.status_code == 200, r.text
    data2 = r.json()
    assert data2["dibuat_pada"] == dibuat_awal
    assert data2["diubah_pada"] > diubah_awal


# ---------------------------------------------------------------------------
# Delete entry
# ---------------------------------------------------------------------------

def test_hapus_entri_tidak_ada(auth_client):
    r = auth_client.delete("/entri/999999")
    assert r.status_code == 404


def test_hapus_entri_berhasil(auth_client):
    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": "password-palsu-1", "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.delete(f"/entri/{entri_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "sukses"
    assert str(entri_id) in body["pesan"]


def test_hapus_entri_menghapus_dari_db(auth_client, test_db):
    from app.database import get_connection

    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": "password-palsu-1", "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.delete(f"/entri/{entri_id}")
    assert r.status_code == 200, r.text

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS n FROM entri WHERE id = ?", (entri_id,))
        assert cursor.fetchone()["n"] == 0
    finally:
        conn.close()


def test_hapus_entri_lalu_get_404(auth_client):
    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": "password-palsu-1", "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.delete(f"/entri/{entri_id}")
    assert r.status_code == 200, r.text

    r = auth_client.get(f"/entri/{entri_id}")
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


# ---------------------------------------------------------------------------
# Reveal password (Tahap 7)
# ---------------------------------------------------------------------------

def test_lihat_password_berhasil(auth_client):
    plaintext = "rahasia-palsu-abc"
    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": plaintext, "provider": "p"},
    )
    assert r.status_code == 201, r.text
    entri_id = r.json()["id"]

    r = auth_client.get(f"/entri/{entri_id}/password")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["id"] == entri_id
    assert data["password"] == plaintext


def test_lihat_password_tidak_ada(auth_client):
    r = auth_client.get("/entri/999999/password")
    assert r.status_code == 404


def test_lihat_password_tidak_bocor_di_list_atau_detail(auth_client):
    """The plaintext must only appear via the dedicated reveal endpoint."""
    plaintext = "rahasia-palsu-xyz"
    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": plaintext, "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.get("/entri")
    assert r.status_code == 200
    for item in r.json():
        assert "password" not in item
        assert "password_terenkripsi" not in item
        assert plaintext not in str(item)

    r = auth_client.get(f"/entri/{entri_id}")
    assert r.status_code == 200
    assert "password" not in r.json()
    assert "password_terenkripsi" not in r.json()
    assert plaintext not in str(r.json())


def test_lihat_password_setelah_diubah(auth_client):
    """Reveal must return the NEW plaintext after an update."""
    plaintext_lama = "password-lama-palsu"
    plaintext_baru = "password-baru-palsu"

    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": plaintext_lama, "provider": "p"},
    )
    entri_id = r.json()["id"]

    r = auth_client.put(f"/entri/{entri_id}", json={"password": plaintext_baru})
    assert r.status_code == 200, r.text

    r = auth_client.get(f"/entri/{entri_id}/password")
    assert r.status_code == 200, r.text
    assert r.json()["password"] == plaintext_baru


def test_lihat_password_id_bukan_integer(auth_client):
    r = auth_client.get("/entri/bukan-angka/password")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Search (Tahap 7)
# ---------------------------------------------------------------------------

def _seed_entries(auth_client):
    entries = [
        {"username": "alice@contoh.example", "password": "pw-1", "provider": "gmail"},
        {"username": "bob@contoh.example", "password": "pw-2", "provider": "github"},
        {"username": "charlie", "password": "pw-3", "provider": "gitlab"},
    ]
    ids = []
    for e in entries:
        r = auth_client.post("/entri", json=e)
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    return ids


def test_cari_entri_by_provider(auth_client):
    _seed_entries(auth_client)
    r = auth_client.get("/entri", params={"q": "git"})
    assert r.status_code == 200
    items = r.json()
    providers = {i["provider"] for i in items}
    assert providers == {"github", "gitlab"}
    for item in items:
        assert "password" not in item


def test_cari_entri_by_username(auth_client):
    _seed_entries(auth_client)
    r = auth_client.get("/entri", params={"q": "alice"})
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["username"].startswith("alice")


def test_cari_entri_case_insensitive(auth_client):
    _seed_entries(auth_client)
    r = auth_client.get("/entri", params={"q": "GMAIL"})
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["provider"] == "gmail"


def test_cari_entri_tidak_ketemu(auth_client):
    _seed_entries(auth_client)
    r = auth_client.get("/entri", params={"q": "tidak-ada-yang-cocok"})
    assert r.status_code == 200
    assert r.json() == []


def test_cari_entri_q_kosong_kembalikan_semua(auth_client):
    _seed_entries(auth_client)
    r = auth_client.get("/entri", params={"q": ""})
    assert r.status_code == 200
    assert len(r.json()) == 3


def test_cari_entri_tanpa_q_kembalikan_semua(auth_client):
    _seed_entries(auth_client)
    r = auth_client.get("/entri")
    assert r.status_code == 200
    assert len(r.json()) == 3


def test_cari_entri_persen_diiteral(auth_client):
    """A literal '%' in q must NOT act as a wildcard."""
    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": "pw", "provider": "persen%provider"},
    )
    assert r.status_code == 201, r.text

    r = auth_client.post(
        "/entri",
        json={"username": "user2", "password": "pw", "provider": "lain"},
    )
    assert r.status_code == 201, r.text

    r = auth_client.get("/entri", params={"q": "%"})
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["provider"] == "persen%provider"


def test_cari_entri_underscore_diiteral(auth_client):
    """A literal '_' in q must NOT act as a single-character wildcard."""
    r = auth_client.post(
        "/entri",
        json={"username": "user", "password": "pw", "provider": "provider_1"},
    )
    assert r.status_code == 201, r.text

    r = auth_client.post(
        "/entri",
        json={"username": "user2", "password": "pw", "provider": "providerX1"},
    )
    assert r.status_code == 201, r.text

    r = auth_client.get("/entri", params={"q": "_"})
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    assert items[0]["provider"] == "provider_1"


def test_cari_entri_q_terlalu_panjang(auth_client):
    """q longer than the allowed max_length returns 422."""
    r = auth_client.get("/entri", params={"q": "x" * 101})
    assert r.status_code == 422