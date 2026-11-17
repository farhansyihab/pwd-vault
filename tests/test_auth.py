import time

import pytest
from fastapi import HTTPException
from httpx import AsyncClient, ASGITransport

import app.auth as auth_module
import app.database as database
from app.auth import (
    authenticate_user,
    check_rate_limit,
    record_failed_attempt,
    reset_failed_attempts,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_DURATION,
)
from app.config import Settings
from app.main import create_app
from app.security import hash_password

USERNAME = "pengguna-uji"
PASSWORD = "password-palsu-123"
GENERIC_LOGIN_ERROR = "Username atau password salah."
# Tes memakai batas bawah n yang diterima verify_password agar cepat
FAST = {"n": 16384, "r": 8, "p": 1}


@pytest.fixture
def app(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "FERNET_KEY=password-palsu-key\nSESSION_SECRET=password-palsu-secret\n"
    )
    settings = Settings(env_path=str(env_file))

    # Database sementara: vault.db asli tidak tersentuh
    db_file = tmp_path / "vault.db"
    monkeypatch.setattr(database, "DEFAULT_DB_PATH", db_file)
    database.init_db()

    # Hash palsu cepat untuk username yang tidak ada
    monkeypatch.setattr(
        auth_module, "_dummy_hash_cache", hash_password("dummy-password-palsu", **FAST)
    )
    reset_failed_attempts()

    return create_app(settings)


def _buat_pengguna(username=USERNAME, password=PASSWORD):
    conn = database.get_connection()
    conn.execute(
        "INSERT INTO pengguna (username, password_hash, dibuat_pada) VALUES (?, ?, ?)",
        (username, hash_password(password, **FAST), "2026-11-17T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()


async def _login(client, username=USERNAME, password=PASSWORD):
    return await client.post(
        "/auth/login", data={"username": username, "password": password}
    )


@pytest.mark.anyio
async def test_login_berhasil(app):
    _buat_pengguna()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await _login(client)
        assert resp.status_code == 200

        saya = await client.get("/auth/saya")
        assert saya.status_code == 200
        assert saya.json()["username"] == USERNAME


@pytest.mark.anyio
async def test_login_password_salah(app):
    _buat_pengguna()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await _login(client, password="password-salah-palsu")
        assert resp.status_code == 401
        assert resp.json()["detail"] == GENERIC_LOGIN_ERROR


@pytest.mark.anyio
async def test_login_username_tidak_ada(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await _login(client, username="tidak-ada-palsu")
        assert resp.status_code == 401
        assert resp.json()["detail"] == GENERIC_LOGIN_ERROR


@pytest.mark.anyio
async def test_verify_password_tetap_dipanggil_untuk_username_tidak_ada(app, monkeypatch):
    panggilan = []
    asli = auth_module.verify_password

    def spy(password, stored_hash):
        panggilan.append(stored_hash)
        return asli(password, stored_hash)

    monkeypatch.setattr(auth_module, "verify_password", spy)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await _login(client, username="tidak-ada-palsu")

    assert resp.status_code == 401
    assert len(panggilan) == 1  # scrypt tetap dijalankan terhadap hash palsu


@pytest.mark.anyio
async def test_logout_menghapus_sesi(app):
    _buat_pengguna()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await _login(client)).status_code == 200
        assert (await client.get("/auth/saya")).status_code == 200

        assert (await client.post("/auth/logout")).status_code == 200
        assert (await client.get("/auth/saya")).status_code == 401


@pytest.mark.anyio
async def test_akses_tanpa_login_ditolak(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/auth/saya")
        assert resp.status_code == 401


@pytest.mark.anyio
async def test_terkunci_setelah_lima_gagal_dan_tanpa_scrypt(app, monkeypatch):
    _buat_pengguna()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(MAX_FAILED_ATTEMPTS):
            resp = await _login(client, password="password-salah-palsu")
            assert resp.status_code == 401

        # Percobaan ke-6 (walau password benar) harus 429 tanpa menjalankan scrypt
        panggilan = []
        monkeypatch.setattr(
            auth_module, "verify_password", lambda p, h: panggilan.append(1) or False
        )
        resp = await _login(client)
        assert resp.status_code == 429
        assert panggilan == []


def test_percobaan_saat_terkunci_tidak_memperpanjang_kunci():
    reset_failed_attempts()
    clock = [1000.0]

    for _ in range(MAX_FAILED_ATTEMPTS):
        record_failed_attempt(lambda: clock[0])

    lock_before = auth_module._lockout_until
    with pytest.raises(HTTPException) as exc:
        check_rate_limit(lambda: clock[0] + 1)
    assert exc.value.status_code == 429

    # Percobaan saat terkunci tidak memperpanjang
    clock[0] += 1
    record_failed_attempt(lambda: clock[0])
    assert auth_module._lockout_until == lock_before

    # Setelah masa kunci habis, login diperbolehkan lagi dan hitungan mulai dari nol
    check_rate_limit(lambda: lock_before + 1)
    assert auth_module._failed_attempts == 0
    assert auth_module._lockout_until == 0.0

    # Satu kegagalan baru tidak langsung mengunci ulang
    record_failed_attempt(lambda: lock_before + 2)
    assert auth_module._failed_attempts == 1
    check_rate_limit(lambda: lock_before + 2)


def test_login_sukses_mereset_penghitung(app):
    _buat_pengguna()
    reset_failed_attempts()
    clock = lambda: 2000.0

    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        record_failed_attempt(clock)
    assert auth_module._failed_attempts == MAX_FAILED_ATTEMPTS - 1

    user = authenticate_user(USERNAME, PASSWORD, monotonic_fn=clock)
    assert user is not None
    assert auth_module._failed_attempts == 0
    assert auth_module._lockout_until == 0.0


@pytest.mark.anyio
async def test_login_menolak_password_terlalu_panjang(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await _login(client, password="x" * 129)
        assert resp.status_code == 400


@pytest.mark.anyio
async def test_wajib_login_mengecek_pengguna_masih_ada(app):
    _buat_pengguna()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await _login(client)).status_code == 200
        assert (await client.get("/auth/saya")).status_code == 200

        conn = database.get_connection()
        conn.execute("DELETE FROM pengguna")
        conn.commit()
        conn.close()

        # Sesi masih ada, tetapi pengguna sudah dihapus -> 401
        assert (await client.get("/auth/saya")).status_code == 401