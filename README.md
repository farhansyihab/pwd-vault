# 🔐 pwd-vault

Aplikasi manajemen password (password vault) **lokal** yang dibangun dengan **FastAPI**, **SQLite**, dan enkripsi **Fernet**. Dirancang untuk dijalankan di komputer pribadi (`127.0.0.1`) sebagai tempat penyimpanan kredensial yang aman.

---

## ✨ Fitur

- **Autentikasi pengguna** — login/logout berbasis session cookie
- **Rate limiting / lockout** — akun terkunci **5 menit** setelah **5 kali** gagal login berturut-turut
- **Enkripsi password at-rest** — password entri dienkripsi dengan **Fernet** (AES-128-CBC + HMAC-SHA256)
- **Hashing password pengguna** — **scrypt** dengan salt acak (n=2¹⁷, r=8, p=1)
- **CRUD entri** — tambah, lihat, ubah (partial update), hapus
- **Reveal password** — endpoint khusus `GET /entri/{id}/password` untuk menampilkan plaintext (hanya setelah login)
- **Pencarian** — cari entri berdasarkan `provider` atau `username` (case-insensitive, wildcard di-*escape*)
- **Generator password acak** — berbasis `secrets`, dijamin setiap kelas karakter yang aktif muncul minimal satu kali
- **Anti timing attack** — verifikasi terhadap *dummy hash* saat username tidak ditemukan

---

## 📋 Prasyarat

- **Python 3.10+**
- `pip`
- Sistem operasi Linux/macOS/Windows

---

## 🚀 Instalasi Awal

### 1. Masuk ke direktori proyek

```bash
cd pwd-vault/
```

### 2. Buat & aktifkan virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# atau
.venv\Scripts\activate           # Windows (PowerShell / CMD)
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" cryptography python-multipart \
            pytest httpx anyio
```

> 💡 Disarankan membuat `requirements.txt` agar instalasi reproducible:
>
> ```bash
> pip freeze > requirements.txt
> ```
>
> Lalu di masa depan cukup jalankan `pip install -r requirements.txt`.

### 4. Buat file konfigurasi `.env`

```bash
python scripts/buat_env.py
```

Skrip ini akan:
- Membuat file `.env` dengan permission **`0o600`** (hanya *owner* yang bisa baca/tulis)
- Menolak menimpa file `.env` yang sudah ada (memakai `O_EXCL`)
- Mengisi dua variabel:

```
FERNET_KEY=<kunci-fernet-base64>
SESSION_SECRET=<hex-64-karakter>
```

> ⚠️ **Penting:** File `.env` berisi kunci enkripsi dan *secret* sesi. **Jangan pernah commit file ini**. Pastikan `.gitignore` memuat `.env` dan `data/`.

### 5. Inisialisasi database & buat pengguna

```bash
python scripts/buat_pengguna.py
```

Skrip ini akan:
- Menjalankan `init_db()` (membuat `data/vault.db` + tabel `pengguna` & `entri`)
- Meminta **username** dan **password** (minimal **12 karakter**)
- Menyimpan hash scrypt ke database

> ⚠️ Jalankan dari **root proyek** agar import `app.*` berhasil. Jika perlu, atur `PYTHONPATH`:
>
> ```bash
> export PYTHONPATH="$PWD:$PYTHONPATH"    # Linux/macOS
> set PYTHONPATH=%CD%;%PYTHONPATH%       # Windows CMD
> ```

---

## ▶️ Menjalankan Aplikasi

Gunakan `uvicorn` dengan flag `--factory` karena `app.main` mengekspos **factory function** `create_app()`:

```bash
uvicorn app.main:create_app --factory --reload --host 127.0.0.1 --port 8000
```

Atau tanpa `--reload` (lebih ringan untuk pemakaian sehari-hari):

```bash
uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
```

Setelah server berjalan:

| URL | Keterangan |
|-----|------------|
| http://127.0.0.1:8000 | Root API |
| http://127.0.0.1:8000/docs | **Swagger UI** (dokumentasi interaktif) |
| http://127.0.0.1:8000/redoc | ReDoc |
| http://127.0.0.1:8000/health | Health check → `{"status":"ok"}` |

### Catatan runtime

- Server di-*bind* ke `127.0.0.1` → **hanya bisa diakses dari komputer lokal**.
- Session cookie bernama `pwd_vault_session`, berlaku maksimal **1 jam** (`3600` detik), dengan `SameSite=Strict`.
- HTTPS **tidak** diaktifkan (`https_only=False`) karena targetnya localhost.

---

## 🧪 Menjalankan Test

Seluruh test berada di `tests/` dan menggunakan **pytest**.

### Jalankan semua test

```bash
pytest -v
```

### Jalankan file test tertentu

```bash
pytest tests/test_security.py -v     # hashing & enkripsi Fernet
pytest tests/test_auth.py -v         # login, rate limit, sesi
pytest tests/test_entri.py -v        # CRUD entri & enkripsi at-rest
pytest tests/test_alat.py -v         # generator password acak
pytest tests/test_config_db.py -v    # parser .env & skema DB
pytest tests/test_health.py -v       # endpoint /health
```

### Catatan test

- Test menggunakan **SQLite sementara** via `tmp_path`, sehingga `data/vault.db` **tidak tersentuh**.
- Hash scrypt diperkecil ke `n=2^14` (batas bawah yang tetap diterima `verify_password`) supaya test cepat.
- Test async memakai `httpx.AsyncClient` + `ASGITransport` (butuh plugin `anyio`).
- State rate limiter global (`_failed_attempts`, `_lockout_until`) di-reset di setiap fixture agar test tidak saling memengaruhi.

---

## 📁 Struktur Proyek

```
pwd-vault/
├── app/
│   ├── main.py              # Application factory + SessionMiddleware
│   ├── config.py            # Parsing & validasi .env
│   ├── database.py          # Koneksi SQLite + init_db()
│   ├── auth.py              # Login, rate limit, dependency wajib_login
│   ├── security.py          # scrypt + Fernet
│   ├── models.py            # Pydantic schemas
│   └── routers/
│       ├── auth.py          # /auth/*
│       ├── entri.py         # /entri/*
│       └── alat.py          # /alat/*
├── scripts/
│   ├── buat_env.py          # Generator .env (sekali pakai)
│   └── buat_pengguna.py     # Pembuat pengguna (sekali per user)
├── tests/                   # Unit & integration test
├── data/
│   └── vault.db             # SQLite (dibuat otomatis)
└── .env                     # ⚠️ KONFIDENSIAL — jangan di-commit
```

---

## 🌐 Ringkasan Endpoint API

| Method | Path | Auth | Deskripsi |
|--------|------|:----:|-----------|
| `POST`   | `/auth/login`            | ❌ | Login (form: `username`, `password`) |
| `POST`   | `/auth/logout`           | ❌ | Logout (hapus sesi) |
| `GET`    | `/auth/saya`             | ✅ | Info pengguna saat ini |
| `GET`    | `/entri`                 | ✅ | Daftar entri (+ `?q=` untuk search) |
| `POST`   | `/entri`                 | ✅ | Tambah entri baru |
| `GET`    | `/entri/{id}`            | ✅ | Lihat detail entri (**tanpa** password) |
| `PUT`    | `/entri/{id}`            | ✅ | Ubah entri (partial update) |
| `DELETE` | `/entri/{id}`            | ✅ | Hapus entri |
| `GET`    | `/entri/{id}/password`   | ✅ | **Reveal** password asli (terdekripsi) |
| `GET`    | `/alat/password-acak`    | ✅ | Generator password acak |
| `GET`    | `/health`                | ❌ | Health check |

Contoh pemakaian (`curl`) setelah login:

```bash
# Login (simpan cookie)
curl -c cookies.txt -X POST http://127.0.0.1:8000/auth/login \
     -d "username=admin&password=rahasia-panjang-123"

# Tambah entri
curl -b cookies.txt -X POST http://127.0.0.1:8000/entri \
     -H "Content-Type: application/json" \
     -d '{"username":"me@contoh.example","password":"rahasia123","provider":"contoh"}'

# Reveal password entri id=1
curl -b cookies.txt http://127.0.0.1:8000/entri/1/password
```

---

## 🔒 Catatan Keamanan (Tahap 9 — Tinjauan Akhir)

Sebelum memakai di lingkungan nyata, perhatikan:

1. **`.gitignore`** wajib memuat minimal:
   ```
   .env
   data/
   .venv/
   __pycache__/
   *.pyc
   .pytest_cache/
   ```
   File `.env` berisi `FERNET_KEY` & `SESSION_SECRET`; `data/vault.db` berisi data terenkripsi (jangan sampai ikut ter-commit).

2. **Password plaintext** hanya dikembalikan oleh endpoint `GET /entri/{id}/password`. Endpoint list/detail/update **tidak** menyertakan field password.

3. **Enkripsi at-rest**: ciphertext Fernet di database tidak pernah muncul di response API.

4. **Hashing scrypt** dengan salt acak per password. Format: `scrypt$n$r$p$salt$hash`. Verifikasi memakai `hmac.compare_digest` (constant-time).

5. **Anti timing attack**: username yang tidak ditemukan tetap memicu `verify_password` terhadap *dummy hash* agar waktu respons seragam.

6. **Error dekripsi generik**: tidak pernah membocorkan ciphertext, kunci, atau stack trace ke pemanggil.

7. **Pencarian aman**: karakter `%`, `_`, dan `\` di input user di-*escape* dan dipakai dengan klausa `ESCAPE '\'` di SQL `LIKE`.

8. **Parameter scrypt dibatasi**: `verify_password` menolak `n` di luar `[2^14, 2^20]` (harus pangkat 2) dan `r`/`p` di luar `[1, 32]` untuk mencegah DoS lewat hash berbahaya.

9. **Backup `.env`**: kehilangan `FERNET_KEY` = **semua password terenkripsi tidak dapat dipulihkan**. Simpan salinan aman (mis. password manager terpisah atau kertas di tempat aman).

10. **Jika hendak di-deploy publik** (di luar localhost):
    - Aktifkan HTTPS (`https_only=True`) + reverse proxy (nginx / Caddy).
    - Ganti session store ke server-side (Redis) bila multi-instance.
    - Pertimbangkan menambahkan 2FA.
    - Batasi akses jaringan (firewall / VPN).

---

## ⚠️ Peringatan

`pwd-vault` ditujukan untuk **penggunaan pribadi di localhost**. Jangan menjalankan server ini di `0.0.0.0` atau membukanya ke jaringan publik tanpa langkah pengamanan tambahan di atas.

---

## 📄 Lisensi

Proyek internal — belum ditentukan. Hubungi pemilik repo untuk detail.




