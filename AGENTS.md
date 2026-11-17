# PROJECT: Penyimpan Password Pribadi (pwd-vault)

---

# 1. RULES (wajib dipatuhi)

## Teknologi
- Lubuntu, Python 3.12, FastAPI, SQLite (modul `sqlite3` bawaan)
- Virtual environment di `.venv` dalam folder proyek
- Tanpa ORM
- Library yang sudah disetujui: `fastapi`, `uvicorn`, `pydantic`, `cryptography` (enkripsi Fernet), `itsdangerous` (cookie sesi), `python-multipart` (form login), `pytest`, `httpx` (untuk TestClient)
- Library lain: tanyakan dulu sebelum dipasang
- Hash password login memakai `hashlib.scrypt` bawaan Python, bukan library tambahan
- Menjalankan server dev: `uvicorn app.main:app --reload --host 127.0.0.1 --port 8001`

## Cara bekerja
- Di awal setiap tahap, jelaskan rencana dalam 3-5 kalimat, lalu tunggu kata "lanjut" dari saya sebelum menulis file
- Kerjakan satu tahap saja per giliran, sesuai bagian STATUS
- Tulis atau ubah file hanya di dalam folder proyek ini, dan jangan ubah file yang tidak relevan dengan tahap aktif
- Setelah menulis kode, jalankan `pytest` dan laporkan hasil sebenarnya (lulus atau gagal). Jangan menyatakan berhasil sebelum tes dijalankan
- Perintah shell yang mengubah sistem (instal paket, hapus file, pindah file) tampilkan dulu dan minta persetujuan saya. Jangan pakai `sudo`
- Jika ada pilihan desain, tawarkan 2 opsi beserta trade-off, lalu tunggu keputusan saya
- Jika permintaan kurang jelas atau bertentangan dengan SPEC, tanyakan dulu
- Di akhir tahap, ringkas hasilnya dan usulkan pembaruan untuk ARCHITECTURE dan STATUS. Ubah file ini hanya setelah saya menyatakan tahap lulus

## Keamanan dan kualitas
- Password entri disimpan terenkripsi (Fernet), tidak pernah sebagai teks biasa di database
- Kunci enkripsi dan kunci sesi dibaca dari file `.env`. Jangan menaruh kunci di kode, di log, atau di jawaban, dan jangan menampilkan isi `.env`
- `.env`, `data/*.db`, dan `.venv/` wajib masuk `.gitignore`
- Password akun login disimpan sebagai hash scrypt dengan salt acak, dibandingkan dengan `hmac.compare_digest`
- Semua input divalidasi dengan Pydantic
- Query database wajib parameterized, tidak boleh string formatting
- Daftar entri tidak boleh mengembalikan password. Password asli hanya lewat endpoint khusus setelah login
- Tangani error dengan pesan jelas, jangan biarkan stack trace sampai ke pengguna
- Server hanya mendengarkan `127.0.0.1`
- Tulis test pytest untuk setiap fitur baru. Data uji harus palsu (contoh: `password-palsu-123`), jangan pakai password sungguhan

---

# 2. SPEC (apa yang dibangun)

## Tujuan
Aplikasi web lokal (berbentuk API, dicoba lewat halaman `/docs` bawaan FastAPI) untuk menyimpan kredensial akun online. Dipakai satu pengguna, berjalan hanya di komputer sendiri. Proyek ini juga sarana saya belajar memakai Hermes Agent.

## Fitur
1. Login dan logout memakai sesi cookie. Akun tunggal dibuat lewat skrip CLI, bukan lewat web
2. Tambah, lihat, ubah, hapus entri dengan field: username, password, email, provider, url, keterangan
3. Field otomatis: id, dibuat_pada, diubah_pada
4. Semua endpoint entri hanya bisa diakses setelah login
5. Password disimpan terenkripsi. Password asli hanya bisa dilihat lewat endpoint khusus
6. Cari entri berdasarkan provider atau username
7. Batas percobaan login: 5 kali gagal berturut-turut mengunci login selama 5 menit
8. Pembuat password acak (memakai modul `secrets`)

## Di luar cakupan (jangan dikerjakan)
- Registrasi atau multi-pengguna lewat web
- Antarmuka HTML atau frontend
- Impor dan ekspor data
- Sinkronisasi cloud, deploy, akses dari luar localhost
- Autentikasi dua faktor
- Pemulihan password akun login

---

# 3. ARCHITECTURE (bagaimana disusun)

## Struktur folder
```
pwd-vault/
├── AGENTS.md
├── .env               # rahasia, tidak di-commit
├── .gitignore
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── main.py            # entry point FastAPI, daftar router, /health
│   ├── config.py          # baca .env
│   ├── database.py        # koneksi SQLite, pembuatan tabel
│   ├── models.py          # skema Pydantic
│   ├── security.py        # hash scrypt, enkripsi Fernet
│   ├── auth.py            # sesi, dependency wajib-login, batas percobaan
│   ├── buat_pengguna.py   # skrip CLI membuat akun login
│   └── routers/
│       ├── auth.py        # /auth/login, /auth/logout, /auth/saya
│       └── entri.py       # CRUD entri, reveal password, password acak
├── scripts/
│   └── buat_env.py        # skrip CLI membuat .env (izin 600, tidak menimpa)
├── data/
│   └── vault.db           # SQLite, tidak di-commit
└── tests/
    ├── test_health.py
    └── test_config_db.py
```

## Skema database
- Tabel `pengguna`: id (integer, PK), username (text, unik), password_hash (text, format `scrypt$n$r$p$salt$hash`), dibuat_pada (text, ISO 8601 UTC)
- Tabel `entri`: id (integer, PK), username (text), password_terenkripsi (text), email (text, boleh kosong), provider (text), url (text, boleh kosong), keterangan (text, boleh kosong), dibuat_pada (text), diubah_pada (text)

## Daftar endpoint
- `GET /health` (publik)
- `POST /auth/login`, `POST /auth/logout`, `GET /auth/saya`
- `GET /entri` (dengan parameter pencarian), `POST /entri`, `GET /entri/{id}`, `PUT /entri/{id}`, `DELETE /entri/{id}`
- `GET /entri/{id}/password` (membuka password asli)
- `GET /alat/password-acak`

## Keputusan desain
- 2026-11-17: Akun login tunggal, dibuat lewat skrip CLI agar tidak ada halaman registrasi yang bisa disalahgunakan
- 2026-11-17: Password entri dienkripsi dengan Fernet karena harus bisa dibaca kembali (tidak cukup di-hash). Kunci disimpan di `.env`, di luar database
- 2026-11-17: Password akun login di-hash dengan `hashlib.scrypt`, tanpa library tambahan
- 2026-11-17: Antarmuka cukup `/docs` bawaan FastAPI, tanpa HTML
- 2026-11-17: Port 8001 dipakai supaya tidak bentrok dengan layanan lain di port 8000

---

# 4. PLAN (urutan kerja)

- [x] Tahap 1: folder proyek, venv, `requirements.txt`, `.gitignore`, `git init`, `main.py` minimal dengan `/health`, satu test
- [x] Tahap 2: `config.py` (baca `.env`), `database.py` dan pembuatan tabel
- [ ] Tahap 3: `security.py` (hash scrypt dan enkripsi Fernet), beserta test
- [ ] Tahap 4: `buat_pengguna.py`, login, logout, sesi, batas percobaan login, beserta test
- [ ] Tahap 5: endpoint tambah, lihat daftar, lihat satu entri, beserta test (termasuk test bahwa isi database terenkripsi)
- [ ] Tahap 6: endpoint ubah dan hapus, beserta test
- [ ] Tahap 7: endpoint lihat password asli dan pencarian
- [ ] Tahap 8: pembuat password acak
- [ ] Tahap 9: tinjauan keamanan akhir (cek `.gitignore`, tidak ada rahasia di kode atau log, semua endpoint entri wajib login)

---

# 5. STATUS (kondisi sekarang)

- **Tahap aktif:** 3
- **Terakhir selesai:** Tahap 2 (`config.py`, `database.py`, pembuatan tabel)
- **Masalah terbuka:** belum ada
- **Yang ingin dikerjakan sekarang:** Tahap 3, `security.py` (hash scrypt dan enkripsi Fernet), beserta test

---

# 6. CARA MEMULAI PERCAKAPAN

Baca `AGENTS.md` di folder ini. Patuhi bagian RULES. Kerjakan hanya tahap yang tertulis di STATUS. Sebelum menulis file, jelaskan rencana dan tunggu persetujuan saya. Jika ada yang tidak jelas atau bertentangan dengan SPEC, tanyakan dulu.
