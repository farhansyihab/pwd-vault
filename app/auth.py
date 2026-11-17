import time
from fastapi import Request, HTTPException, status
from starlette.middleware.sessions import SessionMiddleware
from app.database import get_connection
from app.security import verify_password, hash_password

# Global in-memory state untuk pembatasan percobaan login (rate limiter / lockout)
# 5 kali gagal berturut-turut mengunci login selama 5 menit (300 detik)
_failed_attempts = 0
_lockout_until = 0.0
LOCKOUT_DURATION = 300.0  # 5 menit dalam detik
MAX_FAILED_ATTEMPTS = 5

# Lazy cache untuk hash palsu (dummy hash) untuk menyamakan waktu respons (anti timing attack)
_dummy_hash_cache = None

def get_dummy_hash() -> str:
    global _dummy_hash_cache
    if _dummy_hash_cache is None:
        # Menggunakan parameter produksi standar untuk hash palsu
        _dummy_hash_cache = hash_password("dummy-password-palsu-12345")
    return _dummy_hash_cache


def check_rate_limit(monotonic_fn=time.monotonic):
    global _failed_attempts, _lockout_until
    now = monotonic_fn()
    if _lockout_until and now >= _lockout_until:
        # Masa kunci habis: mulai hitungan baru
        _failed_attempts = 0
        _lockout_until = 0.0
        return
    if now < _lockout_until:
        # Masih terkunci
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Terlalu banyak percobaan login gagal. Akun dikunci sementara selama 5 menit.",
        )


def record_failed_attempt(monotonic_fn=time.monotonic):
    global _failed_attempts, _lockout_until
    now = monotonic_fn()
    # Jika sudah terkunci, percobaan saat terkunci tidak memperpanjang kunci
    if now >= _lockout_until:
        _failed_attempts += 1
        if _failed_attempts >= MAX_FAILED_ATTEMPTS:
            _lockout_until = now + LOCKOUT_DURATION


def reset_failed_attempts():
    global _failed_attempts, _lockout_until
    _failed_attempts = 0
    _lockout_until = 0.0


def authenticate_user(username: str, password: str, monotonic_fn=time.monotonic):
    check_rate_limit(monotonic_fn)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash FROM pengguna WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user is None:
        # Username tidak ada: tetap jalankan verify_password terhadap hash palsu agar waktu respons sama
        verify_password(password, get_dummy_hash())
        record_failed_attempt(monotonic_fn)
        return None

    # Pengguna ada, verifikasi password
    is_valid = verify_password(password, user["password_hash"])
    if not is_valid:
        record_failed_attempt(monotonic_fn)
        return None

    # Login sukses: reset penghitung kegagalan
    reset_failed_attempts()
    return user


async def wajib_login(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi diperlukan. Silakan login terlebih dahulu.",
        )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, dibuat_pada FROM pengguna WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user is None:
        # Sesi ada tapi pengguna sudah dihapus dari database
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Pengguna tidak valid atau sudah dihapus.",
        )

    return user