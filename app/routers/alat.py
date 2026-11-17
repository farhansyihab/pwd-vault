"""Utility endpoints (alat) for the pwd-vault application.

Provides a cryptographically secure random password generator based on the
standard library ``secrets`` module. All endpoints require login, consistent
with the rest of the application.

The generator guarantees that, when a character class is enabled, at least
one character from that class will appear in the result. This prevents
surprising outputs like "no symbols" when the user explicitly asked for them.
"""
import secrets
import string

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import wajib_login
from app.models import PasswordAcakResponse

router = APIRouter(prefix="/alat", tags=["alat"])


# Character classes. Kept as module-level constants so tests can assert
# that generated output only contains characters from the chosen pools.
HURUF_KECIL = string.ascii_lowercase
HURUF_BESAR = string.ascii_uppercase
ANGKA = string.digits
SIMBOL = "!@#$%^&*()-_=+[]{};:,.<>/?"


def buat_password_acak(
    panjang: int,
    pakai_kecil: bool,
    pakai_besar: bool,
    pakai_angka: bool,
    pakai_simbol: bool,
) -> str:
    """Generate a random password using the ``secrets`` module.

    Raises ``ValueError`` when no character class is enabled or when
    ``panjang`` is smaller than the number of enabled classes (so that
    every class can be represented at least once).
    """
    pools = []
    if pakai_kecil:
        pools.append(HURUF_KECIL)
    if pakai_besar:
        pools.append(HURUF_BESAR)
    if pakai_angka:
        pools.append(ANGKA)
    if pakai_simbol:
        pools.append(SIMBOL)

    if not pools:
        raise ValueError("Minimal satu jenis karakter harus diaktifkan.")

    if panjang < len(pools):
        raise ValueError(
            f"Panjang minimal {len(pools)} karakter agar setiap jenis "
            "karakter yang aktif terwakili."
        )

    semua_karakter = "".join(pools)

    # Start with one character from each enabled pool, then fill the rest
    # from the combined pool, and shuffle so positions are unpredictable.
    hasil = [secrets.choice(pool) for pool in pools]
    while len(hasil) < panjang:
        hasil.append(secrets.choice(semua_karakter))

    secrets.SystemRandom().shuffle(hasil)
    return "".join(hasil)


@router.get("/password-acak", response_model=PasswordAcakResponse)
def password_acak(
    panjang: int = Query(
        16,
        ge=8,
        le=128,
        description="Panjang password yang dihasilkan (8-128).",
    ),
    huruf_kecil: bool = Query(True, description="Sertakan huruf kecil (a-z)."),
    huruf_besar: bool = Query(True, description="Sertakan huruf besar (A-Z)."),
    angka: bool = Query(True, description="Sertakan angka (0-9)."),
    simbol: bool = Query(True, description="Sertakan simbol (!@#$...)."),
    current_user=Depends(wajib_login),
):
    """Return a freshly generated random password.

    This endpoint never touches the database and never stores the
    generated value. It exists purely as a convenience utility for the
    single logged-in user.
    """
    try:
        pw = buat_password_acak(panjang, huruf_kecil, huruf_besar, angka, simbol)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return PasswordAcakResponse(password=pw, panjang=len(pw))