import hashlib
import hmac
import secrets
from cryptography.fernet import Fernet, InvalidToken
from app.config import get_settings


class VaultDecryptionError(Exception):
    """Exception generik untuk kegagalan dekripsi tanpa membocorkan data/kunci."""
    pass


class VaultEncryptionError(Exception):
    """Exception untuk kesalahan kunci Fernet saat enkripsi."""
    pass


def hash_password(password: str, n: int = 2**17, r: int = 8, p: int = 1) -> str:
    """Hash password menggunakan hashlib.scrypt dengan salt acak.

    Format output: scrypt$n$r$p$salt$hash (hex encoded salt dan hash).
    """
    if not isinstance(password, str):
        password = str(password)
    
    salt_bytes = secrets.token_bytes(16)
    salt_hex = salt_bytes.hex()

    try:
        hash_bytes = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt_bytes,
            n=n,
            r=r,
            p=p,
            dklen=32,
            maxmem=2**28,
        )
    except ValueError as e:
        raise ValueError(f"Gagal melakukan hashing password: {e}")

    hash_hex = hash_bytes.hex()
    return f"scrypt${n}${r}${p}${salt_hex}${hash_hex}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifikasi password terhadap stored_hash scrypt.

    Memeriksa batas parameter (n pangkat 2 antara 2**14 dan 2**20, r & p wajar),
    serta memakai hmac.compare_digest untuk perbandingan aman.
    Mengembalikan False untuk hash rusak atau di luar batas tanpa exception.
    """
    if not stored_hash or not isinstance(stored_hash, str):
        return False
    if not isinstance(password, str):
        return False

    parts = stored_hash.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False

    try:
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
    except ValueError:
        return False

    # Validasi batas parameter:
    # n harus merupakan pangkat 2 antara 2**14 (16384) dan 2**20 (1048576)
    if not (16384 <= n <= 1048576 and (n & (n - 1)) == 0):
        return False
    # r dan p dalam rentang wajar (1 s.d. 32)
    if not (1 <= r <= 32 and 1 <= p <= 32):
        return False

    salt_hex = parts[4]
    expected_hash_hex = parts[5]

    try:
        salt_bytes = bytes.fromhex(salt_hex)
        expected_hash_bytes = bytes.fromhex(expected_hash_hex)
    except ValueError:
        return False

    try:
        computed_hash_bytes = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt_bytes,
            n=n,
            r=r,
            p=p,
            dklen=32,
            maxmem=2**28,
        )
    except ValueError:
        return False

    return hmac.compare_digest(computed_hash_bytes, expected_hash_bytes)


def encrypt_entry_password(plaintext: str, key: str = None) -> str:
    """Enkripsi password entri menggunakan Fernet.

    Mengembalikan string (TEXT) hasil enkripsi.
    """
    if key is None:
        key = get_settings().fernet_key

    if not isinstance(plaintext, str):
        raise TypeError("Plaintext harus berupa string.")

    try:
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        f = Fernet(key_bytes)
    except (ValueError, TypeError) as e:
        raise VaultEncryptionError("Kunci enkripsi Fernet tidak valid.") from e

    try:
        ciphertext_bytes = f.encrypt(plaintext.encode("utf-8"))
    except Exception as e:
        raise VaultEncryptionError("Gagal mengenkripsi data.") from e

    return ciphertext_bytes.decode("utf-8")


def decrypt_entry_password(ciphertext: str, key: str = None) -> str:
    """Dekripsi password entri menggunakan Fernet.

    Mengembalikan string hasil dekripsi, atau melempar VaultDecryptionError jika gagal token/kunci.
    Kesalahan tipe (misal None) melempar TypeError secara langsung agar tidak disamarkan.
    """
    if key is None:
        key = get_settings().fernet_key

    if not isinstance(ciphertext, str):
        raise TypeError("Ciphertext harus berupa string.")

    try:
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        f = Fernet(key_bytes)
    except (ValueError, TypeError) as e:
        raise VaultDecryptionError("Kunci enkripsi Fernet tidak valid.") from e

    try:
        decrypted_bytes = f.decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as e:
        raise VaultDecryptionError("Gagal mendekripsi data. Periksa kembali kunci atau ciphertext.") from e

    return decrypted_bytes.decode("utf-8")
