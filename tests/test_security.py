import pytest
from app.security import (
    hash_password,
    verify_password,
    encrypt_entry_password,
    decrypt_entry_password,
    VaultDecryptionError,
    VaultEncryptionError,
)
from cryptography.fernet import Fernet


def test_hash_and_verify_password():
    password = "password-palsu-123"
    # Pakai parameter kecil untuk tes cepat
    h1 = hash_password(password, n=16384, r=8, p=1)
    h2 = hash_password(password, n=16384, r=8, p=1)

    # Dua hash dari password yang sama harus berbeda (salt acak)
    assert h1 != h2

    # Format hash sesuai ARCHITECTURE: scrypt$n$r$p$salt$hash
    parts = h1.split("$")
    assert len(parts) == 6
    assert parts[0] == "scrypt"
    assert parts[1] == "16384"
    assert parts[2] == "8"
    assert parts[3] == "1"

    # Verifikasi berhasil
    assert verify_password(password, h1) is True
    assert verify_password(password, h2) is True

    # Verifikasi salah password
    assert verify_password("password-salah", h1) is False


def test_password_edge_cases():
    password = "password-palsu-123"
    valid_hash = hash_password(password, n=16384, r=8, p=1)

    # 1. Password kosong
    assert verify_password("", valid_hash) is False

    # 2. Password unicode / emoji
    unicode_pwd = "password-palsu-émoji-🔑"
    unicode_hash = hash_password(unicode_pwd, n=16384, r=8, p=1)
    assert verify_password(unicode_pwd, unicode_hash) is True
    assert verify_password("password-salah", unicode_hash) is False

    # 3. Hash kosong atau None
    assert verify_password(password, "") is False
    assert verify_password(password, None) is False

    # 4. Hash dengan jumlah bagian (parts) salah
    assert verify_password(password, "scrypt$16384$8$salt$hash") is False
    assert verify_password(password, "bukan-scrypt$16384$8$1$salt$hash") is False

    # 5. Parameter n di luar batas / bukan pangkat 2
    bad_n_hash = "scrypt$15000$8$1$123456$abcdef"
    assert verify_password(password, bad_n_hash) is False

    # 6. Parameter r atau p di luar batas
    bad_rp_hash = "scrypt$16384$100$1$123456$abcdef"
    assert verify_password(password, bad_rp_hash) is False

    # 7. Hex salt / hash rusak
    bad_hex_hash = "scrypt$16384$8$1$xyz$abc"
    assert verify_password(password, bad_hex_hash) is False


def test_fernet_encryption_decryption():
    key = Fernet.generate_key().decode()
    plaintext = "rahasia-palsu-456"

    ciphertext = encrypt_entry_password(plaintext, key=key)

    # Ciphertext harus berupa string dan berbeda dari plaintext asli
    assert isinstance(ciphertext, str)
    assert ciphertext != plaintext

    # Dekripsi berhasil dan mengembalikan str
    decrypted = decrypt_entry_password(ciphertext, key=key)
    assert isinstance(decrypted, str)
    assert decrypted == plaintext


def test_fernet_wrong_key_fails():
    key1 = Fernet.generate_key().decode()
    key2 = Fernet.generate_key().decode()
    plaintext = "rahasia-palsu-789"

    ciphertext = encrypt_entry_password(plaintext, key=key1)

    # Dekripsi dengan kunci salah harus melempar VaultDecryptionError generik
    with pytest.raises(VaultDecryptionError):
        decrypt_entry_password(ciphertext, key=key2)


def test_malformed_key_raises_error():
    bad_key = "kunci-salah-format"
    with pytest.raises((VaultEncryptionError, VaultDecryptionError)):
        encrypt_entry_password("test", key=bad_key)

    with pytest.raises((VaultDecryptionError, VaultEncryptionError)):
        decrypt_entry_password("someciphertext", key=bad_key)


def test_wrong_ciphertext_type_not_masked_as_decryption_error():
    key = Fernet.generate_key().decode()

    # Ciphertext None adalah kesalahan tipe pemrograman, bukan kegagalan dekripsi.
    with pytest.raises(TypeError):
        decrypt_entry_password(None, key=key)

    with pytest.raises(TypeError):
        decrypt_entry_password(12345, key=key)
