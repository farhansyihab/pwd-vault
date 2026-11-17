import getpass
import sys
from datetime import datetime, timezone
from app.database import init_db, get_connection
from app.security import hash_password


def main():
    print("=== Skrip Pembuatan Pengguna Pwd-Vault ===")
    init_db()

    username = input("Masukkan username: ").strip()
    if not username:
        print("Error: Username tidak boleh kosong.", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass("Masukkan password (minimal 12 karakter): ")
    if len(password) < 12:
        print("Error: Password terlalu pendek (minimal 12 karakter).", file=sys.stderr)
        sys.exit(1)

    confirm_password = getpass.getpass("Konfirmasi password: ")
    if password != confirm_password:
        print("Error: Konfirmasi password tidak cocok.", file=sys.stderr)
        sys.exit(1)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM pengguna WHERE username = ?", (username,))
    if cursor.fetchone():
        print(f"Error: Pengguna dengan username '{username}' sudah ada.", file=sys.stderr)
        conn.close()
        sys.exit(1)

    password_hash = hash_password(password)
    dibuat_pada = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        "INSERT INTO pengguna (username, password_hash, dibuat_pada) VALUES (?, ?, ?)",
        (username, password_hash, dibuat_pada),
    )
    conn.commit()
    conn.close()

    print(f"Sukses: Pengguna '{username}' berhasil dibuat.")


if __name__ == "__main__":
    main()