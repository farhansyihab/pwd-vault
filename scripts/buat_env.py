import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet
import secrets

def main():
    project_root = Path(__file__).resolve().parent.parent
    env_path = project_root / ".env"

    try:
        fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"Error: {env_path} sudah ada. Skrip menolak menimpa file yang sudah ada.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error saat membuat file .env: {e}", file=sys.stderr)
        sys.exit(1)

    fernet_key = Fernet.generate_key().decode()
    session_secret = secrets.token_hex(32)

    content = f"FERNET_KEY={fernet_key}\nSESSION_SECRET={session_secret}\n"

    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)

    print("File .env berhasil dibuat dengan aman.")

if __name__ == "__main__":
    main()
