import os
from pathlib import Path


class Settings:
    """Konfigurasi aplikasi yang dibaca dari file .env.

    Membaca .env ke dictionary lokal tanpa memodifikasi os.environ.
    """

    def __init__(self, env_path: str = None):
        if env_path is None:
            env_path = Path(__file__).resolve().parent.parent / ".env"
        self.fernet_key: str = ""
        self.session_secret: str = ""
        self._env_vars = {}
        self._load_env(env_path)
        self._validate()

    def _load_env(self, env_path):
        path = Path(env_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"File konfigurasi '{path}' tidak ditemukan. "
                "Jalankan 'python scripts/buat_env.py' untuk membuatnya."
            )

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                self._env_vars[key.strip()] = val.strip().strip("\"'")

        self.fernet_key = self._env_vars.get("FERNET_KEY", "")
        self.session_secret = self._env_vars.get("SESSION_SECRET", "")

    def _validate(self):
        if not self.fernet_key:
            raise ValueError(
                "FERNET_KEY kosong. Jalankan 'python scripts/buat_env.py' "
                "lalu periksa kembali file .env."
            )
        if not self.session_secret:
            raise ValueError(
                "SESSION_SECRET kosong. Jalankan 'python scripts/buat_env.py' "
                "lalu periksa kembali file .env."
            )

    def __repr__(self):
        return "Settings(fernet_key='[REDACTED]', session_secret='[REDACTED]')"


_settings = None


def get_settings() -> Settings:
    """Ambil (dan cache) objek Settings. Memicu validasi konfigurasi."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
