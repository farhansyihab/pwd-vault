from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings, get_settings
from app.database import init_db
from app.routers import auth as auth_router

SESSION_MAX_AGE = 3600  # 1 jam (detik); sesi berakhir otomatis setelah itu


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Application factory.

    - Bila settings None, ambil dari get_settings() (gagal jelas bila .env hilang/kunci kosong).
    - SessionMiddleware memakai settings.session_secret yang sudah valid.
    - init_db() dijalankan saat lifespan startup.
    """
    if settings is None:
        settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db()
        yield

    app = FastAPI(title="pwd-vault", version="0.1.0", lifespan=lifespan)

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="pwd_vault_session",
        max_age=SESSION_MAX_AGE,
        same_site="strict",
        https_only=False,  # hanya http://127.0.0.1
    )

    app.include_router(auth_router.router)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app