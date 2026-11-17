from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validasi konfigurasi saat startup. Bila .env hilang atau kunci kosong,
    # aplikasi gagal start dengan pesan yang jelas (bukan stack trace mentah).
    get_settings()
    yield


app = FastAPI(title="pwd-vault", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}
