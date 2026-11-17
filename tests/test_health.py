import pytest
from httpx import AsyncClient, ASGITransport

from app.config import Settings
from app.main import create_app


@pytest.mark.anyio
async def test_health(tmp_path):
    # Konfigurasi sementara lewat tmp_path; .env asli tidak dibaca.
    env_file = tmp_path / ".env"
    env_file.write_text(
        "FERNET_KEY=password-palsu-key\nSESSION_SECRET=password-palsu-secret\n"
    )
    settings = Settings(env_path=str(env_file))
    app = create_app(settings)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
