from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from app.auth import authenticate_user, wajib_login

router = APIRouter(prefix="/auth", tags=["auth"])

GENERIC_LOGIN_ERROR = "Username atau password salah."


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    # Validasi panjang input
    if not username or len(username) > 150:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username tidak valid.")
    if not password or len(password) > 128:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password maksimal 128 karakter.")

    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_LOGIN_ERROR,
        )

    # Login sukses: kosongkan session lama terlebih dahulu sebelum set user_id
    request.session.clear()
    request.session["user_id"] = user["id"]

    return {"status": "sukses", "pesan": f"Login berhasil sebagai {user['username']}"}


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return {"status": "sukses", "pesan": "Logout berhasil."}


@router.get("/saya")
def saya(current_user=Depends(wajib_login)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "dibuat_pada": current_user["dibuat_pada"],
    }