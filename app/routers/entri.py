"""Entry (entri) endpoints: create, list, view, update, delete,
reveal password, and search.

All endpoints require authentication (wajib_login).
Passwords are encrypted before being stored and are never returned
by the list/detail/update endpoints. The original password can only
be obtained via the dedicated reveal endpoint.
"""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth import wajib_login
from app.database import get_connection
from app.models import (
    EntriCreate,
    EntriPasswordResponse,
    EntriResponse,
    EntriUpdate,
)
from app.security import (
    VaultDecryptionError,
    decrypt_entry_password,
    encrypt_entry_password,
)

router = APIRouter(prefix="/entri", tags=["entri"])


def _now_iso() -> str:
    """Current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _like_pattern(q: str) -> str:
    """Build a SQL LIKE pattern from user input, escaping wildcards.

    A literal ``\\``, ``%`` or ``_`` typed by the user must be matched
    literally, not treated as a wildcard. The backslash is used as the
    ESCAPE character in the SQL query.
    """
    escaped = (
        q.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
    return f"%{escaped}%"


def _row_to_response(row) -> EntriResponse:
    return EntriResponse(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        provider=row["provider"],
        url=row["url"],
        keterangan=row["keterangan"],
        dibuat_pada=row["dibuat_pada"],
        diubah_pada=row["diubah_pada"],
    )


@router.post("", response_model=EntriResponse, status_code=status.HTTP_201_CREATED)
def tambah_entri(payload: EntriCreate, current_user=Depends(wajib_login)):
    """Create a new entry. Password is encrypted before storage."""
    try:
        ciphertext = encrypt_entry_password(payload.password)
    except Exception:
        # Do not leak details about the key or underlying error.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Gagal menyimpan entri. Silakan coba lagi.",
        )

    now = _now_iso()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO entri (
                username, password_terenkripsi, email, provider,
                url, keterangan, dibuat_pada, diubah_pada
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.username,
                ciphertext,
                payload.email,
                payload.provider,
                payload.url,
                payload.keterangan,
                now,
                now,
            ),
        )
        conn.commit()
        entri_id = cursor.lastrowid

        cursor.execute(
            "SELECT id, username, email, provider, url, keterangan, "
            "dibuat_pada, diubah_pada FROM entri WHERE id = ?",
            (entri_id,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    return _row_to_response(row)


@router.get("", response_model=List[EntriResponse])
def daftar_entri(
    q: Optional[str] = Query(
        None,
        max_length=100,
        description="Cari berdasarkan provider atau username (case-insensitive).",
    ),
    current_user=Depends(wajib_login),
):
    """List entries. The password field is never included.

    If ``q`` is provided, only entries whose ``provider`` or ``username``
    contains ``q`` (case-insensitive, wildcard characters are treated
    literally) are returned. An empty ``q`` returns all entries.
    """
    base_sql = (
        "SELECT id, username, email, provider, url, keterangan, "
        "dibuat_pada, diubah_pada FROM entri"
    )

    conn = get_connection()
    try:
        cursor = conn.cursor()
        if q:
            like = _like_pattern(q)
            cursor.execute(
                base_sql
                + " WHERE provider LIKE ? ESCAPE '\\'"
                + " OR username LIKE ? ESCAPE '\\'"
                + " ORDER BY id DESC",
                (like, like),
            )
        else:
            cursor.execute(base_sql + " ORDER BY id DESC")
        rows = cursor.fetchall()
    finally:
        conn.close()

    return [_row_to_response(row) for row in rows]


@router.get("/{entri_id}/password", response_model=EntriPasswordResponse)
def lihat_password(entri_id: int, current_user=Depends(wajib_login)):
    """Reveal the original (decrypted) password for one entry.

    This is the only endpoint that returns the plaintext password.
    Decryption failures are reported generically so that no detail
    about the Fernet key or ciphertext leaks to the caller.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password_terenkripsi FROM entri WHERE id = ?",
            (entri_id,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entri dengan id {entri_id} tidak ditemukan.",
        )

    try:
        plaintext = decrypt_entry_password(row["password_terenkripsi"])
    except (VaultDecryptionError, Exception):
        # Never expose ciphertext, key, or stack trace to the user.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Gagal membuka password entri. Data mungkin rusak.",
        )

    return EntriPasswordResponse(id=row["id"], password=plaintext)


@router.get("/{entri_id}", response_model=EntriResponse)
def lihat_entri(entri_id: int, current_user=Depends(wajib_login)):
    """Return a single entry by id (without password)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, provider, url, keterangan, "
            "dibuat_pada, diubah_pada FROM entri WHERE id = ?",
            (entri_id,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entri dengan id {entri_id} tidak ditemukan.",
        )

    return _row_to_response(row)


@router.put("/{entri_id}", response_model=EntriResponse)
def ubah_entri(
    entri_id: int,
    payload: EntriUpdate,
    current_user=Depends(wajib_login),
):
    """Update an existing entry (partial update).

    - Fields omitted from the request are left unchanged.
    - ``password`` is re-encrypted with Fernet only if provided.
    - ``dibuat_pada`` is preserved; ``diubah_pada`` is always refreshed.
    """
    provided = payload.model_dump(exclude_unset=True)

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_terenkripsi, email, provider, "
            "url, keterangan, dibuat_pada, diubah_pada "
            "FROM entri WHERE id = ?",
            (entri_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Entri dengan id {entri_id} tidak ditemukan.",
            )

        # Non-nullable columns (username, provider): update only if a
        # non-None value is explicitly provided.
        if provided.get("username") is not None:
            new_username = provided["username"]
        else:
            new_username = row["username"]

        if provided.get("provider") is not None:
            new_provider = provided["provider"]
        else:
            new_provider = row["provider"]

        # Nullable columns (email, url, keterangan): if the key is present
        # (including null), use it; otherwise keep existing value.
        new_email = provided["email"] if "email" in provided else row["email"]
        new_url = provided["url"] if "url" in provided else row["url"]
        new_keterangan = (
            provided["keterangan"] if "keterangan" in provided else row["keterangan"]
        )

        # Password: re-encrypt only when a non-None value is provided.
        if provided.get("password") is not None:
            try:
                new_password_enc = encrypt_entry_password(provided["password"])
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Gagal menyimpan entri. Silakan coba lagi.",
                )
        else:
            new_password_enc = row["password_terenkripsi"]

        now = _now_iso()
        cursor.execute(
            """
            UPDATE entri
            SET username = ?, password_terenkripsi = ?, email = ?,
                provider = ?, url = ?, keterangan = ?, diubah_pada = ?
            WHERE id = ?
            """,
            (
                new_username,
                new_password_enc,
                new_email,
                new_provider,
                new_url,
                new_keterangan,
                now,
                entri_id,
            ),
        )
        conn.commit()

        cursor.execute(
            "SELECT id, username, email, provider, url, keterangan, "
            "dibuat_pada, diubah_pada FROM entri WHERE id = ?",
            (entri_id,),
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    return _row_to_response(row)


@router.delete("/{entri_id}", status_code=status.HTTP_200_OK)
def hapus_entri(entri_id: int, current_user=Depends(wajib_login)):
    """Delete an entry by id. Returns 404 if it does not exist."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM entri WHERE id = ?", (entri_id,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Entri dengan id {entri_id} tidak ditemukan.",
            )
        cursor.execute("DELETE FROM entri WHERE id = ?", (entri_id,))
        conn.commit()
    finally:
        conn.close()

    return {
        "status": "sukses",
        "pesan": f"Entri dengan id {entri_id} berhasil dihapus.",
    }