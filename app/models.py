"""Pydantic schemas for entry (entri) endpoints.

Response model intentionally excludes the password field so that
listing/detail endpoints never leak the original password.
"""
from typing import Optional

from pydantic import BaseModel, Field


class EntriCreate(BaseModel):
    """Payload for creating an entry."""

    username: str = Field(..., min_length=1, max_length=150)
    password: str = Field(..., min_length=1, max_length=128)
    email: Optional[str] = Field(None, max_length=254)
    provider: str = Field(..., min_length=1, max_length=100)
    url: Optional[str] = Field(None, max_length=500)
    keterangan: Optional[str] = Field(None, max_length=1000)


class EntriResponse(BaseModel):
    """Entry representation returned by the API (no password)."""

    id: int
    username: str
    email: Optional[str] = None
    provider: str
    url: Optional[str] = None
    keterangan: Optional[str] = None
    dibuat_pada: str
    diubah_pada: str