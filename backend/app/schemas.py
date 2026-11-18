"""Validated API models."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["low", "medium", "high", "critical"]


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=120)
    event_type: str = Field(min_length=1, max_length=120)
    severity: Severity = "low"
    message: str = Field(min_length=1, max_length=4000)
    host: str | None = Field(default=None, max_length=255)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source", "event_type", "message")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank.")
        return value

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone.")
        return value.astimezone(UTC)


class NetworkScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    network: str = Field(min_length=9, max_length=43)


class EventRecord(EventCreate):
    id: UUID
    ingested_at: datetime


class EventPage(BaseModel):
    items: list[EventRecord]
    total: int
    limit: int
    offset: int
