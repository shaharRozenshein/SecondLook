"""Data models shared across the backend."""

from pydantic import BaseModel, Field


class Attachment(BaseModel):
    """Attachment metadata only. File contents are never sent to the backend."""
    name: str = Field(default="", max_length=300)
    content_type: str = Field(default="", max_length=200)
    size: int = Field(default=0, ge=0)


class EmailInput(BaseModel):
    """Data the add-on sends. Length limits protect against oversized input."""
    sender: str = Field(max_length=500)
    reply_to: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1000)
    auth_results: str = Field(default="", max_length=5000)
    body_text: str = Field(default="", max_length=50_000)
    body_html: str = Field(default="", max_length=200_000)
    attachments: list[Attachment] = Field(default_factory=list, max_length=20)


class Reason(BaseModel):
    signal: str
    detail: str
    points: int


class AnalysisResult(BaseModel):
    score: int
    verdict: str
    reasons: list[Reason]