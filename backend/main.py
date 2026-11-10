"""Second Look backend: analyzes email metadata and returns a phishing risk score."""

import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

# The API key is read from the environment, never hard-coded in the repo
API_KEY = os.environ.get("API_KEY")

app = FastAPI(title="Second Look API")


class EmailInput(BaseModel):
    """Data the add-on sends. Length limits protect against oversized input."""
    sender: str = Field(max_length=500)
    subject: str = Field(default="", max_length=1000)


class Reason(BaseModel):
    signal: str      # the name of the signal, e.g. "display_name_mismatch"
    detail: str      # human explanation, e.g. "Claims to be PayPal but sent from paypa1.xyz"
    points: int      # how much this signal added to the score

class AnalysisResult(BaseModel):
    score: int              # the total
    verdict: str            # the conclusion: Safe / Suspicious / Malicious
    reasons: list[Reason]   # all the lines of the receipt

def require_api_key(x_api_key: str = Header(default="")) -> None:
    """Reject requests without a valid API key (read from the X-API-Key header)."""
    # Fail closed if no key is configured; constant-time comparison prevents timing attacks
    if not API_KEY or not secrets.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


# Analyze an email. Two checks run first: the caller must have a valid API key,
# and the email data must match the EmailInput format.
@app.post("/analyze", response_model=AnalysisResult, dependencies=[Depends(require_api_key)])
def analyze(email: EmailInput) -> AnalysisResult:
    # Placeholder result until the scoring engine is built 
    return AnalysisResult(
        score=42,
        verdict="Suspicious",
        reasons=[Reason(signal="placeholder", detail="Scoring engine not implemented yet", points=0)],
    )