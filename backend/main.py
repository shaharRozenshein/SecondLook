"""Second Look backend: receives email data from the Gmail add-on and returns a risk score."""

import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException

from models import AnalysisResult, EmailInput
from scoring import analyze_email

# The API key is read from the environment, never hard-coded in the repo
API_KEY = os.environ.get("API_KEY")

app = FastAPI(title="Second Look API")


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
    return analyze_email(email)