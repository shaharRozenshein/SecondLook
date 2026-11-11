"""Second Look backend: receives email data from the Gmail add-on and returns a risk score."""

import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from models import AnalysisResult, EmailInput
from scoring import analyze_email

# The API key is read from the environment, never hard-coded in the repo
API_KEY = os.environ.get("API_KEY")

# Interactive API docs help during development, but in production they would publicly
# describe the API, so they are off unless explicitly enabled
DOCS_ENABLED = os.environ.get("ENABLE_DOCS") == "true"

# Largest request accepted; real requests are far smaller (all field limits add up to ~260 KB)
MAX_BODY_BYTES = 1_000_000

app = FastAPI(
    title="Second Look API",
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url=None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Reject oversized requests before reading them, to protect the server's memory."""
    declared_size = request.headers.get("content-length", "0")
    if not declared_size.isdigit() or int(declared_size) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request too large"})
    return await call_next(request)


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