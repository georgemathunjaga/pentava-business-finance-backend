"""Root entry point — Railpack detects this and runs it with uvicorn."""
from pentava_finances.main import app  # noqa: F401

if __name__ == "__main__":
    import os
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
