import uuid
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def _request_id() -> str:
    return f"req_{uuid.uuid4().hex[:12]}"


def error_response(
    status_code: int,
    code: str,
    message: str,
    fields: dict[str, Any] | None = None,
    retryable: bool = False,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "fields": fields or {},
                "retryable": retryable,
            },
            "request_id": _request_id(),
        },
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    fields: dict[str, str] = {}
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", []) if p != "body")
        if loc:
            fields[loc] = err.get("msg", "invalid")
    return error_response(
        status_code=422,
        code="VALIDATION_ERROR",
        message="Request body validation failed.",
        fields=fields,
    )
