from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from redis.asyncio import Redis
from starlette.responses import JSONResponse

from app.core import VaultOracle
from app.ctfd_auth import team_key
from app.store import StateStore


app = FastAPI(title="Vault Backup Service", docs_url=None, redoc_url=None)
oracle = VaultOracle()
redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"))
store = StateStore(
    redis,
    int(os.environ.get("REQUEST_BUDGET", "16000")),
    os.environ.get("DEPLOYMENT_ID", "development"),
)
allowed_tokens = {
    value.strip()
    for value in os.environ.get("TEAM_TOKENS", "").split(",")
    if value.strip()
}
MAX_REQUEST_BODY = 32768


@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    if request.method == "POST":
        raw_length = request.headers.get("content-length")
        if raw_length is None:
            return JSONResponse(status_code=411, content={"detail": "content_length_required"})
        try:
            length = int(raw_length, 10)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid_content_length"})
        if length < 0 or length > MAX_REQUEST_BODY:
            return JSONResponse(status_code=413, content={"detail": "request_body_too_large"})
    return await call_next(request)


class ShareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(max_length=512)

    @field_validator("value")
    @classmethod
    def utf8_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 512:
            raise ValueError("공유 메모는 UTF-8 기준 512바이트 이하여야 합니다.")
        return value


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seed: int = Field(ge=0, le=0xFFFFFFFF)
    style: int = Field(ge=0, le=3)
    filler: int = Field(ge=0, le=15)


class MeasureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(max_length=512)
    exports: list[ExportRequest] = Field(min_length=1, max_length=16)

    @field_validator("value")
    @classmethod
    def utf8_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 512:
            raise ValueError("공유 메모는 UTF-8 기준 512바이트 이하여야 합니다.")
        return value


class MeasureBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    measurements: list[MeasureRequest] = Field(min_length=1, max_length=16)


def team_token(x_team_token: str = Header(default="", alias="X-Team-Token")) -> str:
    if os.environ.get("CTFD_BASE_URL"):
        try:
            return team_key(x_team_token)
        except ValueError as error:
            raise HTTPException(status_code=401, detail="invalid_team_token") from error
    if x_team_token not in allowed_tokens:
        raise HTTPException(status_code=401, detail="invalid_team_token")
    return x_team_token


async def team_identity(
    x_team_session: str = Header(default="", alias="X-Team-Session"),
    x_team_token: str = Header(default="", alias="X-Team-Token"),
) -> str:
    if x_team_session:
        identity = await store.resolve_session(x_team_session)
        if identity is None:
            raise HTTPException(status_code=401, detail="invalid_team_session")
        return identity
    return team_token(x_team_token)


@app.get("/health")
async def health() -> dict[str, str]:
    if not os.environ.get("CTFD_BASE_URL") and not allowed_tokens:
        raise HTTPException(status_code=503, detail="team_tokens_not_configured")
    try:
        await redis.ping()
    except Exception as error:
        raise HTTPException(status_code=503, detail="redis_unavailable") from error
    return {"status": "ok"}


@app.post("/api/session")
async def session(token: str = Depends(team_token)) -> dict[str, int | str]:
    status = await store.status(token)
    return {**status, "session": await store.create_session(token)}


@app.post("/api/share")
async def share(request: ShareRequest, token: str = Depends(team_identity)) -> dict[str, bool]:
    await store.set_note(token, request.value)
    return {"saved": True}


@app.post("/api/reset")
async def reset(token: str = Depends(team_identity)) -> dict[str, bool]:
    await store.reset_note(token)
    return {"reset": True}


@app.post("/api/export-size")
async def export_size(request: ExportRequest, token: str = Depends(team_identity)) -> dict[str, int]:
    counter, note, remaining = await store.consume(token)
    if counter < 0:
        raise HTTPException(status_code=429, detail="request_budget_exhausted")
    try:
        measured = oracle.export_size(
            note,
            counter,
            request.seed,
            request.style,
            request.filler,
            token.encode("utf-8"),
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {
        "size": measured["size"], "counter": counter,
        "next_counter": counter + 1, "remaining": remaining,
    }


@app.post("/api/measure")
async def measure(request: MeasureRequest, token: str = Depends(team_identity)) -> dict[str, object]:
    counter, note, remaining = await store.consume_many(
        token, len(request.exports), request.value
    )
    if counter < 0:
        raise HTTPException(status_code=429, detail="request_budget_exhausted")
    sizes: list[int] = []
    try:
        for offset, item in enumerate(request.exports):
            measured = oracle.export_size(
                note,
                counter + offset,
                item.seed,
                item.style,
                item.filler,
                token.encode("utf-8"),
            )
            sizes.append(int(measured["size"]))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {
        "sizes": sizes,
        "counter": counter,
        "next_counter": counter + len(request.exports),
        "remaining": remaining,
    }


@app.post("/api/measure-batch")
async def measure_batch(
    request: MeasureBatchRequest, token: str = Depends(team_identity)
) -> dict[str, object]:
    total = sum(len(group.exports) for group in request.measurements)
    counter, _note, remaining = await store.consume_many(
        token, total, request.measurements[-1].value
    )
    if counter < 0:
        raise HTTPException(status_code=429, detail="request_budget_exhausted")

    groups: list[list[int]] = []
    offset = 0
    try:
        for group in request.measurements:
            sizes: list[int] = []
            for item in group.exports:
                measured = oracle.export_size(
                    group.value,
                    counter + offset,
                    item.seed,
                    item.style,
                    item.filler,
                    token.encode("utf-8"),
                )
                sizes.append(int(measured["size"]))
                offset += 1
            groups.append(sizes)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {
        "measurements": groups,
        "counter": counter,
        "next_counter": counter + total,
        "remaining": remaining,
    }
