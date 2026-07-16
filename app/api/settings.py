"""全局系统配置 API。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dto import (
    FofaKeyDTO,
    FofaKeyOrderDTO,
    FofaKeyUpdateDTO,
    LLMProtocol,
    LLMProviderDTO,
    LLMProviderOrderDTO,
    LLMProviderUpdateDTO,
    SettingsUpdateRequest,
)
from app.db.session import get_session
from app.settings_service import (
    FofaKeyConflictError,
    FofaKeyNotFoundError,
    FofaKeyOrderError,
    FofaKeyReadOnlyError,
    FofaKeyValidationError,
    LLMProviderConflictError,
    LLMProviderNotFoundError,
    LLMProviderOrderError,
    LLMProviderValidationError,
    adopt_legacy_fofa_key,
    create_fofa_key,
    create_llm_provider,
    delete_fofa_key,
    delete_llm_provider,
    get_llm_provider,
    is_masked_secret,
    list_fofa_keys,
    list_llm_providers,
    list_available_models,
    probe_llm_provider,
    public_settings_view,
    refresh_cache,
    reorder_fofa_keys,
    reorder_llm_providers,
    run_settings_health_check,
    test_fofa_key,
    update_fofa_key,
    update_llm_provider,
    update_settings,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    return public_settings_view()


@router.post("/health-check")
async def check_settings_health(session: AsyncSession = Depends(get_session)):
    try:
        return await run_settings_health_check(session)
    except ValueError as exc:
        _raise_provider_http_error(exc)


def _raise_provider_http_error(exc: ValueError) -> None:
    if isinstance(exc, (LLMProviderConflictError, FofaKeyConflictError)):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, (LLMProviderNotFoundError, FofaKeyNotFoundError)):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(exc, (LLMProviderOrderError, FofaKeyOrderError, FofaKeyReadOnlyError)):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if isinstance(exc, (LLMProviderValidationError, FofaKeyValidationError)):
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    raise exc


@router.get("/llm-providers")
async def get_llm_providers(session: AsyncSession = Depends(get_session)):
    try:
        return await list_llm_providers(session, include_legacy=True)
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.post("/llm-providers")
async def post_llm_provider(
    body: LLMProviderDTO,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await create_llm_provider(session, body.model_dump())
    except ValueError as exc:
        _raise_provider_http_error(exc)


# Keep this static route before /{name}; provider names are otherwise unrestricted text.
@router.put("/llm-providers/order")
async def put_llm_provider_order(
    body: LLMProviderOrderDTO,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await reorder_llm_providers(session, body.names)
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.put("/llm-providers/{name}")
async def put_llm_provider(
    name: str,
    body: LLMProviderUpdateDTO,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await update_llm_provider(
            session, name, body.model_dump(exclude_unset=True)
        )
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.delete("/llm-providers/{name}")
async def remove_llm_provider(
    name: str,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await delete_llm_provider(session, name)
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.post("/llm-providers/{name}/test")
async def test_llm_provider(
    name: str,
    session: AsyncSession = Depends(get_session),
):
    try:
        provider = await get_llm_provider(session, name, include_legacy=True)
    except ValueError as exc:
        _raise_provider_http_error(exc)
    return await probe_llm_provider(provider)


@router.get("/fofa-keys")
async def get_fofa_keys(session: AsyncSession = Depends(get_session)):
    try:
        return await list_fofa_keys(session, include_legacy=True)
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.post("/fofa-keys/legacy/adopt")
async def post_adopt_legacy_fofa_key(
    session: AsyncSession = Depends(get_session),
):
    try:
        return await adopt_legacy_fofa_key(session)
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.post("/fofa-keys")
async def post_fofa_key(
    body: FofaKeyDTO,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await create_fofa_key(session, body.model_dump())
    except ValueError as exc:
        _raise_provider_http_error(exc)


# Keep this static route before /{name} so "order" is never treated as a key name.
@router.put("/fofa-keys/order")
async def put_fofa_key_order(
    body: FofaKeyOrderDTO,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await reorder_fofa_keys(session, body.names)
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.put("/fofa-keys/{name}")
async def put_fofa_key(
    name: str,
    body: FofaKeyUpdateDTO,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await update_fofa_key(
            session, name, body.model_dump(exclude_unset=True)
        )
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.delete("/fofa-keys/{name}")
async def remove_fofa_key(
    name: str,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await delete_fofa_key(session, name)
    except ValueError as exc:
        _raise_provider_http_error(exc)


@router.post("/fofa-keys/{name}/test")
async def probe_saved_fofa_key(
    name: str,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await test_fofa_key(session, name)
    except ValueError as exc:
        _raise_provider_http_error(exc)


class ModelsProbeRequest(BaseModel):
    base_url: str | None = None
    api_key: str | None = None
    protocol: LLMProtocol | None = None
    provider_name: str | None = None


@router.post("/models")
async def probe_models(
    body: ModelsProbeRequest,
    session: AsyncSession = Depends(get_session),
):
    """拉取模型商可用模型列表，供前端下拉选择。base_url/api_key 留空用有效配置。
    注意：api_key 为脱敏占位（如 ****）时视为未传，回退到服务端已存的真实 key。"""
    await refresh_cache(session)
    key = (body.api_key or "").strip()
    if key and is_masked_secret(key):
        key = ""  # 前端回显的脱敏占位，丢弃
    base_url = body.base_url
    protocol = body.protocol
    if body.provider_name:
        try:
            provider = await get_llm_provider(
                session, body.provider_name, include_legacy=True
            )
        except ValueError as exc:
            _raise_provider_http_error(exc)
        requested_base = str(base_url or "").strip().rstrip("/")
        stored_base = provider.base_url.strip().rstrip("/")
        base_url = base_url or provider.base_url
        if not key and (not requested_base or requested_base == stored_base):
            key = provider.api_key
        protocol = protocol or provider.protocol
    return await list_available_models(
        base_url=base_url,
        api_key=key or None,
        protocol=protocol or "openai_chat",
    )


@router.put("")
async def put_settings(
    body: SettingsUpdateRequest,
    session: AsyncSession = Depends(get_session),
):
    payload = body.model_dump(exclude_unset=True)
    return await update_settings(session, payload)
    create_fofa_key,
    delete_fofa_key,
    list_fofa_keys,
    reorder_fofa_keys,
    test_fofa_key,
    update_fofa_key,
