"""Runtime application settings.

Persisted per workspace. Legacy installation settings apply only to default.
New credentials use server environment references; reads never return values.
"""

from __future__ import annotations

from typing import Any
import math

from sqlalchemy.orm import Session

from .config import AI_API_KEY, AI_BASE_URL, AI_MODELS, AI_PROVIDER, AI_TIMEOUT, OLLAMA_URL
from .policies import default_policy
from . import scoped_settings

AI_SETTINGS_KEY = "ai"
POLICY_SETTINGS_KEY = "policy"
MASK = "••••••"

# Stored keys use snake_case; the API speaks camelCase (like the rest of TRACE).
_API_TO_STORE = {"secretRef": "secret_ref", "baseUrl": "base_url", "ollamaUrl": "ollama_url", "apiKey": "api_key", "analysisDepth": "analysis_depth", "responseLanguage": "response_language", "analystContext": "analyst_context", "reviewPass": "review_pass"}
_STORE_TO_API = {v: k for k, v in _API_TO_STORE.items()}
_ALLOWED = {"provider", "models", "base_url", "ollama_url", "api_key", "secret_ref", "temperature", "timeout", "analysis_depth", "response_language", "analyst_context", "review_pass"}


def _defaults() -> dict[str, Any]:
    return {
        "provider": AI_PROVIDER,
        "models": list(AI_MODELS),
        "base_url": AI_BASE_URL,
        "ollama_url": OLLAMA_URL,
        "api_key": AI_API_KEY,
        "temperature": 0.1,
        "timeout": AI_TIMEOUT,
        "analysis_depth": "deep",
        "response_language": "ru",
        "analyst_context": "",
        "review_pass": False,
    }


def get_ai_settings(db: Session) -> dict[str, Any]:
    """Current AI config: env defaults overlaid with persisted overrides.

    Keys are the engine's natural snake_case; :func:`public_ai_settings` maps
    them to the API's camelCase.
    """
    data = _defaults()
    if db.info.get('workspace_id','default') != 'default':
        data.update(provider='rules', api_key='', base_url='', ollama_url='', models=[])
    data.update({k:v for k,v in scoped_settings.read(db,AI_SETTINGS_KEY).items() if k in _ALLOWED})
    if data.get('secret_ref'):
        data['api_key']=scoped_settings.resolve_secret(db,data['secret_ref'])
    return data


def normalize_ai_patch(patch: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for raw_key, value in patch.items():
        key = _API_TO_STORE.get(raw_key, raw_key)
        if key not in _ALLOWED: continue
        if key == 'secret_ref': scoped_settings.validate_ref(value)
        if key == 'api_key' and value not in (None, '', MASK): raise ValueError('Передавайте secretRef вместо API-ключа')
        if key == 'analysis_depth' and value not in ('standard','deep'): raise ValueError('Неизвестная глубина анализа')
        if key == 'response_language' and value not in ('ru','en'): raise ValueError('Язык ответа: ru или en')
        if key == 'analyst_context' and (not isinstance(value,str) or len(value)>4000): raise ValueError('Контекст должен быть строкой до 4000 символов')
        if key == 'review_pass' and not isinstance(value,bool): raise ValueError('Повторная проверка: true или false')
        if key in ('temperature','timeout'):
            try: value = float(value)
            except (ValueError,TypeError): raise ValueError('Некорректное числовое значение')
            lower,upper = (0,1) if key == 'temperature' else (5,600)
            if not math.isfinite(value) or not lower<=value<=upper: raise ValueError(f'{key}: допустимо от {lower} до {upper}')
        if key == 'models':
            if not isinstance(value,list) or len(value)>4 or any(not isinstance(m,str) or len(m)>200 for m in value): raise ValueError('Укажите до четырёх названий моделей')
        result[key]=value
    return result


def set_ai_settings(db: Session, patch: dict[str, Any]) -> dict[str, Any]:
    """Merge a validated patch (camelCase or snake_case) into the AI config.

    A masked or missing ``apiKey`` leaves the stored key untouched; an explicit
    empty string clears it.
    """
    current = get_ai_settings(db)
    for key, value in normalize_ai_patch(patch).items():
        key = _API_TO_STORE.get(key, key)
        if key not in _ALLOWED:
            continue
        if key == "api_key" and value in (None, MASK):
            continue
        if key == "models":
            value = [str(m).strip() for m in (value or []) if str(m).strip()]
        if key in ("temperature", "timeout"):
            try:
                value = float(value)
            except (TypeError, ValueError):
                continue
        current[key] = value
    stored={k:v for k,v in current.items() if k != 'api_key'}
    if normalize_ai_patch(patch).get('api_key') == '': stored['api_key']=''
    scoped_settings.write(db,AI_SETTINGS_KEY,stored)
    return current


def public_ai_settings(db: Session) -> dict[str, Any]:
    """Settings safe to return over the API (camelCase, key masked)."""
    data = get_ai_settings(db)
    key = data.get("api_key") or ""
    public = {_STORE_TO_API.get(k, k): v for k, v in data.items()}
    public["apiKeySet"] = bool(key)
    public["apiKey"] = MASK if key else ""
    reference=data.get('secret_ref','')
    public['secretRef']=reference
    public['secretRefReady']=bool(reference and key)
    public['secretEnvironmentName']=scoped_settings.environment_name(db,reference)
    public['workspaceId']=db.info.get('workspace_id','default')
    return public


def resolve_ai_settings(db: Session, override: dict[str, Any] | None = None) -> dict[str, Any]:
    """Settings for a scan: global config, optionally overridden per-scan."""
    data = get_ai_settings(db)
    if override:
        patch=normalize_ai_patch(override)
        for key,value in patch.items():
            if key not in ('api_key','secret_ref') and value not in (None,''):data[key]=value
    return data


# --------------------------------------------------------------------------- #
# Policy (release gate) settings
# --------------------------------------------------------------------------- #
_POLICY_ALLOWED = {"name", "defaultAction", "blockOn", "exemptions", "warnOnReview"}


def get_policy_settings(db: Session) -> dict[str, Any]:
    """Current release policy: defaults overlaid with persisted overrides."""
    data = default_policy()
    data.update({k:v for k,v in scoped_settings.read(db,POLICY_SETTINGS_KEY).items() if k in _POLICY_ALLOWED})
    return data


def set_policy_settings(db: Session, patch: dict[str, Any]) -> dict[str, Any]:
    """Merge a validated patch into the persisted policy configuration."""
    current = get_policy_settings(db)
    for key, value in patch.items():
        if key not in _POLICY_ALLOWED:
            continue
        if key == "blockOn":
            value = [str(s).strip().lower() for s in (value or []) if str(s).strip().lower() in ("critical", "high", "medium", "low")]
        elif key == "exemptions":
            value = [str(s).strip() for s in (value or []) if str(s).strip()]
        elif key == "warnOnReview":
            value = bool(value)
        current[key] = value
    scoped_settings.write(db,POLICY_SETTINGS_KEY,current)
    return current
