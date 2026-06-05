from slowapi import Limiter
from slowapi.util import get_remote_address

_key_store = None


def set_key_store(store):
    global _key_store
    _key_store = store


def _get_key(request):
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return api_key
    return get_remote_address(request)


limiter = Limiter(key_func=_get_key)

TIER_LIMITS = {"free": "30/minute", "pro": "200/minute", "enterprise": "10000/minute"}


def get_tier_limit(key: str) -> str:
    if _key_store and key:
        tier = _key_store.get_tier(key)
        return TIER_LIMITS.get(tier, "30/minute")
    return "30/minute"
