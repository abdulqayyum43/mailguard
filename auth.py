from datetime import datetime, UTC
from fastapi import Security, HTTPException, status, Request
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
ADMIN_KEY_HEADER = APIKeyHeader(name="X-Admin-Secret", auto_error=False)


class APIKeyStore:
    def __init__(self, initial_keys: set[str]):
        self._keys: dict[str, dict] = {
            k: {"active": True, "tier": self._infer_tier(k), "expires_at": None}
            for k in initial_keys if k.strip()
        }

    @staticmethod
    def _infer_tier(key: str) -> str:
        if key.startswith("mailg-ent-") or key.startswith("mailg-enterprise-"):
            return "enterprise"
        if key.startswith("mailg-pro-"):
            return "pro"
        return "free"

    def is_valid(self, key: str) -> bool:
        entry = self._keys.get(key)
        if not entry or not entry["active"]:
            return False
        expires_at = entry.get("expires_at")
        if expires_at and datetime.fromisoformat(expires_at) < datetime.now(UTC):
            return False
        return True

    def get_tier(self, key: str) -> str:
        return self._keys.get(key, {}).get("tier", "free")

    def add_key(self, key: str, tier: str = "free", expires_at: str | None = None) -> None:
        self._keys[key] = {"active": True, "tier": tier, "expires_at": expires_at}

    def revoke_key(self, key: str) -> bool:
        if key in self._keys:
            self._keys[key]["active"] = False
            return True
        return False

    def all_keys(self) -> list[dict]:
        now = datetime.now(UTC)
        result = []
        for k, v in self._keys.items():
            expires_at = v.get("expires_at")
            expired = bool(expires_at) and datetime.fromisoformat(expires_at) < now
            result.append({"key": k, "tier": v["tier"], "active": v["active"],
                           "expires_at": expires_at, "expired": expired})
        return result


def get_key_store(request: Request) -> APIKeyStore:
    return request.app.state.key_store


async def require_api_key(request: Request, api_key: str = Security(API_KEY_HEADER)) -> str:
    store: APIKeyStore = request.app.state.key_store
    from config import settings
    rapidapi_secret = request.headers.get("X-RapidAPI-Proxy-Secret", "")
    if settings.rapidapi_proxy_secret and rapidapi_secret == settings.rapidapi_proxy_secret:
        return "rapidapi-proxy"
    if not api_key or not store.is_valid(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Pass it in the X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key


async def require_admin(request: Request, admin_key: str = Security(ADMIN_KEY_HEADER)) -> str:
    from config import settings
    if not admin_key or admin_key != settings.admin_secret:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid or missing admin secret.")
    return admin_key
