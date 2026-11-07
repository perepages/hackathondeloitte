import os
from urllib.parse import quote

import httpx
from dotenv import load_dotenv


load_dotenv()
BASE_URL = os.getenv("SOC_API_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT_SECONDS = float(os.getenv("SOC_API_TIMEOUT_SECONDS", "15"))


class SocAPIError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _get(path: str, params: dict | None = None):
    url = f"{BASE_URL}{path}"
    try:
        response = httpx.get(url, params=params, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        raise SocAPIError(
            f"La API SOC respondió HTTP {exc.response.status_code} para {path}: "
            f"{exc.response.text[:300]}",
            status_code=exc.response.status_code,
        ) from exc
    except httpx.HTTPError as exc:
        raise SocAPIError(
            f"No se pudo conectar con {url}. Comprueba que la API está activa. ({exc})"
        ) from exc
    except ValueError as exc:
        raise SocAPIError(f"La API devolvió JSON inválido para {path}") from exc


def list_alerts(status: str = "new", limit: int = 50, offset: int = 0) -> dict:
    return _get(
        "/alerts",
        params={"status": status, "limit": limit, "offset": offset},
    )


def get_alert(alert_id: str) -> dict:
    return _get(f"/alerts/{quote(alert_id, safe='')}")


def get_asset(key: str) -> dict:
    return _get(f"/assets/{quote(key, safe='')}")


def get_user(key: str) -> dict:
    return _get(f"/users/{quote(key, safe='')}")


def search_logs(
    source: str,
    *,
    query: str = "",
    since: str = "",
    until: str = "",
    limit: int = 20,
) -> dict:
    return _get(
        f"/logs/{quote(source, safe='')}",
        params={"q": query, "desde": since, "hasta": until, "limit": limit},
    )


def get_intel(indicator: str) -> dict:
    return _get(f"/intel/{quote(indicator, safe='')}")


def get_sandbox(sha256: str) -> dict:
    return _get(f"/sandbox/{quote(sha256, safe='')}")


def search_changes(query: str = "") -> list[dict]:
    return _get("/changes", params={"q": query})
