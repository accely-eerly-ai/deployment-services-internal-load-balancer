

def _choose_final_status_and_headers(attempts: list) -> tuple[int, dict]:
    """
    attempts: list of dicts with keys like {"status": int|None, "headers": {...}, "error": str|None}
    returns: (status_code, extra_headers)
    """
    statuses = [a.get("status") for a in attempts if a.get("status") is not None]
    errors   = [a.get("error") or "" for a in attempts]

    def hdrs_for(code: int) -> dict:
        for a in attempts:
            if a.get("status") == code:
                return a.get("headers") or {}
        return {}

    if statuses and all(s == 404 for s in statuses):
        return 404, {}

    if 429 in statuses:
        h = hdrs_for(429)
        extra = {}
        ra = h.get("retry-after") or h.get("Retry-After")
        if ra:
            extra["Retry-After"] = ra
        return 429, extra

    if 504 in statuses or any("Timeout" in e for e in errors):
        return 504, {}

    if statuses and set(statuses).issubset({401, 403}):
        return (401 if all(s == 401 for s in statuses) else 403), {}

    if any(s >= 500 for s in statuses):
        return 502, {}

    return 502, {}