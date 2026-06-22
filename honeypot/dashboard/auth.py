from __future__ import annotations

from itsdangerous import BadSignature, URLSafeTimedSerializer

COOKIE_NAME = "dash_session"
_MAX_AGE = 60 * 60 * 12  # 12h


def make_session_cookie(secret: str) -> str:
    return URLSafeTimedSerializer(secret).dumps("ok")


def verify_session(cookie: str | None, secret: str) -> bool:
    if not cookie:
        return False
    try:
        URLSafeTimedSerializer(secret).loads(cookie, max_age=_MAX_AGE)
        return True
    except (BadSignature, Exception):
        return False
