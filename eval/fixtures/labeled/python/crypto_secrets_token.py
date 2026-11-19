import secrets


def make_reset_token() -> str:
    return secrets.token_urlsafe(32)
