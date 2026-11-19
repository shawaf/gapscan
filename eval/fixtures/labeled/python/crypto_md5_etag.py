import hashlib


def etag_for(body: bytes) -> str:
    # Cache validator for static assets; collisions only cause an extra download.
    return hashlib.md5(body).hexdigest()
