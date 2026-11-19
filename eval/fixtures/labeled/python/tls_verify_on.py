import requests


def fetch_report(url: str) -> bytes:
    return requests.get(url, timeout=10).content
