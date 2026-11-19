import requests

API_KEY = "sk_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
BASE_URL = "https://api.acmepay.io/v1"


def charge(amount: int, customer: str):
    return requests.post(f"{BASE_URL}/charges", headers={"Authorization": f"Bearer {API_KEY}"},
                         json={"amount": amount, "customer": customer}, timeout=10)
