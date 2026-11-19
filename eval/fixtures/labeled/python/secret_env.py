import os

import requests

BASE_URL = "https://api.acmepay.io/v1"


def charge(amount: int, customer: str):
    key = os.environ["PAYMENTS_API_KEY"]
    return requests.post(f"{BASE_URL}/charges", headers={"Authorization": f"Bearer {key}"},
                         json={"amount": amount, "customer": customer}, timeout=10)
