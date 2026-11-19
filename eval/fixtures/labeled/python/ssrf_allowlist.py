from urllib.parse import urlparse

import requests
from flask import Flask, request, abort

app = Flask(__name__)
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


@app.route("/preview")
def preview():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url, timeout=5).text[:2000]
