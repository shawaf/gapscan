import re
import subprocess
from flask import Flask, request, abort

app = Flask(__name__)
HOST = re.compile(r"^[a-z0-9.-]{1,253}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST.fullmatch(host):
        abort(400)
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, check=False)
    return out.stdout
