import os
from flask import Flask, request, abort

app = Flask(__name__)
BASE = os.path.realpath("/srv/uploads")


@app.route("/download")
def download():
    target = os.path.realpath(os.path.join(BASE, request.args.get("file", "")))
    if not target.startswith(BASE + os.sep):
        abort(403)
    with open(target, "rb") as fh:
        return fh.read()
