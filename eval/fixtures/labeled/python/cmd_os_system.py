import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    host = request.args.get("host", "")
    os.system("nslookup " + host)
    return "done"
