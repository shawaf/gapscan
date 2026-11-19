import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/archive")
def archive():
    folder = request.form["folder"]
    proc = subprocess.Popen(f"tar czf /tmp/backup.tgz {folder}", shell=True)
    proc.wait()
    return "ok"
