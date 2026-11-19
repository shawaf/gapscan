import zipfile

from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    with open("/tmp/in.zip", "wb") as fh:
        fh.write(request.get_data())
    with zipfile.ZipFile("/tmp/in.zip") as zf:
        zf.extractall("/srv/uploads")
    return "ok"
