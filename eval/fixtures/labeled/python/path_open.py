from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args.get("file", "")
    with open("/srv/uploads/" + name, "rb") as fh:
        return fh.read()
