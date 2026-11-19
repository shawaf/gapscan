from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/report")
def report():
    return send_file(request.args["path"])
