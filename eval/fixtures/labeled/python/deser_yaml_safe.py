import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def config():
    data = yaml.safe_load(request.get_data())
    return {"keys": list(data)}
