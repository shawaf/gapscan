import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def config():
    data = yaml.load(request.get_data(), Loader=yaml.Loader)
    return {"keys": list(data)}
