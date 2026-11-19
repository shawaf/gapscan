import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_state():
    state = pickle.loads(request.get_data())
    return {"keys": list(state)}
