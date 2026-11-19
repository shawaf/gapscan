from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = escape(request.args.get("name", ""))
    return f"<h1>Hello {name}</h1>"
