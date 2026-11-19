from flask import Flask, render_template, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/comment")
def comment():
    body = Markup(request.args.get("body", ""))
    return render_template("comment.html", body=body)
