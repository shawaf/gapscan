from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/profile")
def profile():
    return render_template("profile.html", name=request.args.get("name", ""))
