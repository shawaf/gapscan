from flask import Flask, redirect, request

app = Flask(__name__)
PAGES = {"home": "/", "account": "/account", "billing": "/billing"}


@app.route("/login/done")
def done():
    target = PAGES.get(request.args.get("next", ""), "/")
    return redirect(target)
