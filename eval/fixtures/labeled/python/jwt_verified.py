import os

import jwt
from flask import Flask, abort, request

app = Flask(__name__)
SECRET = os.environ["JWT_SECRET"]


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        abort(401)
    return {"user": claims.get("sub")}
