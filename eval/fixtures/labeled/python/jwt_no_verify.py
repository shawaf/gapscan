import jwt
from flask import Flask, request

app = Flask(__name__)


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    return {"user": claims.get("sub")}
