import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def users():
    name = request.args.get("name", "")
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT id, email FROM users WHERE name = ?", (name,))
    return {"users": cur.fetchall()}
