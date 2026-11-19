import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/orders")
def orders():
    status = request.args.get("status")
    conn = sqlite3.connect("shop.db")
    rows = conn.execute(f"SELECT * FROM orders WHERE status = '{status}' ORDER BY created").fetchall()
    return {"orders": rows}
