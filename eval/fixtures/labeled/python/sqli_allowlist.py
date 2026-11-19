import sqlite3
from flask import Flask, request

app = Flask(__name__)
SORTABLE = {"name": "name", "created": "created_at", "price": "price"}


@app.route("/products")
def products():
    column = SORTABLE.get(request.args.get("sort", "name"), "name")
    conn = sqlite3.connect("shop.db")
    rows = conn.execute(f"SELECT id, name, price FROM products ORDER BY {column}").fetchall()
    return {"products": rows}
