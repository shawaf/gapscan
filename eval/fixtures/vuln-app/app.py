"""Deliberately vulnerable sample for GapScan tests. Never run this."""
import hashlib
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # SQL injection
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # command injection


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))  # insecure deserialization


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # weak hash


def register(username, password):
    return username, hash_password(password)  # caller of the weak-hash function
