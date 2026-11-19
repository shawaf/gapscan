import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file

app = Flask(__name__)
db = sqlite3.connect("x.db")


def find_user(name):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # VULN:sql
    return cur.fetchall()


def find_by_id(uid):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))  # SAFE
    return cur.fetchall()


def run(cmd):
    return subprocess.check_output(cmd, shell=True)  # VULN:cmd


@app.route("/user")
def user():
    name = request.args.get("name")
    return str(find_user(name))


@app.route("/user_id")
def user_id():
    uid = int(request.args.get("id"))  # SAFE-FLOW
    return str(find_by_id(uid))


@app.route("/user_safe")
def user_safe():
    return str(find_by_id(request.args.get("id")))  # SAFE-FLOW


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return run("ping -c1 " + host)  # VULN:xss (command output reflected)


@app.route("/ping_fixed")
def ping_fixed():
    return run("ping -c1 localhost")


@app.route("/file/<path:fname>")
def file(fname):
    return send_file("/srv/" + fname)  # VULN:path


@app.route("/file_safe")
def file_safe():
    fname = os.path.basename(request.args.get("f"))  # SAFE-FLOW
    return send_file("/srv/" + fname)  # SAFE


@app.route("/hello")
def hello():
    who = request.args.get("who", "")
    return render_template_string("<h1>Hello " + who + "</h1>")  # VULN:xss


@app.route("/hello_static")
def hello_static():
    return render_template_string("<h1>Hello</h1>")  # SAFE


@app.route("/go")
def go():
    return redirect(request.args.get("next"))  # VULN:redirect


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text  # VULN:ssrf+xss


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.get_data())  # VULN:deserialization
    cfg = yaml.load(request.data)  # VULN:deserialization
    safe = yaml.safe_load(request.data)  # SAFE
    return str(obj)  # VULN:xss


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))  # VULN:code+xss


@app.route("/lit")
def lit():
    expr = "1+1"
    return str(eval(expr))  # SAFE


@app.route("/overwritten")
def overwritten():
    cmd = request.args.get("c")  # SAFE-FLOW
    cmd = "uptime"
    return run(cmd)


@app.route("/loop")
def loop():
    for part in request.args.getlist("p"):
        run(part)
