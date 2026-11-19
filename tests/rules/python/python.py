import ftplib
import hashlib
import hmac
import io
import json
import logging
import os
import pathlib
import pickle
import random
import re
import secrets
import subprocess
import tarfile
import tempfile
import urllib.parse
import zipfile

import joblib
import jwt
import numpy as np
import pandas as pd
import paramiko
import requests
import torch
import yaml
from Crypto.Cipher import AES, DES
from flask import Flask, abort, redirect, render_template_string, request, send_file
from lxml import etree

app = Flask(__name__)


# --- sqli-string-built -------------------------------------------------------------------------
def sql_cases(cur, name, items):
    # ruleid: gapscan.python.sqli-string-built
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: gapscan.python.sqli-string-built
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ruleid: gapscan.python.sqli-string-built
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: gapscan.python.sqli-string-built
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ok: gapscan.python.sqli-string-built
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    # ok: gapscan.python.sqli-string-built
    cur.execute("SELECT * FROM users " + "WHERE active = 1")
    # ok: gapscan.python.sqli-string-built
    cur.executemany("INSERT INTO t VALUES (?, ?)", items)


# --- command-injection ---------------------------------------------------------------------------
def command_cases(host):
    # ruleid: gapscan.python.command-injection
    os.system("ping -c 1 " + host)
    # ruleid: gapscan.python.command-injection
    subprocess.run("ping " + host, shell=True)
    # ruleid: gapscan.python.command-injection
    os.popen(f"nslookup {host}")
    # ok: gapscan.python.command-injection
    os.system("uptime")
    # ok: gapscan.python.command-injection
    subprocess.run(["ping", "-c", "1", host])
    # ok: gapscan.python.command-injection
    subprocess.run("ls -l", shell=True)


# --- eval-exec -----------------------------------------------------------------------------------
def eval_cases(expr):
    # ruleid: gapscan.python.eval-exec
    eval(expr)
    # ruleid: gapscan.python.eval-exec
    exec(expr)
    # ok: gapscan.python.eval-exec
    eval("1 + 1")


# --- unsafe-deserialization ------------------------------------------------------------------------
def deserialize_cases(blob, text):
    # ruleid: gapscan.python.unsafe-deserialization
    pickle.loads(blob)
    # ruleid: gapscan.python.unsafe-deserialization
    yaml.load(text)
    # ruleid: gapscan.python.unsafe-deserialization
    yaml.load(text, Loader=yaml.Loader)
    # ok: gapscan.python.unsafe-deserialization
    yaml.safe_load(text)
    # ok: gapscan.python.unsafe-deserialization
    yaml.load(text, Loader=yaml.SafeLoader)


# --- weak-hash -------------------------------------------------------------------------------------
def hash_cases(data):
    # ruleid: gapscan.python.weak-hash
    hashlib.md5(data).hexdigest()
    # ruleid: gapscan.python.weak-hash
    hashlib.sha1(data).hexdigest()
    # ok: gapscan.python.weak-hash
    hashlib.sha256(data).hexdigest()


# --- weak-cipher -------------------------------------------------------------------------------------
def cipher_cases(key, iv):
    # ruleid: gapscan.python.weak-cipher
    AES.new(key, AES.MODE_ECB)
    # ruleid: gapscan.python.weak-cipher
    DES.new(key, DES.MODE_CBC, iv)
    # ok: gapscan.python.weak-cipher
    AES.new(key, AES.MODE_GCM, nonce=iv)


# --- tls-verification-disabled ---------------------------------------------------------------------------
def tls_cases(url, ctx):
    # ruleid: gapscan.python.tls-verification-disabled
    requests.get(url, verify=False)
    # ruleid: gapscan.python.tls-verification-disabled
    ctx.check_hostname = False
    # ok: gapscan.python.tls-verification-disabled
    requests.get(url, timeout=5)
    # ok: gapscan.python.tls-verification-disabled
    requests.get(url, verify="/etc/ssl/ca.pem")


# --- hardcoded-secret ----------------------------------------------------------------------------------
# ruleid: gapscan.python.hardcoded-secret
password = "hunter2hunter2"
# ruleid: gapscan.python.hardcoded-secret
API_KEY = "sk_live_51HxxxxxxxxxxxxxxxxYYY"
# ruleid: gapscan.python.hardcoded-secret
CONFIG = {"db_password": "correct-horse-battery"}
# ruleid: gapscan.python.hardcoded-secret
conn = connect(host="db", password="correct-horse-battery")
# ok: gapscan.python.hardcoded-secret
password = os.environ["DB_PASSWORD"]
# ok: gapscan.python.hardcoded-secret
PASSWORD_FIELD = "password"
# ok: gapscan.python.hardcoded-secret
SECRET = "secret"
# ok: gapscan.python.hardcoded-secret
token = ""
# ok: gapscan.python.hardcoded-secret
secret = "changeme"
# ok: gapscan.python.hardcoded-secret
CONFIG2 = {"password": os.getenv("PW")}
# ok: gapscan.python.hardcoded-secret
conn2 = connect(host="db", password=os.getenv("PW"))


# --- debug-enabled ---------------------------------------------------------------------------------------
# ruleid: gapscan.python.debug-enabled
app.run(debug=True)
# ok: gapscan.python.debug-enabled
app.run(debug=False)


# --- jwt-verification-off --------------------------------------------------------------------------------
def jwt_cases(token, key):
    # ruleid: gapscan.python.jwt-verification-off
    jwt.decode(token, options={"verify_signature": False})
    # ruleid: gapscan.python.jwt-verification-off
    jwt.decode(token, key, algorithms=["none"])
    # ok: gapscan.python.jwt-verification-off
    jwt.decode(token, key, algorithms=["HS256"])


# --- insecure-random-token -------------------------------------------------------------------------------
def random_cases():
    # ruleid: gapscan.python.insecure-random-token, gapscan.python.weak-random-generator
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    # ruleid: gapscan.python.insecure-random-token, gapscan.python.weak-random-generator
    otp = random.randint(100000, 999999)
    # ok: gapscan.python.insecure-random-token
    reset_token2 = secrets.token_urlsafe(32)
    # ok: gapscan.python.insecure-random-token
    # ruleid: gapscan.python.weak-random-generator
    colour = random.choice(["red", "green"])
    return reset_token, otp, reset_token2, colour


# --- xxe-enabled -------------------------------------------------------------------------------------------
# ruleid: gapscan.python.xxe-enabled
parser = etree.XMLParser(resolve_entities=True)
# ok: gapscan.python.xxe-enabled
parser2 = etree.XMLParser(resolve_entities=False, no_network=True)


# --- insecure-temp-file -------------------------------------------------------------------------------------
# ruleid: gapscan.python.insecure-temp-file
name = tempfile.mktemp()
# ok: gapscan.python.insecure-temp-file
fd, name2 = tempfile.mkstemp()


# --- unsafe-html-marking ---------------------------------------------------------------------------------------
def html_cases(user_text):
    # ruleid: gapscan.python.unsafe-html-marking
    mark_safe(user_text)
    # ok: gapscan.python.unsafe-html-marking
    mark_safe("<b>fixed</b>")


# --- cookie-flags-off ------------------------------------------------------------------------------------------
def cookie_cases(resp):
    # ruleid: gapscan.python.cookie-flags-off
    resp.set_cookie("sid", "x", secure=False)
    # ruleid: gapscan.python.cookie-flags-off
    resp.set_cookie("sid", "x", httponly=False)
    # ok: gapscan.python.cookie-flags-off
    resp.set_cookie("sid", "x", secure=True, httponly=True)


# --- csrf-protection-off -----------------------------------------------------------------------------------------
# ruleid: gapscan.python.csrf-protection-off
@csrf_exempt
def webhook(request):
    return None


# ok: gapscan.python.csrf-protection-off
def form_view(request):
    return None


# --- cors-allow-all ------------------------------------------------------------------------------------------------
# ruleid: gapscan.python.cors-allow-all
CORS_ALLOW_ALL_ORIGINS = True
# ok: gapscan.python.cors-allow-all
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]


# --- ssh-host-key-not-checked ---------------------------------------------------------------------------------------
def ssh_cases(client):
    # ruleid: gapscan.python.ssh-host-key-not-checked
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # ok: gapscan.python.ssh-host-key-not-checked
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


# =================== taint rules =====================================================================================
@app.route("/user")
def taint_sql():
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + uid
    # ruleid: gapscan.python.taint-sqli, gapscan.python.sqli-string-built
    cursor.execute(query)
    safe_id = int(request.args.get("id"))
    safe_query = "SELECT * FROM users WHERE id = " + str(safe_id)
    # ok: gapscan.python.taint-sqli
    # ruleid: gapscan.python.sqli-string-built
    cursor.execute(safe_query)
    # ok: gapscan.python.taint-sqli
    cursor.execute("SELECT * FROM users WHERE id = %s", (request.args.get("id"),))


@app.route("/ping")
def taint_command():
    host = request.args.get("host")
    cmd = "ping -c 1 " + host
    # ruleid: gapscan.python.command-injection, gapscan.python.taint-command-injection
    os.system(cmd)
    # ok: gapscan.python.taint-command-injection
    # ruleid: gapscan.python.taint-argument-injection
    subprocess.run(["ping", "-c", "1", host])


@app.route("/download")
def taint_path():
    name = request.args.get("file")
    path = os.path.join("/srv/files", name)
    # ruleid: gapscan.python.taint-path-traversal
    return send_file(path)


@app.route("/download2")
def taint_path_safe():
    name = os.path.basename(request.args.get("file"))
    # ok: gapscan.python.taint-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/fetch")
def taint_ssrf():
    target = request.args.get("url")
    # ruleid: gapscan.python.taint-ssrf, gapscan.python.taint-xss
    return requests.get(target).text


@app.route("/fixed")
def not_ssrf():
    # ok: gapscan.python.taint-ssrf
    return requests.get("https://api.example.com/status").text


@app.route("/hello")
def taint_template():
    page = "<h1>Hello " + request.args.get("name") + "</h1>"
    # ruleid: gapscan.python.taint-template-injection, gapscan.python.taint-xss
    return render_template_string(page)


@app.route("/hello2")
def template_ok():
    # ok: gapscan.python.taint-template-injection, gapscan.python.taint-xss
    return render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name"))


@app.route("/go")
def taint_redirect():
    nxt = request.args.get("next")
    # ruleid: gapscan.python.taint-open-redirect
    return redirect(nxt)


@app.route("/go2")
def redirect_ok():
    # ok: gapscan.python.taint-open-redirect
    return redirect("/home")


@app.route("/calc")
def taint_code():
    expr = request.args.get("expr")
    # ruleid: gapscan.python.eval-exec, gapscan.python.taint-code-injection, gapscan.python.taint-xss
    return str(eval(expr))


# =================== round 1 additions ===============================================================================
def random_cases2():
    # ruleid: gapscan.python.weak-random-generator
    value = random.random()
    # ok: gapscan.python.weak-random-generator
    token = secrets.token_hex(16)
    return value, token


def ldap_cases(conn, user):
    # ruleid: gapscan.python.ldap-filter-string-built
    conn.search("ou=users", f"(uid={user})")
    # ok: gapscan.python.ldap-filter-string-built
    conn.search("ou=users", "(uid=admin)")


def xpath_cases(tree, name):
    # ruleid: gapscan.python.xpath-string-built
    tree.xpath(f"//user[@name='{name}']")
    # ok: gapscan.python.xpath-string-built
    tree.xpath("//user[@name=$n]", n=name)


@app.route("/xss")
def taint_xss():
    name = request.args.get("name")
    page = f"<h1>Hello {name}</h1>"
    # ruleid: gapscan.python.taint-xss
    return page


@app.route("/xss2")
def taint_xss_safe():
    name = request.args.get("name")
    # ok: gapscan.python.taint-xss
    return "<h1>Hello " + html.escape(name) + "</h1>"


@app.route("/xp")
def taint_xpath():
    name = request.form.get("n")
    query = f"//user[@name='{name}']"
    # ruleid: gapscan.python.taint-xpath-injection, gapscan.python.taint-xss
    return str(tree.xpath(query))


@app.route("/ld")
def taint_ldap():
    uid = request.headers.get("uid")
    flt = f"(&(objectclass=person)(uid={uid}))"
    # ruleid: gapscan.python.taint-ldap-injection
    conn.search("ou=users", flt)


@app.route("/sess")
def taint_session():
    key = request.cookies.get("k")
    # ruleid: gapscan.python.taint-trust-boundary
    flask.session[key] = "12345"
    # ok: gapscan.python.taint-trust-boundary
    flask.session["user"] = "fixed"


@app.route("/collections")
def taint_through_collections():
    param = request.form.get("p")
    items = []
    items.append("safe")
    items.append(param)
    q = "SELECT * FROM t WHERE c = '" + items[1] + "'"
    # ruleid: gapscan.python.taint-sqli, gapscan.python.sqli-string-built
    cursor.execute(q)


# =================== round 2: sanitizers, statement variables, shell -c ===============================================
def sql_built_in_variable(cur, name, User):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    # ruleid: gapscan.python.sqli-string-built
    cur.execute(query)
    stmt = "DELETE FROM users WHERE name = '%s'" % name
    # ruleid: gapscan.python.sqli-string-built
    cur.execute(stmt)
    # ruleid: gapscan.python.sqli-string-built
    User.objects.raw("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: gapscan.python.sqli-string-built
    User.objects.filter(active=True).extra(where=[f"name = '{name}'"])
    fixed = "SELECT * FROM users " + "WHERE active = 1"
    # ok: gapscan.python.sqli-string-built
    cur.execute(fixed)
    param_query = "SELECT * FROM users WHERE name = %s"
    # ok: gapscan.python.sqli-string-built
    cur.execute(param_query, (name,))


def shell_c_cases(value):
    # ruleid: gapscan.python.shell-c-dynamic-command
    subprocess.run(["sh", "-c", f"echo {value}"])
    # ok: gapscan.python.shell-c-dynamic-command
    subprocess.run(["sh", "-c", "echo hello"])
    # ok: gapscan.python.shell-c-dynamic-command
    subprocess.run(["echo", value])
    args = []
    if os.name == "nt":
        args.append("cmd.exe")
        args.append("/c")
    else:
        args.append("sh")
        args.append("-c")
    args.append("grep " + value + " /var/log/app.log")
    # ruleid: gapscan.python.shell-c-dynamic-command
    subprocess.run(args, capture_output=True)


@app.route("/xp-escaped")
def xpath_quote_escaped():
    name = request.form.get("n")
    query = f"//user[@name='{name.replace("'", "&apos;")}']"
    # ok: gapscan.python.taint-xpath-injection
    nodes = tree.xpath(query)
    # ok: gapscan.python.xpath-string-built
    nodes = tree.xpath(f"//user[@name='{name.replace("'", "&apos;")}']")
    return "ok" if nodes else "none"


@app.route("/xp-rejected")
def xpath_quote_rejected():
    name = request.form.get("n")
    if "'" in name:
        abort(400)
    # ok: gapscan.python.taint-xpath-injection
    nodes = tree.xpath(f"//user[@name='{name}']")
    return "ok" if nodes else "none"


@app.route("/go-checked")
def redirect_host_checked():
    nxt = request.args.get("next")
    url = urllib.parse.urlparse(nxt)
    if url.netloc not in ["app.example.com"] or url.scheme != "https":
        abort(400)
    # ok: gapscan.python.taint-open-redirect
    return redirect(nxt)


@app.route("/read")
def path_pathlib():
    base = pathlib.Path("/srv/files")
    p = base / request.args.get("file")
    # ruleid: gapscan.python.taint-path-traversal
    p.read_text()
    return "ok"


@app.route("/read-checked")
def path_pathlib_checked():
    base = pathlib.Path("/srv/files").resolve()
    p = (base / request.args.get("file")).resolve()
    if not p.is_relative_to(base):
        abort(403)
    # ok: gapscan.python.taint-path-traversal
    p.read_text()
    return "ok"


@app.route("/read-realpath")
def path_realpath_checked():
    target = os.path.realpath(os.path.join("/srv/files", request.args.get("file")))
    if not target.startswith("/srv/files/"):
        abort(403)
    # ok: gapscan.python.taint-path-traversal
    with open(target) as fh:
        fh.read()
    return "ok"


@app.route("/read-dots")
def path_dots_rejected():
    name = request.args.get("file")
    if ".." in name:
        abort(400)
    # ok: gapscan.python.taint-path-traversal
    with open(f"/srv/files/{name}") as fh:
        fh.read()
    return "ok"


@app.route("/exists")
def path_exists():
    name = request.args.get("file")
    # ruleid: gapscan.python.taint-path-traversal
    found = os.path.exists("/srv/files/" + name)
    return "ok" if found else "missing"


@app.route("/xp-stringio")
def xpath_through_stringio():
    buf = io.StringIO()
    buf.write("//user[@name='")
    buf.write(request.form.get("n"))
    buf.write("']")
    # ruleid: gapscan.python.taint-xpath-injection
    nodes = tree.xpath(buf.getvalue())
    return "ok" if nodes else "none"


# --- unsafe-model-load ---------------------------------------------------------------------------------------------
def model_cases(path):
    # ruleid: gapscan.python.unsafe-model-load
    model = torch.load(path)
    # ok: gapscan.python.unsafe-model-load
    weights = torch.load(path, weights_only=True)
    # ruleid: gapscan.python.unsafe-model-load
    arr = np.load(path, allow_pickle=True)
    # ok: gapscan.python.unsafe-model-load
    plain = np.load(path)
    # ruleid: gapscan.python.unsafe-model-load
    clf = joblib.load(path)
    # ruleid: gapscan.python.unsafe-model-load
    frame = pd.read_pickle(path)
    return model, weights, arr, plain, clf, frame


# --- tar-extract-unfiltered / zip-extract-unchecked / archive-member-path-joined -----------------------------------
def archive_cases(upload, dest):
    with tarfile.open(upload) as tar:
        # ruleid: gapscan.python.tar-extract-unfiltered
        tar.extractall(dest)
    with tarfile.open(upload) as tar:
        # ok: gapscan.python.tar-extract-unfiltered
        tar.extractall(dest, filter="data")
    with zipfile.ZipFile(upload) as zf:
        # ruleid: gapscan.python.zip-extract-unchecked
        zf.extractall(dest)
    with zipfile.ZipFile(upload) as zf:
        for info in zf.infolist():
            if info.file_size > 10_000_000:
                raise ValueError("member too large")
        # ok: gapscan.python.zip-extract-unchecked
        zf.extractall(dest)


def manual_unzip(zf, dest):
    for member in zf.infolist():
        # ruleid: gapscan.python.archive-member-path-joined
        with open(os.path.join(dest, member.filename), "wb") as out:
            out.write(zf.read(member))


def manual_unzip_checked(zf, dest):
    root = os.path.realpath(dest)
    for member in zf.infolist():
        target = os.path.realpath(os.path.join(root, member.filename))
        if not target.startswith(root + os.sep):
            raise ValueError("unsafe member")
        # ok: gapscan.python.archive-member-path-joined
        with open(target, "wb") as out:
            out.write(zf.read(member))


# --- timing-unsafe-secret-compare ----------------------------------------------------------------------------------
def webhook_check(body, received_signature, key):
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    # ruleid: gapscan.python.timing-unsafe-secret-compare
    if received_signature != expected:
        return False
    # ok: gapscan.python.timing-unsafe-secret-compare
    if not hmac.compare_digest(received_signature, expected):
        return False
    # ok: gapscan.python.timing-unsafe-secret-compare
    if received_signature == None:
        return False
    # ok: gapscan.python.timing-unsafe-secret-compare
    return len(received_signature) == 64


def api_key_check(request_key, settings):
    # ruleid: gapscan.python.timing-unsafe-secret-compare
    return request_key == settings.API_KEY


def not_a_secret_compare(finding, path, entry, Category):
    # ok: gapscan.python.timing-unsafe-secret-compare
    if finding.category == Category.SECRET:
        return True
    # ok: gapscan.python.timing-unsafe-secret-compare
    return hashlib.sha256(path.read_bytes()).hexdigest() != entry.sha256


def sql_placeholders(cur, ids):
    # ok: gapscan.python.sqli-string-built
    cur.execute(f"SELECT * FROM t WHERE id IN ({','.join('?' * len(ids))})", ids)
    marks = ", ".join(["%s"] * len(ids))
    # ok: gapscan.python.sqli-string-built
    cur.execute(f"DELETE FROM t WHERE id IN ({marks})", ids)


# --- assert-used-for-authorization ---------------------------------------------------------------------------------
def delete_post(user, post):
    # ruleid: gapscan.python.assert-used-for-authorization
    assert user.is_admin, "admins only"
    # ok: gapscan.python.assert-used-for-authorization
    assert post is not None
    if not user.has_perm("blog.delete_post"):
        raise PermissionError("not allowed")
    post.delete()


# --- allowed-hosts-wildcard / hardcoded-app-secret-key -------------------------------------------------------------
# ruleid: gapscan.python.allowed-hosts-wildcard
ALLOWED_HOSTS = ["*"]
# ok: gapscan.python.allowed-hosts-wildcard
ALLOWED_HOSTS = ["app.example.com"]

# ruleid: gapscan.python.hardcoded-app-secret-key
app.secret_key = "s3cr3t-d3v-k3y-9f8a7"
# ok: gapscan.python.hardcoded-app-secret-key
app.secret_key = os.environ["FLASK_SECRET_KEY"]


# --- xmlrpc-dotted-names -------------------------------------------------------------------------------------------
def rpc_server(server, service):
    # ruleid: gapscan.python.xmlrpc-dotted-names
    server.register_instance(service, allow_dotted_names=True)
    # ok: gapscan.python.xmlrpc-dotted-names
    server.register_instance(service)


# --- taint-regex-injection -----------------------------------------------------------------------------------------
@app.route("/grep")
def regex_search():
    pattern = request.args.get("q")
    # ruleid: gapscan.python.taint-regex-injection
    matcher = re.compile(pattern)
    # ok: gapscan.python.taint-regex-injection
    literal = re.compile(re.escape(pattern))
    return "ok" if matcher and literal else "none"


# =================== LLM applications ================================================================================
def llm_code(client, question):
    resp = client.chat.completions.create(model="gpt-4.1", messages=[{"role": "user", "content": question}])
    code = resp.choices[0].message.content
    # ruleid: gapscan.python.llm-output-code-execution, gapscan.python.eval-exec
    exec(code)
    # ok: gapscan.python.llm-output-code-execution
    exec("print('fixed')")


def llm_data(client, question):
    resp = client.messages.create(model="claude-sonnet-4-5", max_tokens=200, messages=[{"role": "user", "content": question}])
    # ok: gapscan.python.llm-output-code-execution
    data = json.loads(resp.content[0].text)
    return data


def llm_shell(llm, task):
    command = llm.invoke(f"Write one shell command that does: {task}").content
    # ruleid: gapscan.python.llm-output-shell-command, gapscan.python.command-injection
    subprocess.run(command, shell=True)
    # ok: gapscan.python.llm-output-shell-command
    subprocess.run(["ls", "-l"])


def llm_sql(client, cur, question):
    resp = client.responses.create(model="gpt-4.1", input=f"SQL for: {question}")
    # ruleid: gapscan.python.llm-output-sql
    cur.execute(resp.output_text)
    # ok: gapscan.python.llm-output-sql
    cur.execute("SELECT name FROM products WHERE id = %s", (question,))


def agent_tools(llm, df):
    # ruleid: gapscan.python.llm-agent-dangerous-tool
    tools = [PythonREPLTool()]
    # ruleid: gapscan.python.llm-agent-dangerous-tool
    agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)
    # ok: gapscan.python.llm-agent-dangerous-tool
    safe_agent = create_pandas_dataframe_agent(llm, df)
    # ruleid: gapscan.python.llm-agent-unrestricted-requests
    toolkit = RequestsToolkit(requests_wrapper=TextRequestsWrapper(), allow_dangerous_requests=True)
    # ok: gapscan.python.llm-agent-unrestricted-requests
    other = RequestsToolkit(requests_wrapper=TextRequestsWrapper())
    # ruleid: gapscan.python.llm-unsafe-index-deserialization
    index = FAISS.load_local("index", embeddings, allow_dangerous_deserialization=True)
    # ok: gapscan.python.llm-unsafe-index-deserialization
    fresh = FAISS.from_documents(docs, embeddings)
    return tools, agent, safe_agent, toolkit, other, index, fresh


# ruleid: gapscan.python.llm-provider-key-hardcoded, gapscan.python.hardcoded-secret
OPENAI_CLIENT = OpenAI(api_key="sk-proj-Q7wErTy8UiOp9AsDfGh2JkLzXcVbNm4Q1w2E3r4T5y6U7i8O")
# ok: gapscan.python.llm-provider-key-hardcoded
OPENAI_CLIENT_ENV = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
# ok: gapscan.python.llm-provider-key-hardcoded
EXAMPLE_KEY = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


@app.route("/xss-helper")
def xss_app_escape_helper():
    name = request.args.get("name")
    # ok: gapscan.python.taint-xss
    return "<h1>Hello " + utils.escape_html(name) + "</h1>"


@app.route("/xss-regex-escape")
def xss_regex_escape_is_not_html():
    name = request.args.get("name")
    # ruleid: gapscan.python.taint-xss
    return "<h1>Hello " + re.escape(name) + "</h1>"


# =================== round 3 ===========================================================================================
@app.route("/login-api", methods=["POST"])
def mongo_login():
    body = request.get_json()
    # ruleid: gapscan.python.taint-nosql-injection
    user = db.users.find_one({"name": body["name"], "password_hash": body["hash"]})
    # ok: gapscan.python.taint-nosql-injection
    same = db.users.find_one({"name": str(body["name"])})
    return "ok" if user and same else "no"


def mongo_where(db, name):
    # ruleid: gapscan.python.mongo-where-string-built
    return db.users.find({"$where": f"this.name == '{name}'"})


def mongo_where_ok(db, name):
    # ok: gapscan.python.mongo-where-string-built
    return db.users.find({"name": name})


def log_cases(logger, user, password, token_count):
    # ruleid: gapscan.python.secret-in-log
    logger.info(f"login for {user.email} with {password}")
    # ruleid: gapscan.python.secret-in-log
    logging.debug("refresh with %s", user.refresh_token)
    # ok: gapscan.python.secret-in-log
    logger.info("login for %s", user.email)
    # ok: gapscan.python.secret-in-log
    logger.info(f"used {token_count} tokens")


def permission_cases(path):
    # ruleid: gapscan.python.world-writable-permissions
    os.chmod(path, 0o777)
    # ruleid: gapscan.python.world-writable-permissions
    os.makedirs(path, mode=0o766, exist_ok=True)
    # ok: gapscan.python.world-writable-permissions
    os.chmod(path, 0o600)
    # ok: gapscan.python.world-writable-permissions
    os.makedirs(path, 0o755, exist_ok=True)


def transfer(host):
    # ruleid: gapscan.python.cleartext-protocol
    ftp = ftplib.FTP(host)
    # ok: gapscan.python.cleartext-protocol
    ftps = ftplib.FTP_TLS(host)
    return ftp, ftps


@app.route("/assistant", methods=["POST"])
def assistant():
    persona = request.form.get("persona")
    question = request.form.get("q")
    messages = [
        # ruleid: gapscan.python.taint-llm-prompt-injection
        {"role": "system", "content": f"You are {persona}. Answer politely."},
        # ok: gapscan.python.taint-llm-prompt-injection
        {"role": "user", "content": question},
    ]
    resp = client.chat.completions.create(model="gpt-4.1", messages=messages)
    # ok: gapscan.python.taint-llm-prompt-injection
    other = client.messages.create(model="claude-sonnet-4-5", max_tokens=100, system="You answer briefly.", messages=[{"role": "user", "content": question}])
    return "ok" if resp and other else "no"


# =================== round 4: more sources and sinks ===================================================================
class ReportView:
    def get(self, *args):
        name = self.request.GET.get("name")
        # ruleid: gapscan.python.taint-command-injection, gapscan.python.command-injection
        out = subprocess.getoutput("wc -l /srv/reports/" + name)
        # ok: gapscan.python.taint-command-injection
        count = subprocess.getoutput("wc -l /srv/reports/daily.csv")
        return out, count


@app.route("/proxy")
def proxy_with_session():
    target = request.args.get("url")
    session = requests.Session()
    # ruleid: gapscan.python.taint-ssrf
    page = session.get(target, timeout=5)
    # ok: gapscan.python.taint-ssrf
    status = session.get("https://status.example.com/", timeout=5)
    return "ok" if page and status else "no"


@app.route("/go-header")
def redirect_header():
    resp = flask.Response(status=302)
    # ruleid: gapscan.python.taint-open-redirect
    resp.headers["Location"] = request.args.get("next")
    responses.append(resp)


# =================== round 5: allow-lists, validation, JSON responses =================================================
SORT_COLUMNS = {"name": "name", "newest": "created_at"}
HOSTNAME = re.compile(r"[a-z0-9.-]{1,253}")


@app.route("/products-sorted")
def products_sorted():
    column = SORT_COLUMNS.get(request.args.get("sort"), "name")
    # ok: gapscan.python.taint-sqli, gapscan.python.sqli-string-built
    rows = cursor.execute("SELECT id, name FROM products ORDER BY " + column).fetchall()
    order = request.args.get("sort")
    # ruleid: gapscan.python.taint-sqli, gapscan.python.sqli-string-built
    more = cursor.execute("SELECT id, name FROM products ORDER BY " + order).fetchall()
    # ok: gapscan.python.taint-xss
    return {"products": rows + more}


@app.route("/ping-checked")
def ping_checked():
    host = request.args.get("host", "")
    if not HOSTNAME.fullmatch(host):
        abort(400)
    # ok: gapscan.python.taint-argument-injection
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, check=False)
    # ok: gapscan.python.taint-xss
    return out.stdout


@app.route("/echo")
def echo_list():
    # ok: gapscan.python.taint-xss
    return [request.args.get("q")]


def etag_for(body):
    # ok: gapscan.python.weak-hash
    return hashlib.md5(body).hexdigest()


def legacy_digest(body):
    # ok: gapscan.python.weak-hash
    return hashlib.sha1(body, usedforsecurity=False).hexdigest()


def password_digest(password):
    # ruleid: gapscan.python.weak-hash
    return hashlib.md5(password.encode()).hexdigest()


# =================== round 6: keys, IVs, password hashing, mass assignment ===========================================
def key_cases():
    # ruleid: gapscan.python.weak-key-size
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    # ok: gapscan.python.weak-key-size
    strong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return weak, strong


def iv_cases(key, data):
    # ruleid: gapscan.python.static-iv
    fixed = AES.new(key, AES.MODE_CBC, b"0123456789abcdef")
    # ok: gapscan.python.static-iv
    fresh = AES.new(key, AES.MODE_CBC, os.urandom(16))
    # ok: gapscan.python.static-iv
    mac = hmac.new(key, b"context", "sha256")
    aead = AESGCM(key)
    # ruleid: gapscan.python.static-iv
    sealed = aead.encrypt(b"000000000000", data, None)
    # ok: gapscan.python.static-iv
    sealed2 = aead.encrypt(os.urandom(12), data, None)
    return fixed, fresh, mac, sealed, sealed2


def password_hash_cases(password, salt):
    # ruleid: gapscan.python.weak-password-hash
    stored = hashlib.sha256(password.encode()).hexdigest()
    # ruleid: gapscan.python.weak-password-hash
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)
    # ok: gapscan.python.weak-password-hash
    good = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    # ok: gapscan.python.weak-password-hash
    digest = hashlib.sha256(salt).hexdigest()
    return stored, derived, good, digest


@app.route("/profile", methods=["POST"])
def update_profile():
    # ruleid: gapscan.python.mass-assignment
    profile = Profile(**request.get_json())
    data = request.form
    # ruleid: gapscan.python.mass-assignment
    Profile.objects.filter(id=1).update(**data)
    body = request.get_json()
    # ok: gapscan.python.mass-assignment
    other = Profile(name=body.get("name"), bio=body.get("bio"))
    return "ok" if profile and other else "no"


def yaml_cases(text):
    # ruleid: gapscan.python.unsafe-deserialization
    docs = list(yaml.load_all(text, Loader=yaml.Loader))
    # ok: gapscan.python.unsafe-deserialization
    safe_docs = list(yaml.safe_load_all(text))
    return docs, safe_docs


def template_env(loader):
    # ruleid: gapscan.python.jinja2-autoescape-default-off
    env = jinja2.Environment(loader=loader)
    # ok: gapscan.python.jinja2-autoescape-default-off
    html_env = jinja2.Environment(loader=loader, autoescape=jinja2.select_autoescape(["html"]))
    return env, html_env
