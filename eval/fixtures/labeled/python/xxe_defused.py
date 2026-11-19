from defusedxml.ElementTree import fromstring
from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
    doc = fromstring(request.get_data())
    return {"root": doc.tag}
