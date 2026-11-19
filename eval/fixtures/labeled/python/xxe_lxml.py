from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    doc = etree.fromstring(request.get_data(), parser)
    return {"root": doc.tag}
