"""Turn the stored raw sources into citable chunks for the local knowledge base.

Every chunk keeps its source, version, license and URL so citations in reports are accurate.
Reads only the raw files saved by `gapscan data fetch*` (no network). Policies are the owner's
own Markdown and carry no third-party license.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET  # noqa: S405 - pinned MITRE catalog, not scanned content
import zipfile
from collections.abc import Iterator
from pathlib import Path

from pydantic import BaseModel

from ..store.raw import RawStore

MAX_CHARS = 1400
OVERLAP = 150


class Chunk(BaseModel):
    id: str
    source: str  # cheatsheet | cwe | top10-2025 | api-top10-2023 | genai-llm-top10-2026 | masvs | asvs | policy
    doc_id: str  # e.g. CWE-89, A05:2025, SQL_Injection_Prevention_Cheat_Sheet
    title: str
    heading: str = ""
    text: str
    url: str = ""
    version: str = ""
    license: str = ""

    @property
    def citation(self) -> str:
        parts = [
            self.title + (f" > {self.heading}" if self.heading else ""),
            self.version,
            self.license,
        ]
        return " | ".join(p for p in parts if p)


def _make_id(source: str, doc_id: str, index: int, text: str) -> str:
    return hashlib.sha256(f"{source}|{doc_id}|{index}|{text}".encode()).hexdigest()[:16]


# --- markdown ------------------------------------------------------------------------

_HEADING = re.compile(r"^(#{1,4})\s+(.*?)\s*#*\s*$")
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_TAG = re.compile(r"</?[A-Za-z][^>]*>")


def clean_markdown(text: str) -> str:
    text = _HTML_COMMENT.sub("", text)
    text = _IMAGE.sub("", text)
    text = _TAG.sub(" ", text)  # tables/attributes from HTML-in-markdown
    return re.sub(r"[ \t]+\n", "\n", re.sub(r"\n{3,}", "\n\n", text)).strip()


def _split_long(text: str, size: int = MAX_CHARS, overlap: int = OVERLAP) -> list[str]:
    """Split on paragraph/line boundaries into pieces of at most `size` characters."""
    if len(text) <= size:
        return [text]
    pieces: list[str] = []
    current = ""
    for para in re.split(r"\n\s*\n", text):
        for seg in (
            [para] if len(para) <= size else re.findall(rf".{{1,{size}}}(?:\s|$)", para, re.DOTALL)
        ):
            if current and len(current) + len(seg) + 2 > size:
                pieces.append(current.strip())
                current = current[-overlap:] if overlap else ""
            current = f"{current}\n\n{seg}" if current else seg
    if current.strip():
        pieces.append(current.strip())
    return pieces


def markdown_sections(text: str) -> tuple[str, list[tuple[str, str]]]:
    """(document title, [(heading path, section body)]) split at headings."""
    title = ""
    path: list[tuple[int, str]] = []
    sections: list[tuple[str, list[str]]] = [("", [])]
    in_code = False
    for line in clean_markdown(text).splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
        m = None if in_code else _HEADING.match(line)
        if m:
            level, heading = len(m.group(1)), m.group(2).strip()
            if level == 1 and not title:
                title = heading
                continue
            path = [(lv, h) for lv, h in path if lv < level] + [(level, heading)]
            sections.append((" > ".join(h for _, h in path), []))
        else:
            sections[-1][1].append(line)
    return title, [(h, "\n".join(b).strip()) for h, b in sections if "\n".join(b).strip()]


def markdown_chunks(text: str, *, source: str, doc_id: str, fallback_title: str, url: str,
                    version: str, license: str) -> list[Chunk]:  # fmt: skip
    title, sections = markdown_sections(text)
    if not title:  # no H1: promote the first heading (the GenAI pages start at H2)
        first = next((ln for ln in clean_markdown(text).splitlines() if _HEADING.match(ln)), "")
        title = _HEADING.match(first).group(2).strip() if first else ""  # type: ignore[union-attr]
        if title:
            sections = [(h.removeprefix(title).removeprefix(" > "), b) for h, b in sections]
    title = title or fallback_title
    chunks: list[Chunk] = []
    for heading, body in sections:
        for piece in _split_long(body):
            if len(piece) < 40:  # skip stray one-liners
                continue
            chunks.append(Chunk(id=_make_id(source, doc_id, len(chunks), piece), source=source,
                                doc_id=doc_id, title=title, heading=heading, text=piece, url=url,
                                version=version, license=license))  # fmt: skip
    return chunks


# --- per-source ingestion --------------------------------------------------------------


def _entries(store: RawStore, prefix: str) -> Iterator[tuple[str, str, str, str]]:
    """(path, version, license, upstream url) for manifest entries under `prefix`."""
    for e in store.manifest().entries:
        if e.path.startswith(prefix):
            yield e.path, e.version, e.license, e.url


def _stem(path: str) -> str:
    return Path(path).stem


def ingest_cheatsheets(store: RawStore) -> list[Chunk]:
    out: list[Chunk] = []
    for path, version, lic, _ in _entries(store, "cheatsheets/"):
        stem = _stem(path)
        url = f"https://cheatsheetseries.owasp.org/cheatsheets/{stem}.html"
        out += markdown_chunks(store.read_raw(path).decode("utf-8", "replace"), source="cheatsheet",
                               doc_id=stem, fallback_title=stem.replace("_", " "), url=url,
                               version=version, license=lic)  # fmt: skip
    return out


def ingest_top10_2025(store: RawStore) -> list[Chunk]:
    out: list[Chunk] = []
    for path, version, lic, url in _entries(store, "top10-2025/"):
        m = re.match(r"^(A\d{2})_2025-", _stem(path) + "-")
        if not m:
            continue  # intro/about pages are not category definitions
        doc_id = f"{m.group(1)}:2025"
        out += markdown_chunks(store.read_raw(path).decode("utf-8", "replace"), source="top10-2025",
                               doc_id=doc_id, fallback_title=doc_id, url=url, version=version,
                               license=lic)  # fmt: skip
    return out


def ingest_api_top10(store: RawStore) -> list[Chunk]:
    out: list[Chunk] = []
    for path, version, lic, url in _entries(store, "api-security-2023/"):
        stem = _stem(path)
        m = re.match(r"^0xa([1-9a])-", stem)
        if not m:
            continue  # front matter, release notes, acknowledgements
        digit = m.group(1)  # 0xa1..0xa9 are API1..API9; 0xaa is API10
        doc_id = f"API{10 if digit == 'a' else int(digit)}:2023"
        out += markdown_chunks(store.read_raw(path).decode("utf-8", "replace"), source="api-top10-2023",
                               doc_id=doc_id, fallback_title=doc_id, url=url, version=version,
                               license=lic)  # fmt: skip
    return out


def ingest_genai_top10(store: RawStore) -> list[Chunk]:
    out: list[Chunk] = []
    for path, version, lic, url in _entries(store, "genai-llm-top10-2026/"):
        m = re.match(r"^(LLM(?:0[1-9]|10))_", _stem(path))
        if not m:
            continue  # preface, appendices, references
        out += markdown_chunks(store.read_raw(path).decode("utf-8", "replace"),
                               source="genai-llm-top10-2026", doc_id=f"{m.group(1)}:2026",
                               fallback_title=_stem(path), url=url, version=version, license=lic)  # fmt: skip
    return out


def ingest_masvs(store: RawStore) -> list[Chunk]:
    out: list[Chunk] = []
    for path, version, lic, url in _entries(store, "masvs-"):
        doc = json.loads(store.read_raw(path))
        for std in doc.get("definitions", {}).get("standards", []):
            for req in std.get("requirements", []):
                ident, title, text = req["identifier"], req.get("title", ""), req.get("text", "")
                body = f"{ident}: {title}\n{text}".strip()
                out.append(Chunk(id=_make_id("masvs", ident, 0, body), source="masvs", doc_id=ident,
                                 title=f"MASVS {ident}", heading=title, text=body, url=url,
                                 version=version, license=lic))  # fmt: skip
    return out


def ingest_asvs(store: RawStore) -> list[Chunk]:
    out: list[Chunk] = []
    for path, version, lic, url in _entries(store, "asvs-5.0.0/"):
        if not path.endswith("_en.csv"):
            continue
        for row in csv.DictReader(io.StringIO(store.read_raw(path).decode("utf-8"))):
            ident = f"v5.0.0-{row['req_id'].removeprefix('V')}"
            body = (f"{row['req_id']} (level {row['L']}) {row['chapter_name']} > "
                    f"{row['section_name']}: {row['req_description']}")  # fmt: skip
            version = "5.0.0"
            out.append(Chunk(id=_make_id("asvs", ident, 0, body), source="asvs", doc_id=ident,
                             title=f"ASVS {row['req_id']}", heading=f"{row['chapter_name']} > {row['section_name']}",
                             text=body, url=url, version=version, license=lic))  # fmt: skip
    return out


def _txt(el: ET.Element | None) -> str:
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def parse_cwe_xml(xml_bytes: bytes, *, version: str, license: str) -> list[Chunk]:
    """One main chunk per non-deprecated weakness, plus a mitigations chunk when present."""
    ns = {"c": "http://cwe.mitre.org/cwe-7"}
    root = ET.fromstring(xml_bytes)  # noqa: S314 - MITRE's pinned catalog, not scanned content
    out: list[Chunk] = []
    for w in root.iterfind(".//c:Weaknesses/c:Weakness", ns):
        if w.get("Status") == "Deprecated":
            continue
        cwe = f"CWE-{w.get('ID')}"
        name = w.get("Name", "")
        url = f"https://cwe.mitre.org/data/definitions/{w.get('ID')}.html"
        parts = [
            f"{cwe}: {name}",
            _txt(w.find("c:Description", ns)),
            _txt(w.find("c:Extended_Description", ns)),
        ]
        alts = [_txt(t) for t in w.iterfind("c:Alternate_Terms/c:Alternate_Term/c:Term", ns)]
        if alts:
            parts.append("Also known as: " + ", ".join(alts))
        cons = []
        for c in w.iterfind("c:Common_Consequences/c:Consequence", ns):
            scope = ", ".join(_txt(s) for s in c.iterfind("c:Scope", ns))
            impact = ", ".join(_txt(i) for i in c.iterfind("c:Impact", ns))
            cons.append(f"{scope}: {impact}")
        if cons:
            parts.append("Common consequences: " + "; ".join(cons[:6]))
        main = "\n".join(p for p in parts if p)[:3500]
        out.append(Chunk(id=_make_id("cwe", cwe, 0, main), source="cwe", doc_id=cwe, title=f"{cwe} {name}",
                         heading="Description", text=main, url=url, version=version, license=license))  # fmt: skip
        mits = []
        for m in w.iterfind("c:Potential_Mitigations/c:Mitigation", ns):
            phase = ", ".join(_txt(p) for p in m.iterfind("c:Phase", ns))
            strategy = _txt(m.find("c:Strategy", ns))
            mits.append(
                f"[{phase}{' / ' + strategy if strategy else ''}] {_txt(m.find('c:Description', ns))}"
            )
        if mits:
            text = f"{cwe} potential mitigations ({name}):\n" + "\n".join(mits)
            for i, piece in enumerate(_split_long(text, 2500, 0)):
                out.append(Chunk(id=_make_id("cwe", cwe, i + 1, piece), source="cwe", doc_id=cwe,
                                 title=f"{cwe} {name}", heading="Potential mitigations", text=piece,
                                 url=url, version=version, license=license))  # fmt: skip
    return out


def cwe_catalog_version(store: RawStore) -> str:
    """ "CWE 4.20 (2026-04-30)" read from the stored catalog's XML header; "" when unavailable."""
    for path, _v, _l, _u in _entries(store, "cwe/"):
        if path.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(store.read_raw(path))) as z:
                name = next((n for n in z.namelist() if n.endswith(".xml")), None)
                head = z.open(name).read(600).decode("utf-8", "replace") if name else ""
            m = re.search(r'Version="([\d.]+)" Date="([\d-]+)"', head)
            return f"CWE {m.group(1)} ({m.group(2)})" if m else ""
    return ""


def ingest_cwe(store: RawStore) -> list[Chunk]:
    out: list[Chunk] = []
    for path, _version, lic, _url in _entries(store, "cwe/"):
        if not path.endswith(".zip"):
            continue
        with zipfile.ZipFile(io.BytesIO(store.read_raw(path))) as z:
            name = next(n for n in z.namelist() if n.endswith(".xml"))
            xml = z.read(name)
        head = xml[:600].decode("utf-8", "replace")
        ver = re.search(r'Version="([\d.]+)" Date="([\d-]+)"', head)
        version = f"CWE {ver.group(1)} ({ver.group(2)})" if ver else "CWE latest"
        out += parse_cwe_xml(xml, version=version, license=lic)
    return out


def ingest_policies(directory: Path) -> list[Chunk]:
    """The owner's own Markdown policies (optional folder)."""
    out: list[Chunk] = []
    if not directory.is_dir():
        return out
    for path in sorted(directory.rglob("*.md")):
        rel = str(path.relative_to(directory))
        out += markdown_chunks(path.read_text(encoding="utf-8", errors="replace"), source="policy",
                               doc_id=rel, fallback_title=path.stem.replace("_", " "), url=f"policies/{rel}",
                               version="local", license="owner's own document")  # fmt: skip
    return out


def ingest_all(owasp: RawStore, mitre: RawStore, policies_dir: Path | None = None) -> list[Chunk]:
    chunks: list[Chunk] = []
    for fn, store in [(ingest_cheatsheets, owasp), (ingest_top10_2025, owasp), (ingest_api_top10, owasp),
                      (ingest_genai_top10, owasp), (ingest_masvs, owasp), (ingest_asvs, owasp),
                      (ingest_cwe, mitre)]:  # fmt: skip
        chunks += fn(store)
    if policies_dir:
        chunks += ingest_policies(policies_dir)
    return chunks
