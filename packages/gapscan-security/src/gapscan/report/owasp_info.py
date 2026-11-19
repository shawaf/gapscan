"""Static facts about the OWASP Top 10:2025 categories for the dashboard (names come from the
mapping table; cheat sheets are curated and checked against the stored snapshot by a test)."""

from __future__ import annotations

from ..owasp.classify import load_tables

CHEATSHEET_BASE = "https://cheatsheetseries.owasp.org/cheatsheets/"

CATEGORY_CHEATSHEETS: dict[str, tuple[str, ...]] = {
    "A01:2025": (
        "Authorization_Cheat_Sheet",
        "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet",
    ),
    "A02:2025": ("Docker_Security_Cheat_Sheet", "Infrastructure_as_Code_Security_Cheat_Sheet"),
    "A03:2025": (
        "Software_Supply_Chain_Security_Cheat_Sheet",
        "Vulnerable_Dependency_Management_Cheat_Sheet",
    ),
    "A04:2025": ("Cryptographic_Storage_Cheat_Sheet", "Password_Storage_Cheat_Sheet"),
    "A05:2025": ("Injection_Prevention_Cheat_Sheet", "SQL_Injection_Prevention_Cheat_Sheet"),
    "A06:2025": ("Secure_Product_Design_Cheat_Sheet", "Threat_Modeling_Cheat_Sheet"),
    "A07:2025": ("Authentication_Cheat_Sheet", "Session_Management_Cheat_Sheet"),
    "A08:2025": ("Deserialization_Cheat_Sheet", "CI_CD_Security_Cheat_Sheet"),
    "A09:2025": ("Logging_Cheat_Sheet",),
    "A10:2025": ("Error_Handling_Cheat_Sheet",),
}


def category_names() -> dict[str, str]:
    return dict(sorted(load_tables().top10_names.items()))


def cheatsheet_links(category: str) -> list[dict[str, str]]:
    return [
        {
            "title": s.removesuffix("_Cheat_Sheet").replace("_", " ") + " Cheat Sheet",
            "url": f"{CHEATSHEET_BASE}{s}.html",
        }
        for s in CATEGORY_CHEATSHEETS.get(category, ())
    ]
