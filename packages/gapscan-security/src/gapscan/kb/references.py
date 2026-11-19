"""Which OWASP Cheat Sheets to point at for a weakness. Curated, not retrieved: semantic search
over CWE names cites unrelated sheets for obscure CWEs (a root-user Dockerfile once matched a
logging sheet), and a wrong citation is worse than none. Targets are Cheat Sheet file names;
a test fails if one stops existing in the stored snapshot, and CWEs with no entry get no
reference rather than a guess."""

from __future__ import annotations

SQLI = ("SQL_Injection_Prevention_Cheat_Sheet", "Query_Parameterization_Cheat_Sheet")
XSS = ("Cross_Site_Scripting_Prevention_Cheat_Sheet",)
CMD = ("OS_Command_Injection_Defense_Cheat_Sheet",)
INPUT = ("Input_Validation_Cheat_Sheet",)
SECRETS = ("Secrets_Management_Cheat_Sheet",)
CRYPTO = ("Cryptographic_Storage_Cheat_Sheet",)
PASSWORDS = ("Password_Storage_Cheat_Sheet",)
AUTHN = ("Authentication_Cheat_Sheet",)
SESSION = ("Session_Management_Cheat_Sheet",)
AUTHZ = ("Authorization_Cheat_Sheet",)
TLS = ("Transport_Layer_Security_Cheat_Sheet",)
LOGGING = ("Logging_Cheat_Sheet",)

CWE_TO_CHEATSHEETS: dict[str, tuple[str, ...]] = {
    # injection
    "CWE-89": SQLI, "CWE-564": SQLI, "CWE-943": ("NoSQL_Security_Cheat_Sheet",),
    "CWE-79": XSS, "CWE-80": XSS, "CWE-83": XSS, "CWE-87": XSS,
    "CWE-78": CMD, "CWE-77": CMD, "CWE-88": CMD,
    "CWE-94": ("Injection_Prevention_Cheat_Sheet",), "CWE-95": ("Injection_Prevention_Cheat_Sheet",),
    "CWE-90": ("LDAP_Injection_Prevention_Cheat_Sheet",),
    "CWE-643": ("XPath_Injection_Prevention_Cheat_Sheet",),
    "CWE-611": ("XML_External_Entity_Prevention_Cheat_Sheet",),
    "CWE-776": ("XML_External_Entity_Prevention_Cheat_Sheet",),
    "CWE-502": ("Deserialization_Cheat_Sheet",),
    "CWE-1321": ("Prototype_Pollution_Prevention_Cheat_Sheet",),
    "CWE-915": ("Mass_Assignment_Cheat_Sheet",),
    "CWE-20": INPUT, "CWE-22": INPUT, "CWE-23": INPUT, "CWE-36": INPUT, "CWE-73": INPUT,
    "CWE-918": ("Server_Side_Request_Forgery_Prevention_Cheat_Sheet",),
    "CWE-601": ("Unvalidated_Redirects_and_Forwards_Cheat_Sheet",),
    "CWE-434": ("File_Upload_Cheat_Sheet",),
    "CWE-352": ("Cross-Site_Request_Forgery_Prevention_Cheat_Sheet",),
    # secrets and cryptography
    "CWE-798": SECRETS, "CWE-259": SECRETS, "CWE-321": SECRETS, "CWE-256": SECRETS,
    "CWE-327": CRYPTO, "CWE-326": CRYPTO, "CWE-338": CRYPTO, "CWE-330": CRYPTO, "CWE-331": CRYPTO,
    "CWE-328": PASSWORDS, "CWE-916": PASSWORDS, "CWE-759": PASSWORDS, "CWE-760": PASSWORDS,
    "CWE-295": TLS, "CWE-319": TLS,
    # authentication, sessions, access control
    "CWE-287": AUTHN, "CWE-306": AUTHN, "CWE-307": AUTHN, "CWE-521": AUTHN, "CWE-620": AUTHN,
    "CWE-640": ("Forgot_Password_Cheat_Sheet",),
    "CWE-384": SESSION, "CWE-613": SESSION, "CWE-614": SESSION, "CWE-1004": SESSION,
    "CWE-284": AUTHZ, "CWE-285": AUTHZ, "CWE-862": AUTHZ, "CWE-863": AUTHZ,
    "CWE-639": ("Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet",),
    # logging, errors, availability
    "CWE-117": LOGGING, "CWE-532": LOGGING, "CWE-778": LOGGING,
    "CWE-209": ("Error_Handling_Cheat_Sheet",), "CWE-755": ("Error_Handling_Cheat_Sheet",),
    "CWE-400": ("Denial_of_Service_Cheat_Sheet",), "CWE-1333": ("Denial_of_Service_Cheat_Sheet",),
    # containers / IaC
    "CWE-250": ("Docker_Security_Cheat_Sheet",), "CWE-269": ("Docker_Security_Cheat_Sheet",),
}  # fmt: skip

# Dependency findings are about the supply chain, whatever CWE the advisory carries.
DEPENDENCY_SHEETS = ("Vulnerable_Dependency_Management_Cheat_Sheet",)


def cheatsheets_for(cwes: list[str], *, dependency: bool = False) -> list[str]:
    """Cheat Sheet document ids for these CWEs, most relevant first, without duplicates."""
    out: list[str] = list(DEPENDENCY_SHEETS) if dependency else []
    for cwe in cwes:
        for sheet in CWE_TO_CHEATSHEETS.get(cwe, ()):
            if sheet not in out:
                out.append(sheet)
    return out
