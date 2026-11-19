"""Triage one finding with the local model: build the prompt from the finding plus its code
context, get a schema-validated answer, and turn it into a Verdict.

Scanned content is untrusted data (hard rule #3). It is wrapped in delimiters, any attempt to
close the delimiter inside the content is neutralized, and model output can trigger nothing
here except producing a Verdict.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..context.injection import warning_for
from ..core.interfaces import LLMError, LLMProvider
from ..llm.cache import ResponseCache
from ..llm.prompts import latest_version, render_prompt
from ..llm.structured import StructuredOutputError, structured_chat
from ..models import (
    Category,
    CodeContext,
    Finding,
    MappingSource,
    Severity,
    TriageAnswer,
    Verdict,
    VerdictLabel,
)
from ..owasp.classify import normalize_cwe
from ..owasp.packs import TOP10, classify_finding
from ..secret_facts import summary as secret_summary
from .tools import KnowledgeBase

log = logging.getLogger(__name__)

PROMPT_NAME = "triage"

# Weaknesses that exist because of a *choice* (algorithm, setting), not because of tainted data.
CHOICE_CWES = {
    "CWE-327", "CWE-326", "CWE-328", "CWE-330", "CWE-331", "CWE-338", "CWE-614",
    "CWE-1004", "CWE-311", "CWE-319", "CWE-916", "CWE-759", "CWE-760", "CWE-295",
}  # fmt: skip


def weakness_kind(finding: Finding) -> str:
    """ "choice" for weak algorithms/insecure settings (judge by purpose, not by data flow)."""
    return "choice" if set(finding.cwe) & CHOICE_CWES else "dataflow"


_DELIM = re.compile(r"<\s*/?\s*untrusted_data", re.IGNORECASE)


def neutralize_delimiters(text: str) -> str:
    """Stop scanned content from closing or reopening our data delimiter."""
    return _DELIM.sub(lambda m: m.group(0).replace("<", "(", 1), text)


def finding_text(finding: Finding, context: CodeContext | None) -> str:
    lines = [
        f"SCANNER: {', '.join(finding.sources)}",
        f"RULE: {finding.rule_id}",
        f"TITLE: {finding.title}",
        f"SEVERITY (scanner): {finding.severity.value}",
        f"CATEGORY: {finding.category.value}",
    ]
    if finding.cwe:
        lines.append(f"CWE: {', '.join(finding.cwe)}")
    where = ("test code" if finding.is_test_code else "build or developer tooling, not shipped"
             if finding.is_tooling_code else "")  # fmt: skip
    if where:
        lines.append(f"LOCATION: {where}")
    if finding.message:
        lines.append(f"SCANNER MESSAGE: {finding.message[:400]}")
    if finding.category == Category.SECRET and finding.raw.get("secret_facts"):
        # computed by GapScan from the value, which itself is withheld
        lines.append(f"SECRET FACTS: {secret_summary(finding.raw['secret_facts'])}")
    if finding.package:
        fixed = finding.fixed_version or "unknown"
        cves = ", ".join(finding.cve) or "n/a"
        lines.append(
            f"PACKAGE: {finding.package} {finding.version or ''} (fixed in: {fixed}; CVEs: {cves})"
        )
    if context is not None:
        lines += ["", context.render()]
    return neutralize_delimiters("\n".join(lines))


def _evidence(finding: Finding) -> list[str]:
    if finding.file and finding.start_line:
        return [f"{finding.file}:{finding.start_line}-{finding.end_line or finding.start_line}"]
    return [f"{finding.package} {finding.version}"] if finding.package else []


_PLACEHOLDER_PATH = re.compile(r"(test|example|sample|mock|dummy|fixture|demo)", re.IGNORECASE)


def _placeholder_location(finding: Finding) -> bool:
    """Secrets in tests, examples and samples are usually placeholders, so a dismissal stands."""
    return finding.is_test_code or bool(_PLACEHOLDER_PATH.search(finding.file or ""))


_STRONG_FORMATS = {
    "private key (PEM)", "Google service account key", "GitHub token", "AWS access key",
    "Slack webhook", "OpenAI key", "Stripe live key",
}  # fmt: skip


def _secret_policy(verdict: Verdict, facts: dict[str, Any]) -> Verdict | None:
    """Decide a secret from facts GapScan computed locally from its value (format, placeholder,
    git-ignored, packaged in the app), which the model cannot see. None: keep the usual rules."""
    note = "Facts computed from the withheld value: " + secret_summary(facts) + "."
    label, conf = None, verdict.confidence
    if facts.get("shipped_in_app"):
        label, conf = VerdictLabel.TRUE_POSITIVE, max(conf, 0.95)
        note += " It is packaged into the app, so anyone with the build can extract it: rotate it."
    elif any(facts.get(k) for k in ("placeholder", "env_reference", "code_reference",
                                    "public_client_key", "firebase_client_key")):  # fmt: skip
        if verdict.verdict in (VerdictLabel.FALSE_POSITIVE, VerdictLabel.NEEDS_REVIEW):
            label, conf = VerdictLabel.FALSE_POSITIVE, max(min(conf, 0.85), 0.7)
            note += (" The value is a placeholder, a reference or a key meant to be public, "
                     "not a leaked credential.")  # fmt: skip
    elif facts.get("format") in _STRONG_FORMATS and facts.get("randomness") != "low":
        label, conf = VerdictLabel.LIKELY_TRUE_POSITIVE, max(conf, 0.8)
        if verdict.verdict == VerdictLabel.TRUE_POSITIVE:
            label = VerdictLabel.TRUE_POSITIVE
        if facts.get("gitignored"):
            note += (" Not committed (git ignores the file), but a real credential on disk: keep "
                     "it out of builds and rotate it if it was ever shared.")  # fmt: skip
        else:
            note += " Committed credentials stay in the git history: rotate it, then remove it."
    if label is None:
        return None
    return verdict.model_copy(
        update={"verdict": label, "confidence": conf, "policy_notes": [*verdict.policy_notes, note]}
    )


def apply_policy(
    finding: Finding, verdict: Verdict, injection_suspected: bool = False, flow_status: str = ""
) -> Verdict:
    """Deterministic guardrails over the model's verdict (computed in Python, not by prompts).

    An installed package with a known vulnerability is not dismissed just because no source file
    imports it: it may be a transitive dependency, and real reachability analysis is Stage 2. The
    model can lower confidence but cannot clear it; a KEV-listed vulnerability is never cleared."""
    dismissed = verdict.verdict == VerdictLabel.FALSE_POSITIVE and not verdict.triage_failed
    confirmed = verdict.verdict in (VerdictLabel.TRUE_POSITIVE, VerdictLabel.LIKELY_TRUE_POSITIVE)
    # A traced path from request input is shown to the model as evidence but does NOT override a
    # dismissal: name-based tracing cannot see allowlists, path checks or parameterization, and
    # blocking on it cost far more false-alarm removal than it saved (see docs/evaluation.md).
    if confirmed and flow_status == "constant" and finding.category == Category.CODE:
        note = (
            "GapScan traced every value used at the flagged line back to a literal, so there "
            "is no attacker-controlled data to exploit. Confirmed by the model, overruled by "
            "the trace."
        )
        return verdict.model_copy(
            update={
                "verdict": VerdictLabel.FALSE_POSITIVE,
                "confidence": min(verdict.confidence, 0.7),
                "policy_notes": [*verdict.policy_notes, note],
            }
        )
    if injection_suspected:
        verdict = verdict.model_copy(update={"injection_suspected": True})
        if dismissed:
            note = (
                "The code contains text aimed at steering the reviewer (a prompt-injection "
                "attempt), so a 'false positive' answer is not accepted: the finding stays "
                "for human review."
            )
            return verdict.model_copy(
                update={
                    "verdict": VerdictLabel.NEEDS_REVIEW,
                    "confidence": min(verdict.confidence, 0.5),
                    "policy_notes": [*verdict.policy_notes, note],
                }
            )
    facts = finding.raw.get("secret_facts") or {}
    if finding.category == Category.SECRET and facts:
        decided = _secret_policy(verdict, facts)
        if decided is not None:
            return decided
    if dismissed and finding.category == Category.SECRET and not _placeholder_location(finding):
        note = (
            "Secret values are withheld from the model on purpose, so it cannot judge whether the "
            "value is real. A secret scanner's hit outside test or example files stays for review."
        )
        return verdict.model_copy(
            update={
                "verdict": VerdictLabel.NEEDS_REVIEW,
                "confidence": min(verdict.confidence, 0.5),
                "policy_notes": [*verdict.policy_notes, note],
            }
        )
    if dismissed and finding.category == Category.DEPENDENCY:
        note = (
            "Model judged the package unused, but it is installed and the vulnerability is "
            "known; reachability is not proven either way, so it stays for human review."
        )
        if finding.kev:
            note = "Listed in the CISA KEV catalog (actively exploited): never dismissed. " + note
        return verdict.model_copy(
            update={
                "verdict": VerdictLabel.NEEDS_REVIEW,
                "confidence": min(verdict.confidence, 0.5),
                "policy_notes": [*verdict.policy_notes, note],
            }
        )
    if dismissed and finding.kev:
        note = "Listed in the CISA KEV catalog (actively exploited): not dismissed."
        return verdict.model_copy(
            update={
                "verdict": VerdictLabel.NEEDS_REVIEW,
                "policy_notes": [*verdict.policy_notes, note],
            }
        )
    return verdict


def guard_memory_use(finding: Finding, verdict: Verdict, kinds: list[str]) -> Verdict:
    """A dismissal made while a team memory said "false alarm" or "accepted" is not final for
    high or critical findings: a wrong or planted memory must not be able to hide a serious issue
    on its own. The reviewer sees the memory ids and decides."""
    leaned = any(k in ("false_positive", "accepted_risk") for k in kinds)
    serious = finding.severity in (Severity.HIGH, Severity.CRITICAL)
    if not (leaned and serious) or verdict.triage_failed:
        return verdict
    if verdict.verdict != VerdictLabel.FALSE_POSITIVE:
        return verdict
    note = (
        "Dismissed while a team memory (" + ", ".join(verdict.memories_used) + ") called similar "
        "findings harmless. For a high or critical finding that is not final: please confirm."
    )
    return verdict.model_copy(
        update={
            "verdict": VerdictLabel.NEEDS_REVIEW,
            "confidence": min(verdict.confidence, 0.5),
            "policy_notes": [*verdict.policy_notes, note],
        }
    )


def with_references(
    verdict: Verdict, kb: KnowledgeBase | None, finding: Finding | None = None
) -> Verdict:
    """Attach Cheat Sheet citations chosen deterministically from the knowledge base (never by
    the model) to confirmed findings; dismissed or failed ones get none."""
    keep = {VerdictLabel.TRUE_POSITIVE, VerdictLabel.LIKELY_TRUE_POSITIVE}
    dependency = finding is not None and finding.category == Category.DEPENDENCY
    if kb is None or verdict.triage_failed or verdict.verdict not in keep:
        return verdict
    if not (verdict.cwe or dependency):
        return verdict
    refs = kb.references_for(verdict.cwe, dependency=dependency)
    return verdict.model_copy(update={"references": refs})


def build_verdict(
    finding: Finding,
    answer: TriageAnswer | None,
    prompt_version: str,
    model: str,
    *,
    cached: bool = False,
    attempts: int = 0,
    injection_suspected: bool = False,
    flow_status: str = "",
) -> Verdict:
    """Turn a validated model answer (or None for a failed triage) into a Verdict.

    The model may only suggest a CWE when the scanner gave none, and Top 10 / ASVS tags always
    come from the mapping table, never from model text."""
    base = Verdict(
        finding_id=finding.id,
        prompt_version=prompt_version,
        model=model,
        cwe=list(finding.cwe),
        evidence_refs=_evidence(finding),
        cached=cached,
        attempts=attempts,
    )
    if answer is None:
        return base.model_copy(update={"injection_suspected": injection_suspected})
    cwes, source = list(finding.cwe), "scanner"
    suggested = normalize_cwe(answer.suggested_cwe) if answer.suggested_cwe else None
    if not cwes and suggested:
        cwes, source = [suggested], "llm"
    tagged = finding.model_copy(update={"cwe": cwes, "owasp_top10": [], "asvs": []})
    classify_finding(tagged)
    return apply_policy(
        finding,
        base.model_copy(
            update={
                "verdict": answer.verdict,
                "confidence": answer.confidence,
                "reasoning": answer.reasoning,
                "exploit_scenario": answer.exploit_scenario,
                "cwe": cwes,
                "cwe_source": source,
                "owasp_category": (
                    tagged.control_ids(TOP10)
                    if tagged.mapping_source == MappingSource.TABLE
                    else []
                ),
                "severity_adjusted": answer.severity_adjusted,
                "fix_suggestion": answer.fix_suggestion,
            }
        ),
        injection_suspected,
        flow_status,
    )


def triage_finding(
    client: LLMProvider,
    finding: Finding,
    context: CodeContext | None = None,
    *,
    cache: ResponseCache | None = None,
    max_tokens: int = 700,
    kb: KnowledgeBase | None = None,
) -> Verdict:
    """Single-shot triage without tools (the fallback when tools are disabled)."""
    version = latest_version(PROMPT_NAME)
    model = client.model
    suspected_lines = context.injection_lines if context else []
    prompt = render_prompt(
        version,
        category=finding.category.value,
        weakness=weakness_kind(finding),
        finding_text=finding_text(finding, context),
        warning=warning_for(suspected_lines) if suspected_lines else "",
    )
    try:
        res = structured_chat(
            client, [{"role": "user", "content": prompt}], TriageAnswer,
            max_tokens=max_tokens, cache=cache, prompt_version=version,
        )  # fmt: skip
    except StructuredOutputError as exc:
        v = build_verdict(
            finding,
            None,
            version,
            model,
            attempts=exc.attempts,
            injection_suspected=bool(suspected_lines),
        )
        return v.model_copy(update={"triage_failed": True, "error": str(exc)})
    except LLMError as exc:
        v = build_verdict(finding, None, version, model, injection_suspected=bool(suspected_lines))
        return v.model_copy(update={"triage_failed": True, "error": str(exc)[:300]})
    v = build_verdict(
        finding,
        res.value,
        version,
        model,
        cached=res.cached,
        attempts=res.attempts,
        injection_suspected=bool(suspected_lines),
        flow_status=context.flow_status if context else "",
    )
    v = v.model_copy(
        update={"tokens": res.prompt_tokens + res.completion_tokens, "seconds": res.duration_s}
    )
    return with_references(v, kb, finding)
