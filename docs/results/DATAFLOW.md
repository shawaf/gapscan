# Data-flow engine results (`taint` scanner)

Measured 2026-10-07. Scanners only, no AI review. Two kinds of evidence, kept apart on purpose:

1. **OWASP Benchmark (Java 1.2, Python 0.1), held-out half.** Cases are split by a hash of their id;
   the engine was developed looking at the dev half only and the test half was scored once.
2. **Independent check:** SecuriBench Micro (a different test family) and six real applications
   with published labels (cogniumhq/sast-benchmarks). Numbers below are first taken *before* any
   change was made for these sets, then again after three framework models were added for them.

Reproduce (needs the clones under `data/eval-targets/`, see each tool's docstring):

    uv run python tools/rule_bench.py java --taint --final
    uv run python tools/rule_bench.py python --taint --final
    uv run python tools/realapp_bench.py

Columns: **own rules** = GapScan's Semgrep rule library; **taint** = the data-flow engine alone;
**reported** = everything GapScan shows (rules and data flow together); **confirmed** = what GapScan
ranks first: injection classes only when the data-flow engine reaches the line, every other class
(crypto, hashing, random numbers, cookies, XXE) from the rules. A rule finding the engine does not
confirm is still reported, with `dataflow: not_confirmed` and a lower priority.

## 1. OWASP Benchmark, held-out half

Score = share of real vulnerabilities caught minus share of safe cases flagged.

| Benchmark (test half) | Community Semgrep | Own rules | Taint alone | Rules + taint, reported | **Confirmed** |
|---|---|---|---|---|---|
| Java (1,354 cases) | 89% / 41% (+48) | 89% / 42% (+47) | 62% / 0% (+62) | 97% / 42% (+55) | **97% / 0% (+97)** |
| Python (600 cases) | 35% / 15% (+20) | 78% / 27% (+51) | 57% / 4% (+54) | 100% / 28% (+71) | **100% / 5% (+95)** |

Per category on Java, taint alone catches 100% with 0% false alarms in all seven injection categories
(SQL, command, LDAP, path, trust boundary, XPath, XSS). For reference, a competitor's page reports
CodeQL at about +60 and a commercial engine at +73.5 on this benchmark (whole benchmark, their setup).

**What this does not say.** The Benchmark's two halves are generated from the same small set of
templates, and its safe cases are built from a handful of decoys (constant conditions, constant
switch selectors, collections read at a different key or index, values overwritten before use,
escaping). The engine learned to see through those decoys on the dev half: constant folding,
switch/`match` selection, index- and key-aware lists and maps, block-scoped strong updates. These
are general techniques, but the held-out half shares the decoys, so it shows the engine generalizes
*within* the Benchmark's family. It does not show +97 on real code. Section 2 is the better guide.

## 2. Independent check: SecuriBench Micro and real applications

Cells: caught / real, false alarms / safe.

| Set (labels) | Own rules | Taint alone | Reported | Confirmed |
|---|---|---|---|---|
| SecuriBench Micro, Java (124 test classes) | 77/109, 8/15 | 79/109, 7/15 | 87/109, 12/15 | 79/109, 7/15 |
| WebGoat, Java (29) | 3/21, 1/8 | 13/21, 1/8 | 14/21, 1/8 | 13/21, 1/8 |
| DVJA, Java (6) | 2/2, 0/4 | 0/2, 0/4 | 2/2, 0/4 | 0/2, 0/4 |
| PyGoat, Python (22) | 7/12, 0/10 | 8/12, 0/10 | 8/12, 0/10 | 8/12, 0/10 |
| DVPWA, Python (6) | 0/1, 0/5 | 0/1, 0/5 | 0/1, 0/5 | 0/1, 0/5 |
| Juice Shop, TypeScript (14) | 6/10, 0/4 | 6/10, 0/4 | 7/10, 0/4 | 6/10, 0/4 |
| NodeGoat, JavaScript (14) | 3/5, 0/9 | 2/5, 1/9 | 3/5, 1/9 | 2/5, 1/9 |
| **All, first look** | **61% / 16% (+45)** | **68% / 16% (+51)** | **76% / 25% (+50)** | **68% / 16% (+51)** |

These first-look numbers are the honest estimate of how the engine generalizes: on real code it
catches more than the rules alone at the same false-alarm rate, and reporting both catches the most.

**After looking at these sets**, three general framework models were added: Struts 2 action fields
(DVJA), aiohttp request sources (DVPWA) and template-aware Django/Flask XSS (PyGoat). With them taint
alone reaches 112/160 caught (70%) at 9/55 false alarms (+54), and DVJA, DVPWA and PyGoat rise to
2/2, 1/1 and 9/12. Those three sets are no longer independent evidence.

## Known gaps (from the misses above)

- **Callbacks and second-order data**: values that arrive as callback parameters (NodeGoat's
  `needle.get(url, (err, res, body) => res.write(body))`) or come back from a database are not
  sources.
- **Framework output helpers** the engine does not know (WebGoat's lesson feedback builders).
- **Reflection, deep aliasing and data structures** (SecuriBench `reflection`, `datastructures`,
  half of `aliasing`): no points-to analysis.
- **Sanitizers by shape** (SecuriBench `sanitizers`, `strong_updates`): a custom sanitizer the engine
  cannot recognize by name or library model is treated as pass-through.
- Labels in the real-app sets are per file or function, written by the benchmark's authors; a few
  are debatable.
