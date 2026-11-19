# GapScan detection results

Generated 2026-10-05 with Semgrep 1.176.0. **215 own rules** across 7 languages python 33, javascript 26, java 40, kotlin 42, swift 30, dart 22, go 22. Reproduce with `uv run python tools/results_report.py`.

GapScan ships its own Apache-2.0 rule library, because the free community Semgrep rules cannot be redistributed in a product. These are the measured results of those rules next to the community rules, scanners only.

**The inter-procedural data-flow engine** (the `taint` scanner) has its own page with the OWASP Benchmark held-out halves and an independent check on SecuriBench Micro and six real applications: [DATAFLOW.md](DATAFLOW.md).

## Headline

- On the 128-site labeled fixture set GapScan's rules alone reach **97.1% recall at 65.6% precision**, up from 47.1% / 59.3% before the new rules (community rules plus GapScan: 91.2% / 62.1%).
- Java: level with the free Semgrep rules on the OWASP Benchmark (held-out half: community +48, GapScan +47).
- Python, Go and JavaScript: clearly ahead of the community rules on their benchmarks.
- Kotlin, Swift and Android Java apps: the community rules catch almost nothing; GapScan catches roughly half to two thirds of the tested samples.

## Results by language (held-out half)

| Language | Benchmark | Evidence | Community Semgrep | GapScan |
|---|---|---|---|---|
| Java | OWASP Benchmark v1.2 (2,740 cases) | standard benchmark | 89% caught, 41% false alarms (score +48) | **89% caught, 42% false alarms (score +47)** |
| Python | OWASP Benchmark for Python v0.1 (1,230 cases) | standard benchmark | 35% caught, 15% false alarms (score +20) | **78% caught, 27% false alarms (score +51)** |
| JavaScript / TypeScript | Node.js synthetic set, Juice Shop, NodeGoat, Juice Shop code fixes (82 cases) | small mixed set | 48% caught, 6% false alarms (score +42) | **61% caught, 0% false alarms (score +61)** |
| Go | Go synthetic set and Vulnerability-goapp (42 labeled cases, with safe files) | small mixed set | 29% caught, 12% false alarms (score +16) | **86% caught, 0% false alarms (score +86)** |
| Kotlin / Android | OWASP MASTG demo apps (44 cases) | demo samples | 0% caught | **65% caught** |
| Swift / iOS | OWASP MASTG demo apps (34 cases) | demo samples | 6% caught | **69% caught** |
| Android apps (Java) | DIVA and InsecureBankv2: 19 labeled files | real apps | 7% caught | **50% caught** |
| iOS app (DVIA-v2) * | 10 labeled files | real app | 0% caught | **50% caught** |
| iOS app (iGoat-Swift) * | 17 labeled files | real app | 0% caught | **20% caught** |
| Kotlin apps (InsecureShop, KotlinGoat) * | 17 labeled files | real apps | 0% caught | **71% caught** |
| Dart / Flutter * | DVMA: 107 modules whose folder holds logic | real app (mostly behavioral simulations) | 0% caught | **7% caught** |

\* Tuned on all files of the set; indicative only.

## What these numbers do not say

- Scores are measured with scanners only (no AI review). The AI review step removes false alarms but cannot add findings the scanners missed.
- 'Held out' means half of each benchmark's cases, chosen by a hash of their names, that were not looked at while writing rules. Rows marked 'tuned on all files' were not kept strictly separate and are indicative only.
- The community Semgrep rules are the free Semgrep rule set. GapScan cannot ship them (their license forbids it), which is why GapScan has its own rule library.
- On Java, GapScan is level with the free Semgrep rules and below CodeQL (about +60 in a competitor's published comparison), which follows data across functions and files; GapScan's rules follow it within one function.
- The mobile and Go sets are small, mostly contain vulnerable samples and say little about false alarms. Labels for the real apps were written by hand from each project's own challenge or vulnerability list.
- Dart numbers are a floor: most DVMA modules simulate behavior that no static rule can see.
- Score = share of vulnerable cases caught minus share of safe cases wrongly flagged (the OWASP Benchmark 'Youden' score). Where a set has no safe cases, only the catch rate is reported.

Market reference (OWASP Benchmark Java, score): Semgrep OSS 47.9, CodeQL 59.9, a commercial engine 73.5. Source: cogniumhq/sast-benchmarks (a competitor's page, read with care): OWASP Benchmark Java, TPR minus FPR.
