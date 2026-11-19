# GapScan for VS Code

Shows the findings of your local GapScan as problems in the editor. Everything runs on your machine:
the extension calls the `gapscan` command you installed, and nothing is sent anywhere.

* **GapScan: Scan workspace** scans the first workspace folder.
* **GapScan: Clear findings** removes them.
* Settings: `gapscan.executable` (path to the command), `gapscan.scanOnSave` (off by default; a full
  scan can be slow on large projects).

Each problem shows the finding's title, CWE, rule id and, for injection findings, the data flow from
source to sink.
