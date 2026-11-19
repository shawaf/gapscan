# Homebrew formula for GapScan (TEMPLATE).
#
# This lives in a tap repo named `homebrew-gapscan` (so `brew tap shawaf/gapscan` finds it).
# It is a template: fill in `url`, `sha256` and the Python `resource` blocks once the CLI is
# published (PyPI sdists or a GitHub release). The real value of the formula is that it declares
# the external scanners as dependencies, so `brew install gapscan` pulls the whole toolchain.
#
# To generate the `resource` stanzas after the package is on PyPI:
#   brew update-python-resources gapscan
#
# The AI model (Ollama + a code model) is intentionally NOT a dependency: it is large and optional.
# `gapscan doctor` reports whether it is present; without it, scanners + standard mapping still run.

class Gapscan < Formula
  include Language::Python::Virtualenv

  desc "Find, prove and prioritize security gaps against OWASP (offline engine)"
  homepage "https://github.com/shawaf/gapscan"
  license "Apache-2.0"

  # TODO: point at a published release or the PyPI sdist of the `gapscan` meta-package.
  url "https://github.com/shawaf/gapscan/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  depends_on "python@3.12"

  # Scanners GapScan runs as separate processes. Each is its own Homebrew formula; a missing one is
  # skipped at runtime, so these could be made optional, but installing them is the point.
  depends_on "semgrep"
  depends_on "trivy"
  depends_on "gitleaks"
  depends_on "osv-scanner"
  # bandit and checkov are Python tools; they are installed into the virtualenv below (as resources)
  # rather than as separate brew formulae, so they share this formula's Python.

  # TODO: `brew update-python-resources gapscan` fills the resource "..." do ... end blocks here,
  # including the gapscan-core / -engine / -security / -server / -local workspace packages and their
  # dependencies (typer, pydantic, httpx, jinja2, rich, numpy, tree-sitter*, cryptography, bandit,
  # checkov, ...). They are omitted from this template.

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "gapscan", shell_output("#{bin}/gapscan version")
    # `doctor` exits non-zero when nothing is configured yet, so just check it runs and reports.
    assert_match(/scanner|model|database/i, shell_output("#{bin}/gapscan doctor 2>&1", 1))
  end
end
