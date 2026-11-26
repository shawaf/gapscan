# GapScan for AI coding assistants (MCP)

`gapscan mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI
coding assistant check the code it writes against GapScan's rules and the OWASP mapping, on your
machine, before the code reaches a pull request.

- **Tools:** `gapscan_scan_snippet(language, code)` checks a snippet; `gapscan_scan_file(path)` checks
  a file in the project. Each finding comes back with its CWE, the OWASP controls it breaks and a
  fix-oriented message.
- **Safe by construction:** read-only, confined to `--root`, fast scanners only, no network. The
  code the assistant sends is treated as untrusted data, like everything GapScan scans.
- **Listed** in the [MCP Registry](https://registry.modelcontextprotocol.io) as
  `io.github.shawaf/gapscan`.

## Setup

Every client below starts the server with `uvx`, which fetches the `gapscan` package from PyPI the
first time ([install uv](https://docs.astral.sh/uv/getting-started/installation/)). With GapScan
already installed (`pipx install gapscan`), use `gapscan` instead of `uvx gapscan`.

### Claude Code

```bash
claude mcp add gapscan -- uvx gapscan mcp --root .
```

### Cursor

Add to `.cursor/mcp.json` in the project (or `~/.cursor/mcp.json` for every project):

```json
{
  "mcpServers": {
    "gapscan": {
      "command": "uvx",
      "args": ["gapscan", "mcp", "--root", "."]
    }
  }
}
```

### VS Code (GitHub Copilot agent mode)

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "gapscan": {
      "type": "stdio",
      "command": "uvx",
      "args": ["gapscan", "mcp", "--root", "${workspaceFolder}"]
    }
  }
}
```

### Any other client

Run `uvx gapscan mcp --root <project folder>` as a stdio server.

## Better results

The snippet tool uses GapScan's own rules, which need Semgrep. Run `gapscan setup --no-data` once (or
`uvx gapscan setup --no-data`) so the scanners are installed; without them the server still answers,
with only the built-in data-flow checks.

Ask the assistant to check its work, for example: *"Before you finish, scan the files you changed
with GapScan and fix anything it reports."*
