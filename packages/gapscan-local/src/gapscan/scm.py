"""Post the pull-request comment to a self-hosted SCM (GitHub Enterprise Server, GitLab, Bitbucket
Data Center, Azure DevOps Server).

This is the one outbound call GapScan can make, it is a separate command from `scan`/`ci` (hard
rule #2 is about scanning), it goes only to the URL the operator passes, over https (plain http only
to localhost or a private address), and the token is read from an environment variable, never from
an argument or a file.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import quote, urlparse

import httpx

PROVIDERS = ("github", "gitlab", "bitbucket", "azure")
MARKER = "<!-- gapscan-comment -->"
MAX_BODY = 60000


class SCMError(RuntimeError):
    pass


def _check_url(url: str) -> str:
    u = urlparse(url)
    host = u.hostname or ""
    private = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local")
    if not private:
        try:
            private = ipaddress.ip_address(host).is_private
        except ValueError:
            private = False
    if u.scheme != "https" and not (u.scheme == "http" and private):
        raise SCMError(
            "the SCM URL must be https (http is allowed only for localhost or a private address)"
        )
    if not host:
        raise SCMError("the SCM URL has no host")
    return url.rstrip("/")


def build_request(
    provider: str, url: str, repo: str, number: str, body: str
) -> tuple[str, dict[str, object]]:
    """(URL, JSON payload) for one summary comment on a pull/merge request."""
    base = _check_url(url)
    body = (MARKER + "\n" + body)[:MAX_BODY]
    if provider == "github":  # `url` is the API root, e.g. https://ghe.example.com/api/v3
        return f"{base}/repos/{repo}/issues/{quote(number)}/comments", {"body": body}
    if provider == "gitlab":  # repo is the numeric project id or the url-encoded path
        return (
            f"{base}/api/v4/projects/{quote(repo, safe='')}/merge_requests/{quote(number)}/notes",
            {"body": body},
        )
    if provider == "bitbucket":  # repo is PROJECT/slug
        project, _, slug = repo.partition("/")
        return (
            f"{base}/rest/api/1.0/projects/{quote(project)}/repos/{quote(slug)}/pull-requests/{quote(number)}/comments",
            {"text": body},
        )
    if provider == "azure":  # repo is project/repository; `url` includes the organization
        project, _, repository = repo.partition("/")
        return (
            f"{base}/{quote(project)}/_apis/git/repositories/{quote(repository)}/pullRequests/{quote(number)}/threads?api-version=7.0",
            {"comments": [{"parentCommentId": 0, "content": body, "commentType": 1}], "status": 1},
        )
    raise SCMError(f"unknown provider {provider!r}; choose one of {', '.join(PROVIDERS)}")


def _headers(provider: str, token: str) -> dict[str, str]:
    if provider == "gitlab":
        return {"PRIVATE-TOKEN": token}
    if provider == "azure":
        import base64

        return {"Authorization": "Basic " + base64.b64encode(f":{token}".encode()).decode()}
    return {"Authorization": f"Bearer {token}"}


def post_comment(
    provider: str, url: str, repo: str, number: str, body: str, token_env: str,
    client: httpx.Client | None = None,
) -> str:  # fmt: skip
    token = os.environ.get(token_env, "")
    if not token:
        raise SCMError(f"environment variable {token_env} is empty: set it to an access token")
    target, payload = build_request(provider, url, repo, number, body)
    own = client is None
    client = client or httpx.Client(timeout=30)
    try:
        resp = client.post(target, json=payload, headers=_headers(provider, token))
        if resp.status_code >= 300:
            raise SCMError(f"{provider} answered {resp.status_code}: {resp.text[:200]}")
        return target
    except httpx.HTTPError as exc:
        raise SCMError(f"could not reach {provider}: {exc}") from exc
    finally:
        if own:
            client.close()
