"""Shared HTTP helpers for the smoke scripts.

These scripts only ever talk to servers they start themselves (or, on purpose, a public
tunnel or Workers URL). They still take base URLs from arguments and environment
variables, so every URL goes through this module first:

* `base_url(raw)` accepts `http` or `https` with a host and no `user:pass@`, and returns
  it without a trailing slash. Anything else (`file:`, `ftp:`, `gopher:`, a missing host,
  embedded credentials) exits the script.
* `urlopen(request_or_url, timeout=...)` checks the final URL the same way and opens it
  with an opener that has HTTP and HTTPS handlers only, so no other scheme can be
  reached even by a redirect.
"""

import sys
import urllib.parse
import urllib.request

_ALLOWED = ("http", "https")


def check_url(url):
    """Return `url` if it is a plain http(s) URL with a host and no credentials."""
    if not isinstance(url, str) or not url or any(c in url for c in "\r\n\t\0 "):
        raise ValueError("not a plain URL")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in _ALLOWED:
        raise ValueError(f"scheme must be http or https, got {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError("URL has no host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("URL must not carry credentials")
    return url


def base_url(raw):
    """A validated base URL (no trailing slash), or exit the script with a message."""
    try:
        return check_url((raw or "").strip()).rstrip("/")
    except ValueError as e:
        sys.exit(f"refusing base URL {raw!r}: {e}")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.OpenerDirector()
for _handler in (
    urllib.request.ProxyHandler(),
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
    _SafeRedirect(),
    urllib.request.HTTPDefaultErrorHandler(),
    urllib.request.HTTPErrorProcessor(),
):
    _OPENER.add_handler(_handler)


def urlopen(request_or_url, timeout=30):
    """`urllib.request.urlopen` limited to validated http(s) URLs."""
    url = request_or_url if isinstance(request_or_url, str) else request_or_url.full_url
    check_url(url)
    return _OPENER.open(request_or_url, timeout=timeout)
