"""Shared HTTP session construction for the scanner.

Why this module exists
----------------------
DVWA (and some other locally-hosted targets) are commonly reached through a
*dot-less* host name such as ``localhost``.  When such a target sets its
session cookie it includes an explicit ``Domain`` attribute::

    Set-Cookie: PHPSESSID=...; path=/; domain=localhost; HttpOnly

Python's standard cookie handling maps the dot-less host ``localhost`` to the
so-called "effective request host" ``localhost.local``.  As a result the
``domain=localhost`` cookie is stored but then *never sent back*, because it
fails the default cookie policy's domain checks.  Every request therefore
arrives without a session, the CSRF token that the server generated is never
echoed, and authentication silently fails -- the crawler simply finds zero
pages.

``curl`` and browsers are lenient here, which is why a target can look
perfectly healthy from the command line while the scanner still fails.

``ScannerSession`` fixes this by:

1. using :class:`DotlessHostCookiePolicy`, which accepts a cookie whose
   ``Domain`` exactly matches a dot-less request host; and
2. re-applying the session's cookies in :meth:`ScannerSession.send`.  This
   second step is required because ``requests`` merges the session cookie jar
   into a throw-away jar (with the stock, host-strict policy) while preparing
   each request, which would otherwise discard our custom policy.

The rebuild lives in ``send`` rather than ``prepare_request`` on purpose:
``requests`` follows redirects *internally* by calling ``send`` again with a
freshly prepared request, and that redirect request's ``Cookie`` header is
built with the stock policy -- ``prepare_request`` is never re-run for it.
A fix that only touched ``prepare_request`` was therefore lost on the very
first redirect hop (for example, the 302 that DVWA's ``security.php`` returns
after changing the security level), which silently dropped the authenticated
session and produced a zero-page crawl.
"""

from http.cookiejar import DefaultCookiePolicy
from urllib.parse import urljoin, urlparse

import requests

DEFAULT_USER_AGENT = "Mozilla/5.0 (Scanner Research Tool)"


class DotlessHostCookiePolicy(DefaultCookiePolicy):
    """Cookie policy that also returns cookies for dot-less hosts.

    A cookie such as ``Domain=localhost`` is normally rejected when the
    request is for ``localhost`` because the cookie library treats dot-less
    hosts as if they were ``<host>.local``.  This subclass treats an exact
    match between the cookie domain and the request host as valid whenever
    the host has no dots (``localhost``, a Docker service name, etc.).
    """

    @staticmethod
    def _is_dotless_host_match(domain, request):
        cleaned = (domain or "").lstrip(".").lower()
        host = (urlparse(request.get_full_url()).hostname or "").lower()
        return bool(cleaned) and cleaned == host and "." not in cleaned

    def set_ok_domain(self, cookie, request):
        if self._is_dotless_host_match(cookie.domain, request):
            return True
        return super().set_ok_domain(cookie, request)

    def domain_return_ok(self, domain, request):
        if self._is_dotless_host_match(domain, request):
            return True
        return super().domain_return_ok(domain, request)

    def return_ok_domain(self, cookie, request):
        if self._is_dotless_host_match(cookie.domain, request):
            return True
        return super().return_ok_domain(cookie, request)


class ScannerSession(requests.Session):
    """A ``requests.Session`` that reliably keeps cookies for dot-less hosts."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cookies.set_policy(DotlessHostCookiePolicy())

    def send(self, request, **kwargs):
        """Send a request after rebuilding its ``Cookie`` header.

        ``requests`` builds the merged cookie jar with a fresh, stock-policy
        jar (which drops ``domain=localhost`` cookies) and it will not
        overwrite a ``Cookie`` header that is already present.  We therefore
        drop any existing header and rebuild it from our own jar so the
        tolerant policy actually applies.

        Doing this in ``send`` (rather than ``prepare_request``) is what makes
        it work for redirects too: ``requests`` resolves redirects by calling
        ``send`` for every hop, so each hop gets the correct cookies.
        """
        if isinstance(request, requests.PreparedRequest):
            request.headers.pop("Cookie", None)
            cookie_header = requests.cookies.get_cookie_header(
                self.cookies, request
            )
            if cookie_header:
                request.headers["Cookie"] = cookie_header
        return super().send(request, **kwargs)


def build_session(user_agent=DEFAULT_USER_AGENT):
    """Return a scanner HTTP session with the given User-Agent."""
    session = ScannerSession()
    session.headers.update({"User-Agent": user_agent})
    return session


def dvwa_login(session, base_url, username=None, password=None):
    """Log a session into DVWA and force the security level to LOW.

    DVWA stores the security level in a *per-session* cookie, so it has to
    be set on every session the scanner opens.  The crawler and the fuzzer
    use separate sessions; if only the crawler lowers the level, the fuzzer
    runs at DVWA's default (``impossible``), where each vulnerability page
    demands a CSRF ``user_token`` and redirects every request that lacks
    one.  The scanner then sees nothing but redirects and reports zero
    findings -- even though the target is wide open at the LOW level.

    Returns ``True`` when the session ends up authenticated with the
    security cookie set to ``low``.
    """
    from bs4 import BeautifulSoup

    base = base_url.rstrip("/") + "/"
    login_url = urljoin(base, "login.php")

    response = session.get(login_url, timeout=10, allow_redirects=True)
    soup = BeautifulSoup(response.text, "html.parser")
    token_field = soup.find("input", {"name": "user_token"})
    if not token_field:
        print("[!] DVWA login token not found (is the target DVWA?)")
        return False

    login_response = session.post(
        login_url,
        data={
            "username": username or "admin",
            "password": password or "password",
            "Login": "Login",
            "user_token": token_field.get("value", ""),
        },
        timeout=10,
        allow_redirects=False,
        headers={"Referer": login_url},
    )

    location = login_response.headers.get("Location", "")
    if "index.php" not in location:
        print(
            f"[!] DVWA authentication failed "
            f"({login_response.status_code} -> {location or 'no redirect'})"
        )
        return False

    set_dvwa_security(session, base_url, "low")
    return session.cookies.get("security") == "low"


def set_dvwa_security(session, base_url, level="low"):
    """Set the DVWA security level for an already-authenticated session.

    The level lives in a per-session cookie, so this must be called on
    every session (crawler *and* fuzzer) before it touches a vulnerable
    page.  Returns ``True`` if the level was applied.
    """
    from bs4 import BeautifulSoup

    base = base_url.rstrip("/") + "/"
    security_url = urljoin(base, "security.php")

    response = session.get(security_url, timeout=10, allow_redirects=True)
    soup = BeautifulSoup(response.text, "html.parser")
    token_field = soup.find("input", {"name": "user_token"})
    token = token_field.get("value", "") if token_field else ""

    session.post(
        security_url,
        data={
            "security": level,
            "seclev_submit": "Submit",
            "user_token": token,
        },
        timeout=10,
        allow_redirects=True,
        headers={"Referer": security_url},
    )
    return session.cookies.get("security") == level
