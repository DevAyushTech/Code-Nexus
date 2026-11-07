import ipaddress
import http.client
import re
import ssl
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse


class UnsafeURL(ValueError):
    pass


def ssl_error_details(exc: ssl.SSLCertVerificationError, hostname: str) -> dict[str, object]:
    message = getattr(exc, "verify_message", None)
    if not message and len(exc.args) > 1:
        message = exc.args[1]
    sanitized_message = re.sub(r"[^A-Za-z0-9 .:_-]", "", str(message or ""))[:160]
    details: dict[str, object] = {"error_hostname": hostname}
    verify_code = getattr(exc, "verify_code", None)
    if not isinstance(verify_code, int) and exc.args and isinstance(exc.args[0], int):
        verify_code = exc.args[0]
    if isinstance(verify_code, int):
        details["verification_code"] = verify_code
    if sanitized_message:
        details["verification_message"] = sanitized_message
    return details


@dataclass(frozen=True)
class ResolvedURL:
    original: str
    host: str
    scheme: str
    port: int
    address: str
    path: str


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global and not address.is_loopback and not address.is_private and not address.is_link_local


def resolve_public_url(url: str) -> ResolvedURL:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeURL("Only HTTP and HTTPS URLs with a hostname are allowed.")
    if parsed.username or parsed.password:
        raise UnsafeURL("URLs containing credentials are not allowed.")
    if parsed.port and parsed.port not in {80, 443}:
        raise UnsafeURL("Only ports 80 and 443 are allowed.")
    host = parsed.hostname.rstrip(".").lower()
    if host in {"localhost", "metadata.google.internal", "metadata"} or host.endswith(".localhost") or host.endswith(".internal"):
        raise UnsafeURL("Local and cloud metadata hosts are not allowed.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = list({ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        except socket.gaierror as exc:
            raise UnsafeURL("Hostname could not be resolved.") from exc
    if not addresses or any(not _is_public(address) for address in addresses):
        raise UnsafeURL("Private, loopback, link-local, or reserved destinations are not allowed.")
    address = str(addresses[0])
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return ResolvedURL(url, host, parsed.scheme, port, address, path)


def validate_public_url(url: str) -> tuple[str, str]:
    resolved = resolve_public_url(url)
    return resolved.host, resolved.scheme


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, destination: ResolvedURL, timeout: float, context: ssl.SSLContext):
        super().__init__(destination.address, destination.port, timeout=timeout, context=context)
        self.destination = destination

    def connect(self) -> None:
        sock = socket.create_connection((self.destination.address, self.destination.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.destination.host)


def open_pinned_response(url: str, timeout: float) -> tuple[ResolvedURL, http.client.HTTPResponse, http.client.HTTPConnection]:
    destination = resolve_public_url(url)
    if destination.scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(destination, timeout, ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(destination.address, destination.port, timeout=timeout)
    connection.request("GET", destination.path, headers={"Host": destination.host, "User-Agent": "NexusPassiveInspector/0.1", "Accept": "*/*"})
    return destination, connection.getresponse(), connection


def resolve_redirect(base_url: str, location: str) -> str:
    return urljoin(base_url, location)
