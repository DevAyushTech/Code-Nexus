import socket
import ssl
from datetime import datetime, timezone

from app.core.config import settings


def inspect_tls(host: str) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=settings.request_timeout_seconds) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                cert = connection.getpeercert()
                not_after = cert.get("notAfter")
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
                return {"status": "valid", "issuer": cert.get("issuer"), "subject": cert.get("subject"), "subject_alt_names": cert.get("subjectAltName", []), "expires_at": expiry.isoformat() if expiry else None}
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"status": "error", "error": type(exc).__name__}
