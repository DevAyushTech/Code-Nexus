import socket
import ssl
from datetime import datetime, timezone

from app.core.config import settings
from app.services.ssrf import ssl_error_details


def inspect_tls(host: str) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=settings.request_timeout_seconds) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                cert = connection.getpeercert()
                not_after = cert.get("notAfter")
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
                return {"status": "valid", "issuer": cert.get("issuer"), "subject": cert.get("subject"), "subject_alt_names": cert.get("subjectAltName", []), "expires_at": expiry.isoformat() if expiry else None}
    except ssl.SSLCertVerificationError as exc:
        return {"source": "TLS", "status": "error", "error": type(exc).__name__, **ssl_error_details(exc, host)}
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"source": "TLS", "status": "error", "error": type(exc).__name__, "error_hostname": host}
