from app.core.config import settings
from app.services.ssrf import UnsafeURL, open_pinned_response, resolve_redirect


def inspect_website(url: str) -> dict:
    current = url
    redirects: list[str] = []
    try:
        for _ in range(settings.max_redirects + 1):
            destination, response, connection = open_pinned_response(current, settings.request_timeout_seconds)
            try:
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    if not location:
                        break
                    current = resolve_redirect(current, location)
                    redirects.append(current)
                    continue
                body_size = 0
                while True:
                    chunk = response.read(min(64 * 1024, settings.max_response_bytes - body_size + 1))
                    if not chunk:
                        break
                    body_size += len(chunk)
                    if body_size > settings.max_response_bytes:
                        raise UnsafeURL("Response exceeded the configured size limit.")
                headers = {key.lower(): value for key, value in response.getheaders()}
                missing = [header for header in ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy") if header not in headers]
                return {"source": "passive_website_inspection", "status": "completed", "final_url": current, "status_code": response.status, "redirects": redirects, "missing_security_headers": missing, "response_bytes_inspected": body_size, "validated_address": destination.address}
            finally:
                response.close()
                connection.close()
        raise UnsafeURL("Redirect limit exceeded.")
    except (OSError, UnsafeURL, ValueError) as exc:
        return {"source": "passive_website_inspection", "status": "unavailable", "error": type(exc).__name__, "redirects": redirects}
