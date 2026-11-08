import ssl

import pytest

from app.services import tls, website


def certificate_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    return ssl.SSLCertVerificationError(code, message)


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (20, "unable to get local issuer certificate"),
        (62, "hostname mismatch"),
        (10, "certificate has expired"),
    ],
)
def test_tls_certificate_failures_are_sanitized(monkeypatch, code, message):
    class Context:
        def wrap_socket(self, raw, server_hostname):
            raise certificate_error(code, message)

    class Raw:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(tls.ssl, "create_default_context", lambda: Context())
    monkeypatch.setattr(tls.socket, "create_connection", lambda *args, **kwargs: Raw())

    result = tls.inspect_tls("example.com")

    assert result["source"] == "TLS"
    assert result["status"] == "error"
    assert result["error_hostname"] == "example.com"
    assert result["verification_code"] == code
    assert result["verification_message"] == message


def test_tls_success_preserves_certificate_details(monkeypatch):
    class Context:
        def wrap_socket(self, raw, server_hostname):
            assert server_hostname == "example.com"
            class Connection:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return None

                def getpeercert(self):
                    return {
                        "issuer": (("organizationName", "Issuer"),),
                        "subject": (("commonName", "example.com"),),
                        "subjectAltName": (("DNS", "example.com"),),
                        "notAfter": "Jan 01 00:00:00 2099 GMT",
                    }

            return Connection()

    class Raw:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(tls.ssl, "create_default_context", lambda: Context())
    monkeypatch.setattr(tls.socket, "create_connection", lambda *args, **kwargs: Raw())

    result = tls.inspect_tls("example.com")

    assert result["status"] == "valid"
    assert result["subject_alt_names"] == (("DNS", "example.com"),)


def test_passive_inspection_reports_certificate_failure(monkeypatch):
    monkeypatch.setattr(
        website,
        "open_pinned_response",
        lambda *args: (_ for _ in ()).throw(certificate_error(62, "hostname mismatch")),
    )

    result = website.inspect_website("https://example.com/path?token=redacted")

    assert result["source"] == "passive_website_inspection"
    assert result["status"] == "unavailable"
    assert result["error_hostname"] == "example.com"
    assert result["verification_code"] == 62
    assert result["verification_message"] == "hostname mismatch"
    assert "token" not in str(result)
