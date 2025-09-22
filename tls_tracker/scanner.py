import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.utils import timezone
from datetime import datetime
import pytz
import logging

logger = logging.getLogger(__name__)


class TLSScanner:
    def __init__(self, timeout=30):
        self.timeout = timeout

    def _make_aware(self, dt):
        """Convert naive datetime to timezone-aware datetime"""
        if dt is None:
            return None
        if timezone.is_naive(dt):
            # Assume UTC for certificate dates
            return timezone.make_aware(dt, pytz.UTC)
        return dt

    def scan_endpoint(self, hostname, port=443):
        """Comprehensive TLS scan for an endpoint"""
        try:
            # Get SSL context and connection info
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # This should allow self-signed certs

            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Basic TLS info
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    if not cert_dict:
                        raise Exception("No certificate found")

                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    if not cert_der:
                        raise Exception(
                            "Could not retrieve certificate in binary format"
                        )

                    # Parse certificate with cryptography
                    cert = x509.load_der_x509_certificate(cert_der)

                    # Try to get certificate chain
                    cert_chain_length = 1
                    cert_chain_raw = ""

                    try:
                        # Try to get the full chain if available
                        if hasattr(ssock, "getpeercert_chain"):
                            cert_chain = ssock.getpeercert_chain()
                            if cert_chain:
                                cert_chain_length = len(cert_chain)
                                cert_chain_raw = self._get_cert_chain_pem(cert_chain)
                        else:
                            # Fallback: just use the single certificate
                            cert_chain_raw = cert.public_bytes(
                                encoding=serialization.Encoding.PEM
                            ).decode()
                    except Exception as e:
                        logger.warning(
                            f"Could not retrieve certificate chain: {str(e)}"
                        )
                        cert_chain_raw = cert.public_bytes(
                            encoding=serialization.Encoding.PEM
                        ).decode()

                    # Check if certificate is self-signed
                    is_self_signed = self._is_self_signed(cert)

                    # Use the new UTC property to avoid deprecation warning
                    cert_expiration = getattr(
                        cert, "not_valid_after_utc", cert.not_valid_after
                    )
                    cert_expiration = self._make_aware(cert_expiration)

                    return {
                        "success": True,
                        "protocol_version": version or "Unknown",
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "key_exchange": (
                            cipher[1] if cipher and len(cipher) > 1 else "Unknown"
                        ),
                        "uses_ephemeral_keys": self._uses_ephemeral_keys(cipher),
                        "cert_subject": cert.subject.rfc4514_string(),
                        "cert_issuer": cert.issuer.rfc4514_string(),
                        "cert_serial_number": str(cert.serial_number),
                        "cert_expiration": cert_expiration,
                        "cert_chain_length": cert_chain_length,
                        "cert_chain_raw": cert_chain_raw,
                        "is_valid": True,
                        "validation_errors": (
                            "Self-signed certificate" if is_self_signed else ""
                        ),
                        "is_self_signed": is_self_signed,
                    }

        except Exception as e:
            logger.error(f"TLS scan failed for {hostname}:{port} - {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "protocol_version": "",
                "cipher_suite": "",
                "key_exchange": "",
                "uses_ephemeral_keys": False,
                "cert_subject": "",
                "cert_issuer": "",
                "cert_serial_number": "",
                "cert_expiration": None,
                "cert_chain_length": 0,
                "cert_chain_raw": "",
                "is_valid": False,
                "validation_errors": str(e),
                "is_self_signed": False,
            }

    def _uses_ephemeral_keys(self, cipher):
        """Check if cipher uses ephemeral key exchange"""
        if not cipher or len(cipher) < 2:
            return False

        key_exchange = cipher[1].upper()
        ephemeral_indicators = ["ECDHE", "DHE", "EDH"]
        return any(indicator in key_exchange for indicator in ephemeral_indicators)

    def _is_self_signed(self, cert):
        """Check if certificate is self-signed"""
        try:
            # A certificate is self-signed if the issuer equals the subject
            return cert.issuer == cert.subject
        except Exception:
            return False

    def _get_cert_chain_pem(self, cert_chain):
        """Convert certificate chain to PEM format"""
        try:
            if not cert_chain:
                return ""

            pem_chain = []
            for cert_der in cert_chain:
                cert = x509.load_der_x509_certificate(cert_der)
                pem_chain.append(
                    cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
                )
            return "\n".join(pem_chain)
        except Exception as e:
            logger.error(f"Error converting cert chain to PEM: {str(e)}")
            return ""

    def get_certificate_info(self, hostname, port=443):
        """Alternative method using just the standard library with self-signed support"""
        try:
            # Create context that allows self-signed certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Get certificate using ssl.get_server_certificate with custom context
            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()

            if not cert_der:
                raise Exception("Could not retrieve certificate")

            cert = x509.load_der_x509_certificate(cert_der)
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()

            # Check if certificate is self-signed
            is_self_signed = self._is_self_signed(cert)

            # Use the new UTC property to avoid deprecation warning
            cert_expiration = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
            cert_expiration = self._make_aware(cert_expiration)

            return {
                "success": True,
                "protocol_version": version or "Unknown",
                "cipher_suite": cipher[0] if cipher else "Unknown",
                "key_exchange": cipher[1] if cipher and len(cipher) > 1 else "Unknown",
                "uses_ephemeral_keys": self._uses_ephemeral_keys(cipher),
                "cert_subject": cert.subject.rfc4514_string(),
                "cert_issuer": cert.issuer.rfc4514_string(),
                "cert_serial_number": str(cert.serial_number),
                "cert_expiration": cert_expiration,
                "cert_chain_length": 1,  # Can't determine chain length with this method
                "cert_chain_raw": cert_pem,
                "is_valid": True,
                "validation_errors": (
                    "Self-signed certificate" if is_self_signed else ""
                ),
                "is_self_signed": is_self_signed,
            }
        except Exception as e:
            logger.error(
                f"Alternative certificate scan failed for {hostname}:{port} - {str(e)}"
            )
            return {
                "success": False,
                "error": str(e),
                "protocol_version": "",
                "cipher_suite": "",
                "key_exchange": "",
                "uses_ephemeral_keys": False,
                "cert_subject": "",
                "cert_issuer": "",
                "cert_serial_number": "",
                "cert_expiration": None,
                "cert_chain_length": 0,
                "cert_chain_raw": "",
                "is_valid": False,
                "validation_errors": str(e),
                "is_self_signed": False,
            }


# Enhanced scanner with fallback methods and self-signed certificate support
class EnhancedTLSScanner(TLSScanner):
    def scan_endpoint(self, hostname, port=443):
        """Try multiple methods to scan the endpoint, handling self-signed certificates"""
        # First try the main method
        result = super().scan_endpoint(hostname, port)

        # If it fails, try the alternative method
        if not result["success"]:
            logger.info(f"Retrying {hostname}:{port} with alternative method")
            result = self.get_certificate_info(hostname, port)

        return result

    def scan_with_verification_options(
        self, hostname, port=443, allow_self_signed=True
    ):
        """Scan endpoint with configurable verification options"""
        try:
            # Try with no verification first (allows self-signed)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (hostname, port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    if not cert_der:
                        raise Exception("No certificate found")

                    cert = x509.load_der_x509_certificate(cert_der)
                    is_self_signed = self._is_self_signed(cert)

                    # If we don't allow self-signed and it is self-signed, return error
                    if not allow_self_signed and is_self_signed:
                        return {
                            "success": False,
                            "error": "Self-signed certificate not allowed",
                            "is_self_signed": True,
                        }

                    cert_pem = cert.public_bytes(
                        encoding=serialization.Encoding.PEM
                    ).decode()

                    # Use the new UTC property to avoid deprecation warning
                    cert_expiration = getattr(
                        cert, "not_valid_after_utc", cert.not_valid_after
                    )
                    cert_expiration = self._make_aware(cert_expiration)

                    return {
                        "success": True,
                        "protocol_version": version or "Unknown",
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "key_exchange": (
                            cipher[1] if cipher and len(cipher) > 1 else "Unknown"
                        ),
                        "uses_ephemeral_keys": self._uses_ephemeral_keys(cipher),
                        "cert_subject": cert.subject.rfc4514_string(),
                        "cert_issuer": cert.issuer.rfc4514_string(),
                        "cert_serial_number": str(cert.serial_number),
                        "cert_expiration": cert_expiration,
                        "cert_chain_length": 1,
                        "cert_chain_raw": cert_pem,
                        "is_valid": True,
                        "validation_errors": (
                            "Self-signed certificate" if is_self_signed else ""
                        ),
                        "is_self_signed": is_self_signed,
                    }

        except Exception as e:
            logger.error(f"TLS scan failed for {hostname}:{port} - {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "protocol_version": "",
                "cipher_suite": "",
                "key_exchange": "",
                "uses_ephemeral_keys": False,
                "cert_subject": "",
                "cert_issuer": "",
                "cert_serial_number": "",
                "cert_expiration": None,
                "cert_chain_length": 0,
                "cert_chain_raw": "",
                "is_valid": False,
                "validation_errors": str(e),
                "is_self_signed": False,
            }


# Create a default scanner instance with enhanced capabilities
scanner = EnhancedTLSScanner()
