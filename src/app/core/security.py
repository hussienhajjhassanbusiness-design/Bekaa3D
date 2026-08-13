import hashlib

from app.core.config import get_settings


def hash_ip(ip_address: str) -> str:
    """Salted, one-way hash so audit/download logs can detect repeat activity
    without storing a raw IP address. Rotate IP_HASH_SALT periodically (the
    rotate_ip_salt job, SRS §23) to make historical hashes unlinkable."""
    settings = get_settings()
    salted = f"{settings.ip_hash_salt}:{ip_address}"
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()
