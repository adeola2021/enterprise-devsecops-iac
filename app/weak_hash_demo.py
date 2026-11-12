import hashlib


def file_fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def legacy_token(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
