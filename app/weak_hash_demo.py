import hashlib


def file_fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def legacy_token(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
