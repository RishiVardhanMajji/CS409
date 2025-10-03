import hashlib
import random


FLAG = b"REDACTED" # Flag has been removed from the code ;)


def group_add(m1: bytes, m2: bytes) -> bytes:
    assert len(m1) == len(m2)
    res = b""
    for i in range(len(m1)):
        res += chr((m1[i]+m2[i])%128).encode()
    return res


def one_time_pad_encrypt(plaintext: bytes) -> tuple[bytes, bytes]:
    key = chr(random.randint(0,127)).encode()
    for _ in range(1, len(plaintext)):
        key += chr(hashlib.sha256(key).digest()[0]%128).encode()
    return (key, group_add(key, plaintext))


if __name__ == "__main__":
    key, encrypted_flag = one_time_pad_encrypt(FLAG)
    with open("ciphertext.enc", 'wb') as f:
        f.write(encrypted_flag)
