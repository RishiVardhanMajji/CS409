from pwn import *
from Crypto.Util.Padding import pad, unpad

HOST = "0.cloud.chals.io"
PORT = 19966

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python", "./server.py"])
target = remote(HOST, PORT)

def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp)
    return resp

def sendline(msg):
    print(msg)
    target.sendline(msg.encode())

def recvline():
    resp = target.recvline().decode()
    print(resp)
    return resp

def recvall():
    resp = target.recvall().decode()
    print(resp)
    return resp


recvuntil("IV: ")
IV = bytes.fromhex(recvline())

recvuntil("Flag: ")
flag_enc = bytes.fromhex(recvline())


def validate_padding(iv_hex: str, ciphertext_hex: str) -> bool:
    recvuntil("validated:\n")
    sendline(ciphertext_hex)
    recvuntil("IV:\n")
    sendline(iv_hex)
    response = recvline()
    valid_padding = ("Valid Padding!" in response)
    return valid_padding


# ===== YOUR CODE BELOW =====
# The variable IV has the iv (as a bytes object)
# The variable flag_enc has the ciphertext (as a bytes object)
# You can call the function validate_padding(iv_hex: str, ciphertext_hex: str) -> bool which takes in the hex of the iv (str) and hex of the ciphertext (str) and returns True if the corresponding plaintext has valid padding, and return False otherwise (as dictated by the server's response)

# ===== YOUR CODE BELOW =====

n = 16  # AES block size

def split_blocks(data: bytes, size: int = n):
    return [data[i:i+size] for i in range(0, len(data), size)]

def decrypt_block(prev_block: bytes, curr_block: bytes) -> bytes:
    intermediate = [0] * n   # will hold I bytes (D_k(C))
    plaintext = [0] * n      # will hold recovered P bytes

    # work from last byte to first
    for pos in range(n - 1, -1, -1):
        pad_val = n - pos
        for I_guess in range(256):
            # Build forged previous block C' (all zeros start)
            forged = bytearray(b'\x00' * n)

            # set bytes we already discovered so they produce 'pad_val'
            for j in range(pos + 1, n):
                forged[j] = intermediate[j] ^ pad_val

            # set current trial: C'[pos] = I_guess ^ pad_val
            forged[pos] = I_guess ^ pad_val

            # send to oracle: validate_padding expects (iv_hex, ciphertext_hex)
            # it will send ciphertext then IV internally, so passing (forged, curr) is correct
            if validate_padding(forged.hex(), curr_block.hex()):
                # we found the correct intermediate byte
                intermediate[pos] = I_guess
                plaintext[pos] = intermediate[pos] ^ prev_block[pos]
                break

    return bytes(plaintext)

# split ciphertext into blocks (IV + ciphertext blocks)
blocks = [IV] + split_blocks(flag_enc, n)
recovered = b""

# decrypt each block
for i in range(1, len(blocks)):
    recovered += decrypt_block(blocks[i-1], blocks[i])

# remove padding and print flag
flag = unpad(recovered, n).decode()
print(flag)
# ===== YOUR CODE ABOVE =====

target.close()
