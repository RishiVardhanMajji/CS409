from pwn import *
from hashlib import sha256
import string

HOST = "0.cloud.chals.io"
PORT = 12145

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python", "./server.py"])
target = remote(HOST, PORT)


def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp, end='')
    return resp


def sendline(msg):
    print(msg)
    target.sendline(msg.encode())


def recvline():
    resp = target.recvline().decode()
    print(resp, end='')
    return resp


def recvall():
    resp = target.recvall().decode()
    print(resp, end='')
    return resp


def get_proof(index: int) -> tuple[int, list[str]]:
    recvuntil(f"-{DATA_LEN-1}: ")
    sendline(str(index))
    recvuntil("Value: ")
    val = int(recvline().strip())
    recvuntil("Proof: ")
    proof = eval(recvline().strip())
    return val, proof


recvuntil("Data Length: ")
DATA_LEN = int(recvline().strip())
recvuntil("Root Hash: ")
ROOT_HASH = recvline().strip()

# ===== YOUR CODE BELOW =====
# You can use the function "get_proof(index : int) -> tuple[int, list[str]]" to retrieve the ASCII value of the character at the specified index and a list of hexstrings of the proof
# Set the data variable to your guess of data (in bytes)
# The variable "DATA_LEN" stores the length of the flag
# The variable "ROOT_HASH" stores the root hash of the Merkle Tree

recovered = [None] * DATA_LEN

# one query per 4-byte block (allowed = DATA_LEN/4)
# allowed n/4 queries → one per 4-byte block
for idx in range(0, DATA_LEN, 4):
    val, proof = get_proof(idx)
    recovered[idx] = val if isinstance(val, int) else val[0]

    proof_bytes = [bytes.fromhex(p) for p in proof]
    # immediate sibling leaf (last proof element)
    #last proof hash = sibling leaf
    if proof_bytes:
        sib_hash = proof_bytes[-1]
        sib_idx = idx ^ 1
        # brute-force single printable char whose hash matches
        if recovered[sib_idx] is None:
            for ch in string.printable:
                if sha256(ch.encode()).digest() == sib_hash:
                    recovered[sib_idx] = ord(ch)
                    break

    # sibling subtree of size 2 (second-last proof element) -> brute-force printable pairs
    # second-last proof hash = sibling subtree (2-byte pair)
    if len(proof_bytes) >= 2:
        pair_hash = proof_bytes[-2]
        base = (idx // 4) * 4
        a_pos, b_pos = base + 2, base + 3
        # brute-force printable pairs to match subtree hash
        if (0 <= a_pos < DATA_LEN) and (0 <= b_pos < DATA_LEN) and (recovered[a_pos] is None or recovered[b_pos] is None):
            found = False
            for a in string.printable:
                ha = sha256(a.encode()).digest()
                for b in string.printable:
                    if sha256(ha + sha256(b.encode()).digest()).digest() == pair_hash:
                        recovered[a_pos], recovered[b_pos] = ord(a), ord(b)
                        found = True
                        break
                if found:
                    break

# fill unknowns with '?' and produce final bytes
data = bytes([c if c is not None else ord('?') for c in recovered])


#data = None
# ===== YOUR CODE ABOVE =====

recvuntil("(in hex): ")
sendline(data.hex())

recvline()

target.close()

#flag --> cs409{maybe_you_don't_know_what's_lost_'til_you_find_it_merkle!}