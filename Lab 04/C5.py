from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from math import gcd # To use gcd function
import ast

HOST = "0.cloud.chals.io"
PORT = 26194

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
target = process(["python", "./server.py"])
#target = remote(HOST, PORT)

context.log_level = 'debug'

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


recvuntil("Are you ready for the challenge?\n\n")

for i in range(25):
    recvuntil(f"Challenge #{i}:\n")

    ct_line = recvline().strip()
    ct_bytes = ast.literal_eval(ct_line)
    c = bytes_to_long(ct_bytes)

    v_line = recvline().strip()
    v = ast.literal_eval(v_line)

    pub_line = recvline().strip()
    pub = int(pub_line)

    # ===== YOUR CODE BELOW =====
    # Set the message variable to your guess of the original message (in hex)
    # The variable "c" stores the ciphertext in bytes
    # The variable "v" stores the list of public parameters in decimal
    # The variable "pub" stores the large public prime
   # ===== YOUR CODE BELOW =====
    
    n = len(v)
    half_n = n // 2

    vLeft = v[:half_n]
    vRight = v[half_n:]

    # 1. Precompute all products for the first half (vLeft)
    # This uses fast bitwise checks, not slow strings
    leftTable = {}
    for m_L in range(1 << half_n):
        c_L = 1
        for i in range(half_n):
            # Check the (15-i)-th bit of m_L
            if (m_L >> (half_n - 1 - i)) & 1:
                c_L = (c_L * vLeft[i]) % pub
        leftTable[c_L] = m_L

    # 2. Search the second half (vRight) for a match
    for m_R in range(1 << half_n):
        c_R = 1
        for i in range(half_n):
            # Check the (15-i)-th bit of m_R
            if (m_R >> (half_n - 1 - i)) & 1:
                c_R = (c_R * vRight[i]) % pub

        # Check if invertible
        if gcd(c_R, pub) != 1:
            continue
        
        # Find the target to look up in our table
        c_Rinv = pow(c_R, -1, pub)
        c_L_target = (c * c_Rinv) % pub

        if c_L_target in leftTable:
            # Match found!
            m_L_found = leftTable[c_L_target]
            
            # Reconstruct the full 32-bit message
            solution_mask = (m_L_found << half_n) | m_R
            break

    # 3. Convert to hex
    n_bytes = (n + 7) // 8
    message_bytes = long_to_bytes(solution_mask, n_bytes)
    message = message_bytes.hex()
    
# ===== YOUR CODE ABOVE =====
    target.sendlineafter(b"Tell me the plaintext (hex): ", message.encode())

    # Check the response
    response = recvline()
    if "Correct!" in response: # Removed b before "Correct!"
        log.success(f"Challenge #{i} solved correctly.")
    else:                       # Removed decode()
        log.error(f"Incorrect solution for Challenge #{i}. Server response: {response}")

# After 25 successful rounds, receive the flag
recvuntil(
    "You have broken my unbreakable cipher, here is your reward:\n")
flag = recvline().strip()
log.success(f"Flag: {flag}")

target.close()