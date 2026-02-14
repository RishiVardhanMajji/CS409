
from pwn import *
import hashlib
import ecdsa
import random
from Crypto.Util.number import inverse

HOST = "0.cloud.chals.io"
PORT = 22754

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


recvuntil("Message 1: ")
msg1 = recvline().strip()

recvuntil("r = ")
r_1 = int(recvline().strip())
recvuntil("s = ")
s_1 = int(recvline().strip())

recvuntil("Message 2: ")
msg2 = recvline().strip()

recvuntil("r = ")
r_2 = int(recvline().strip())
recvuntil("s = ")
s_2 = int(recvline().strip())


# ===== YOUR CODE BELOW =====
# Enter the decimal form of the recovered nonce in the variable 'nonce_rec'
# Enter the decimal form of the recovered private key in the variable 'privkey_rec'
n = ecdsa.SECP256k1.order
h1 = int(hashlib.sha256(msg1.encode()).hexdigest(), base=16)
h2 = int(hashlib.sha256(msg2.encode()).hexdigest(), base=16)
r = r_1
# k = (h1- h2) * (s1- s2)^-1 mod n
s_diff = (s_1- s_2) % n
h_diff = (h1- h2) % n
# (s1- s2)^-1 mod n
inv_s_diff = inverse(s_diff, n)
nonce_rec = (h_diff * inv_s_diff) % n # Got the nonce
# d = (k*s1- h1) * r^-1 mod n
# r^-1 mod n
inv_r = inverse(r, n)

k_s1 = (nonce_rec * s_1) % n
k_s1_h1 = (k_s1- h1) % n
privkey_rec = (k_s1_h1 * inv_r) % n # Got the private key
# ===== YOUR CODE ABOVE =====

recvuntil("Enter recovered nonce (as decimal): ")
sendline(str(nonce_rec))
recvuntil("Enter recvoered private_key (as decimal): ")
sendline(str(privkey_rec))

recvline()
recvline()
target.close()