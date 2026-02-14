
from pwn import *
import hashlib
import ecdsa
import random
from Crypto.Util.number import inverse

HOST = "0.cloud.chals.io"
PORT = 24035

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
#target = process(["python", "./server.py"])
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


def point_to_tuple(point):
    return (int(point.x()), int(point.y()))

def tuple_to_point(tup):
    return ecdsa.ellipticcurve.Point(ecdsa.ellipticcurve.CurveFp(ecdsa.NIST256p.curve.p(), ecdsa.NIST256p.curve.a(), ecdsa.NIST256p.curve.b()), tup[0], tup[1])


# -----VARIANT 1-----
recvuntil("Public Key: ")
VARIANT1_PUBKEY = tuple_to_point(eval(recvline().strip()))

# ===== YOUR CODE BELOW =====
# Variables You Have:
#     - VARIANT1_PUBKEY: the public key point used in VARIANT 1 signatures
# Enter the five message (str) you want to get signed in the list 'msgs'
msgs = ["msg1", "msg2", "msg3", "msg4", "msg5"]
# ===== YOUR CODE ABOVE =====

assert len(msgs) == 5
sigs = []
for msg in msgs:
    recvuntil("]: ")
    sendline(msg)
    recvuntil("Signature: ")
    sigs.append(eval(recvline().strip()))
    sigs[-1] = (tuple_to_point(sigs[-1][0]), sigs[-1][1])

recvuntil("Variant 1: ")
challenge_msg_1 = recvline().strip().encode()

# ===== YOUR CODE BELOW =====
# Variables You Have:
#    - VARIANT1_PUBKEY: the public key point used in VARIANT 1 signatures
#    - msgs: the list of messages (str) you had submitted earlier
#    - sigs: list of respective (R, s) VARIANT 1 signatures for each of the messages you had submitted earlier
#    - challenge_msg_1: the message whose VARIANT 1 signature you have to provide
# Set the variable 'R' to the point R of the signature
# Set the variable 's' to the value s of the signature

# Get curve parameters
G = ecdsa.NIST256p.generator
q = G.order()

# --- 1. Get data for the KNOWN signature (msgs[0]) ---
msg1 = msgs[0].encode()
R1, s1 = sigs[0]

# Calculate k1 (the nonce for msg1)
k1_hash_inp = msg1 + str(VARIANT1_PUBKEY.x()).encode()
k1 = int(hashlib.sha256(k1_hash_inp).hexdigest(), base=16) % q

# Calculate e1 (the hash for msg1)
e1_hash_inp = str(R1.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + msg1
e1 = int(hashlib.sha256(e1_hash_inp).hexdigest(), base=16) % q

# --- 2. Get data for the FORGED signature (challenge_msg_1) ---
# Calculate kc (the nonce for the challenge msg)
kc_hash_inp = challenge_msg_1 + str(VARIANT1_PUBKEY.x()).encode()
kc = int(hashlib.sha256(kc_hash_inp).hexdigest(), base=16) % q

# Calculate Rc (the point for the challenge msg)
Rc = kc * G

# Calculate ec (the hash for the challenge msg)
ec_hash_inp = str(Rc.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + challenge_msg_1
ec = int(hashlib.sha256(ec_hash_inp).hexdigest(), base=16) % q

# --- 3. Forge 's' using the one-shot formula ---
# s_c = kc + ec * (s1 - k1) * (e1^-1)
s1_minus_k1 = (s1 - k1) % q
inv_e1 = inverse(e1, q)

s = (kc + (ec * s1_minus_k1 * inv_e1)) % q
R = Rc

# ===== YOUR CODE ABOVE =====

recvuntil(")): ")
sendline(f"({point_to_tuple(R)}, {int(s)})")


# -----VARIANT 2-----
recvuntil("Public Key: ")
VARIANT2_PUBKEY = tuple_to_point(eval(recvline().strip()))

# ===== YOUR CODE BELOW =====
# Variables You Have:
#     - VARIANT2_PUBKEY: the public key point used in VARIANT 1 signatures
# Enter the five message (str) you want to get signed in the list 'msgs'
msgA = "prefix_is_the_same_suffix_is_not_1"
msgB = "prefix_is_the_same_suffix_is_also_2"
msgs = [msgA, msgB, "msg3", "msg4", "msg5"]
# ===== YOUR CODE ABOVE =====

assert len(msgs) == 5
sigs = []
for msg in msgs:
    recvuntil("]: ")
    sendline(msg)
    recvuntil("Signature: ")
    sigs.append(eval(recvline().strip()))
    sigs[-1] = (tuple_to_point(sigs[-1][0]), sigs[-1][1])

recvuntil("Variant 2: ")
challenge_msg_2 = recvline().strip().encode()

# ===== YOUR CODE BELOW =====
# Variables You Have:
#    - VARIANT2_PUBKEY: the public key point used in VARIANT 2 signatures
#    - msgs: the list of messages (str) you had submitted earlier
#    - sigs: list of respective (R, s) VARIANT 2 signatures for each of the messages you had submitted earlier
#    - challenge_msg_2: the message whose VARIANT 2 signature you have to provide
# Set the variable 'R' to the point R of the signature
# Set the variable 's' to the value s of the signature
# Get curve parameters
q = ecdsa.NIST256p.generator.order()
G = ecdsa.NIST256p.generator

# --- 1. Recover Private Key (Your Code - This is 100% correct) ---
msgAbytes = msgs[0].encode()
msgBbytes = msgs[1].encode()
R_a, s_a = sigs[0]
R_b, s_b = sigs[1]
Rknown = R_a # The collided R

# Calculate h_a
h_aHashInp = str(Rknown.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msgAbytes
h_a = int(hashlib.sha256(h_aHashInp).hexdigest(), base=16) % q

# Calculate h_b
h_bHashInp = str(Rknown.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msgBbytes
h_b = int(hashlib.sha256(h_bHashInp).hexdigest(), base=16) % q

# Recover private key 'd'
sDiff = (s_a - s_b) % q
hDiff = (h_a - h_b) % q
hDiffInv = inverse(hDiff, q)
privkey = (sDiff * hDiffInv) % q

# --- 2. Forge Signature for Challenge Message (Corrected Logic) ---
# We must follow the server's exact (flawed) signing process
# using the private key we just found.

# 2a. Calculate the challenge nonce 'kc' based on its prefix
msg_c = challenge_msg_2
msg_c_prefix = msg_c[:len(msg_c)//2]

# The hash is H(prefix_bytes || str(private_key_int).encode())
kc_hash_inp = msg_c_prefix + str(privkey).encode()
kc = int(hashlib.sha256(kc_hash_inp).hexdigest(), base=16) % q

# 2b. Calculate the challenge point 'Rc'
Rforge = kc * G

# 2c. Calculate the challenge hash 'hc'
hc_hash_inp = str(Rforge.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msg_c
hc = int(hashlib.sha256(hc_hash_inp).hexdigest(), base=16) % q

# 2d. Calculate the final signature 'sc'
sForge = (kc + hc * privkey) % q
R = Rforge
s = sForge
# ===== YOUR CODE ABOVE =====

recvuntil(")): ")
sendline(f"({point_to_tuple(R)}, {int(s)})")

target.interactive()