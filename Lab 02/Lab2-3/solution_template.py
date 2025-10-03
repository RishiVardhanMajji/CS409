from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 11437

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
#target = process(["python", "./server.py"])
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


def choice1(params: str) -> str:
    recvuntil("parameters: ")
    sendline("1")
    recvuntil("parameters: ")
    sendline(params)
    recvuntil("hex): ")
    ciphertext_hex = recvline().strip()
    return ciphertext_hex

def choice2(params_enc: str) -> tuple[bool, str]:
    recvuntil("parameters: ")
    sendline("2")
    recvuntil("hex): ")
    sendline(params_enc)
    resp = recvline().strip()
    if resp == "Invalid parameters! Incorrect padding or Non-ASCII characters detected!":
        recvuntil("hex): ")
        return False, recvline().strip()
    elif resp == "Your parameters have been successfully submitted!":
        return False, ""
    elif resp == "Welcome, admin!":
        recvuntil("flag: ")
        return True, recvline().strip()
        


# ===== YOUR CODE BELOW =====
# Use the function choice1(params) the send your parameters (str) to the server (Choice 1)
# It returns (given that your input was successfully processed) the ciphertext as a hex-string


n = AES.block_size  # 16 bytes

ct_hex = choice1("a=b")
ct = bytes.fromhex(ct_hex)
C0 = ct[:n]

# Make the server decrypt and leak plaintext by sending: C0 || zero_block || C0
mal = C0 + (b"\x00" * n) + C0
ok, leaked_hex = choice2(mal.hex())
# we expect the server to return leaked plaintext hex when it rejects the input
leaked = bytes.fromhex(leaked_hex)
P0 = leaked[0:n]
P2 = leaked[2*n:3*n]

# Recover key (because IV == key): key = P0 XOR P2
key = strxor(P0, P2)

#Locally encrypt a params string that contains admin=true using key as IV too.
payload = b"a=1&admin=true"
made = AES.new(key, AES.MODE_CBC, iv=key).encrypt(pad(payload, n))

# Submit made ciphertext and print only the flag if we get admin.
got_admin, flag = choice2(made.hex())

flag_cipher=bytes.fromhex(flag)
flag=unpad(AES.new(key,AES.MODE_CBC,iv=key).decrypt(flag_cipher),n).decode()
print(flag)

# Use the function choice2(params_enc) to send your encrypted parameters (hex string) to the server (Choice 2)
# It returns a 2-tuple: the first component being a boolean indicating whether you got admin access (True) or not (False), the second component being the hex-string returned by the server (empty string in the case that the server returns nothing)
    
# ===== YOUR CODE ABOVE =====

try:
    target.close()
except:
    pass
