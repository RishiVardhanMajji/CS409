from pwn import *

HOST = "0.cloud.chals.io"
PORT = 32320

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


# ===== YOUR CODE BELOW =====

L=5000
payload = "00"*L# TODO: This variable should finally contain the hex-string you want to send
# ===== YOUR CODE ABOVE =====

#so the encrypted msg can't have a 00 byte as the key cant have a 00
recvuntil("string: ")
sendline(payload)

for level in range(100):
    recvuntil("c1: ")
    c1 = recvline().strip()

    recvuntil("c2: ")
    c2 = recvline().strip()
    
    recvuntil("c1 or c2: ")
    # ===== YOUR CODE BELOW =====
    # Write code here to decide whether to send c1 or c2
    # The variable c1 (which is of type str) contains the hex-encoded version of c1 returned by the server
    # The variable c2 (which is of type str) contains the hex-encoded version of c2 returned by the server

    def func(c):
        x=bytes.fromhex(c)
        return b'\x00' in x
    
    if func(c1) and not func(c2) :guess=2
    elif func(c2) and not func(c1): guess=1
    else :guess=1
    # TODO: Set guess to 1 or 2 accordingly if you think the correct answer is c1 vs. c2 respectively
    # ===== YOUR CODE ABOVE =====

    sendline(f"c{guess}")

recvall()
target.close()

#cs409{y0u_h4d_fu11_4dv4nt4g3}
