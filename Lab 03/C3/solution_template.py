from pwn import *
import time

HOST = "0.cloud.chals.io"
PORT = 30216

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


def send_guess(hmac_guess : str) -> int:
    recvuntil("omniscience: ")
    sendline(hmac_guess)
    resp = recvline()
    if "omniscient" in resp:
        recvline()
        return 1
    else:
        return -1


recvuntil("of length ")
msg_len = int(recvuntil(" ")[:-1])

# ===== YOUR CODE BELOW =====
# The variable "msg_len" contains the length of the message that the server is asking for
# Set the message that you want to send to the server (in hex, as str) in the variable "msg"
msg=b"We are what we repeatedly do. Excellence, then, is not an act, but a habit, said Aristotle"
msg = msg[:msg_len]
msg=msg.hex()
# ===== YOUR CODE ABOVE =====

recvuntil("in hex): ")
sendline(msg)

# ===== YOUR CODE BELOW =====
# Use the function "send_guess(hmac_guess : str) -> int" to send your guess of the first 10 hexchars of the hmac to the server
#   A return value of -1 indicates that your guess was incorrect
#   A return value of 1 indicates the your guess was correct

HEX = "0123456789abcdef"
decoded = ""

# keep guessing until we have 10 hex chars
while len(decoded) < 10:
    found = False
    for x in HEX:
        # build candidate: decoded + candidate nibble + padding to length 10
        candidate = decoded + x
        guess = candidate + "0" * (10 - len(candidate))

        # do a few trials to reduce noise, take average time
        trials = 3
        times = []
        result_= -1
        for _ in range(trials):
            start = time.time()
            result = send_guess(guess)
            elapsed = time.time() - start
            times.append(elapsed)
            if result == 1:                    # if server says omniscient -> done
                decoded = candidate
                result_ = 1
                break
        if result_ == 1:
            found = True
            break

        avg_t = sum(times) / len(times)
        # if avg time exceeds current matched-prefix length by ~0.5s(for latency), we take it as matched
        if avg_t > (len(decoded)+0.5):
            decoded += x
            found = True
            break

    if not found:
        continue

    # if we reached full 10 chars, stop
    if len(decoded) == 10:
        break
# build final data variable for sending (not required here; template expects send_guess use only)
# ===== YOUR CODE ABOVE =====

target.close()

#flag-> cs409{k3$h4_0r_t4yl0r_5w1ft?}
