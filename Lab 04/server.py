from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from math import gcd
import secrets
import random
import signal
import time


BLOCK_SIZE = 4
timelimit = 250

FLAG = "REDACTED"


class TimedOut(Exception):
    pass


def _alarm_handler(signum, frame):
    raise TimedOut()


def timed_input(prompt: str, timeout: int):
    """Get input from user with timeout (seconds). Unix only (uses signal.alarm)."""
    # install handler
    old_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _alarm_handler)
    # use setitimer for fractional secs if needed
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        val = input(prompt)
        signal.setitimer(signal.ITIMER_REAL, 0)  # cancel alarm
        return val
    except TimedOut:
        # Ensure alarm is cancelled and handler restored
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        raise
    finally:
        # restore old handler if it wasn't restored already
        try:
            signal.signal(signal.SIGALRM, old_handler)
        except Exception:
            pass


def genkeys(n):
    pub = getPrime(n)
    while (True):
        b = []
        prod = 1
        while (len(b) < 8*BLOCK_SIZE):
            p = getPrime(n//(8*BLOCK_SIZE))
            if (p not in b):
                b.append(p)
                prod *= p
        if (prod < pub):
            break
    while (True):
        s = random.randint(0, pub-1)
        if (gcd(s, pub-1) == 1):
            break
    v = []
    e = pow(s, -1, pub-1)
    for ele in b:
        v.append(pow(ele, e, pub))
    return (b, pub, v, s)


def encrypt(v, pub, x):
    blkbin = (bin(bytes_to_long(x))[2:]).rjust(8 * BLOCK_SIZE, '0')
    c = 1
    for i, bit in enumerate(blkbin):
        if (bit == '1'):
            c = (c * v[i]) % pub
    return c


def decrypt(c, s, b, pub):
    m = 0
    cts = pow(c, s, pub)
    for i in range(8*BLOCK_SIZE):
        g = gcd(cts, b[i])
        f = (g-1)//(b[i]-1)
        m += (f << (8*BLOCK_SIZE - i - 1))
    return long_to_bytes(m)


if __name__ == "__main__":
    print(f"Hello and welcome to the unbreakable cipher.\nWe offer a bounty of 1 krypton to anyone who can break our cipher within a time limit of {timelimit} seconds.\nAre you ready for the challenge?")
    print()
    start_time = time.time()
    for i in range(25):
        print(f"Challenge #{i}:")
        b, pub, v, s = genkeys(1024)
        mhex = secrets.token_hex(BLOCK_SIZE)
        m = bytes.fromhex(mhex)
        ct = encrypt(v, pub, m)
        print(long_to_bytes(ct))
        print(v)
        print(pub)
        print()
        elapsed = time.time() - start_time
        remaining_time = timelimit - elapsed

        if remaining_time <= 0:
            print("\nMy Grandma can solve this faster than you")
            exit(0)
        try:
            inp = timed_input(
                "Tell me the plaintext (hex): ", timelimit).strip()
        except TimedOut:
            print("\nMy Grandma can solve this faster than you")
            exit(0)
        try:
            inp_hex = bytes.fromhex(inp)
        except Exception as e:
            print("Hmm that doesn't look like hex to me ...")
            exit(e)
        if (bytes.fromhex(inp) == m):
            print("Correct!")
        else:
            print("The cipher remains unbreakable.")
            exit(0)
    end_time = time.time()
    total_elapsed = end_time - start_time

    if total_elapsed > timelimit:
        print("\nToo slow :(")
        exit(0)
    print("You have broken my unbreakable cipher, here is your reward:")
    print(FLAG)
