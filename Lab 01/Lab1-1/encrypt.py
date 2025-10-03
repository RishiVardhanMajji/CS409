from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes

FLAG = b"REDACTED" # Flag has been removed from the code ;)
MESG = b"REDACTED" # The message has been removed from the code ;)
key = get_random_bytes(len(FLAG))

c1 = strxor(key, FLAG)
c2 = strxor(key, MESG)

with open("ciphertext1.enc", 'wb') as f:
    f.write(c1)

with open("ciphertext2.enc", 'wb') as f:
    f.write(c2)
