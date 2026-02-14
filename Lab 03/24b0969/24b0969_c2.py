from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 32703

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


recvuntil("originally assigned: ")
original_mac = recvline().strip()
recvuntil("secret: ")
iv = recvline().strip()

# ===== YOUR CODE BELOW =====
# The variable "orginal_mac" contains the MAC digest (as a hex string) of the credentials you were originally assigned
# The variable "iv" contains the IV (as a hex string) used to generate the MAC
# Set the data (in hex) you want to send to Möbius Hacker in the variable "mobius_data"


original_mac_bytes = bytes.fromhex(original_mac)
iv_bytes = bytes.fromhex(iv)

# Define the data we want to append
append_data = b"&admin=true"
append_block = pad(append_data, AES.block_size)#m2

# Craft the message for the oracle (Möbius Hacker)
# mobius_data_bytes = m2^t1^iv
mobius_data_bytes = strxor(strxor(append_block, original_mac_bytes), iv_bytes)
mobius_data = mobius_data_bytes.hex()
#now its func(m2^t1)=>t2

# ===== YOUR CODE ABOVE =====

recvuntil("(in hex) > ")
sendline(mobius_data)
recvuntil("(in hex) --> ")
mobius_mac = recvline().strip()

# ===== YOUR CODE BELOW =====
# The variable "orginal_mac" contains the MAC digest (as a hex string) of the credentials you were originally assigned
# The variable "iv" contains the IV (as a hex string) used to generate the MAC
# The variable "mobius_mac" contains the MAC digest (as a hex string) of the message you sent to Möbius Hacker
# Set the credetials to be sent to the server in the variables "creds"
# Set the mac to be sent to the server in the variable "forged_mac"

DATA = b"user=cs409learner&password=V3ry$3cur3p455"
DATA = pad(DATA, AES.block_size)

creds_bytes = DATA + append_block
creds = creds_bytes.hex()
#now this maxc would be the mac for m1||m2
forged_mac = mobius_mac 

# ===== YOUR CODE ABOVE =====

recvuntil("idenitity credentials to access the system (in hex): ")
sendline(creds)

recvuntil("MAC of your credentials (in hex): ")
sendline(forged_mac)

recvline()
recvline()

target.close()

#I'm having the mac of original msg->t
#need mac of originalmsg||admin=true --> its continuation of using t over the second half
#m1||m2 ->t1||t2; we need to create t2 => func(t1^m2),and we can do this without using m1
# flag --> cs409{53cur1ty_f0r_4ll_t1m3_4lw4y5}