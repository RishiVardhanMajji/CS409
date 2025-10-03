from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 23369

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


def send_to_server(input: str) -> tuple[str, str]:
    recvuntil("$ ")
    sendline(input)
    recvuntil("Encrypted Input (hex): ")
    inp_enc = recvline().strip()
    recvuntil("Encrypted Output (hex): ")
    outp_enc = recvline().strip()
    return (inp_enc, outp_enc)


# ===== YOUR CODE BELOW =====
# Use the send_to_server(input) function to send your input (str) to the server
# It returns a 2-tuple of strings as output: the first component being the encrypted input (hex-string), the second component being the encrypted output (hex-string)

x=1000
known_plaintext=b'0'*x 

enc_inp_hex,enc_out_hex=send_to_server(known_plaintext.decode()) 
enc_inp=bytes.fromhex(enc_inp_hex)

k=strxor(enc_inp,known_plaintext)
enc_flag_in_hex,enc_flag_out_hex=send_to_server("!flag")
flag_ciph=bytes.fromhex(enc_flag_out_hex)

for i in range(len(k)-len(flag_ciph)):
    text=strxor(flag_ciph,k[i:i+len(flag_ciph)])  
    try:
        text = text.decode()
    except UnicodeDecodeError:
        text = text.decode(errors="ignore")
    if "cs409{" in text:
        print(text)
        break
    
#flag-> cs409{y0u_kn0w_th3_gr34t35t_f1lm5_of_4ll_t1m3_w3re_n3v3r_m4d3}

# ===== YOUR CODE ABOVE =====

target.close()
