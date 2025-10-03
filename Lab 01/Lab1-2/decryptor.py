import random
import hashlib
#only 128 possible keys
#brute force?

with open("ciphertext.enc", 'rb') as f:
    encflag=f.read()
    
for i in range(0,128):
    key=chr(i).encode()
    for a in range(1, len(encflag)):
        key += chr(hashlib.sha256(key).digest()[0]%128).encode()
            
    flag=b""
    for i in range(len(key)):
        flag+= chr((encflag[i]+127*key[i])%128).encode()
    flag=flag.decode('utf-8')
    if '{' in flag and 'cs409' in flag:
        print (flag)  
#found flag for i=5
#cs409{algebra_enters_the_picture!}