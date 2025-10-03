from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes

with open("ciphertext1.enc", 'rb') as f:
    c1=f.read()
with open("ciphertext2.enc", 'rb') as f:
    c2=f.read()
    
c = strxor(c1,c2)
'''
#t1^k ^ t2^k -> t1^t2
text1=b'cs409{one_time_pad_key_reuse_compromises_security!!!}'
text2=b'Cryptanalysis frequently involves statistical attacks'
print(len(text1))
print(len(text2))
#t1^t2^'cs409.....' ->t1
#first five letters of t1 ->Crypt  and of t2-> cs409


#so c2^k should have Crypt and c1^k should have cs409 at their beginnings
#so k -> Crypt^c1 or cs409^c2

if len(text1)< len(c):
    text1=text1.ljust(len(c))
else :
    text1=text1[:len(c)]
    
if len(text2)< len(c):
    text2=text2.ljust(len(c))
else :
    text2=text2[:len(c)]
    
c3=strxor(text1,c)
c4=strxor(text2,c)
print(c3)
print(c4)
'''
key = b'Cryptanalysis frequently involves statistical attacks'
msg=strxor(key,c)
msg=msg.decode('utf-8')
print(msg)