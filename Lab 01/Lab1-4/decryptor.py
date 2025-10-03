

with open ("ciphertext.enc",'rb') as f:
    x=f.read()
with open ("keyfile",'rb') as f:
    k=f.read()
    
value=0
a=1
for i in range(len(x),0,-1):
    value+=x[i-1]*a
    a*=256

c=[]
for i in range(len(x)):
    c.append(value%255)
    value//=255

c[:]=c[::-1]    

p=[]
for i in range(len(c)):
    p.append((c[i]-k[i]+1)%255)

value=0
a=1
for i in range(len(c),0,-1):
    value+=p[i-1]*a
    a*=255

m=[]
for i in range(len(c)):
    m.append(value%256)
    value//=256

m[:]=m[::-1]

byte_seq = bytes(m)
flag = byte_seq.decode('utf-8')  # or decode('utf-8', errors='replace') if needed
print(flag)

    