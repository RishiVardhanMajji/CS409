from Crypto.Cipher import AES

n = AES.block_size
HEADER = "_Have you heard about the \\{quick\\} brown fox which jumps over the lazy dog?\n__The decimal number system uses the digits 0123456789!\n___The flag is: "

ciphertext = open("ciphertext.bin","rb").read()

mymap = {}
for i in range(len(HEADER)):
    mymap[ciphertext[i*n:(i+1)*n]] = HEADER[i]

flag = ""
for i in range(len(HEADER), len(ciphertext)//n):
    flag += mymap[ciphertext[i*n:(i+1)*n]]

print(flag)


#flag => cs409{r3dund4nt_l34k4g35}