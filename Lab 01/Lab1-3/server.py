from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
import random

FLAG = "REDACTED"


def one_time_pad_xor(plaintext: bytes) -> bytes:
    key = b""
    for _ in range(len(plaintext)):
        byte = random.randint(1,255)
        key += byte.to_bytes(1, 'big')
    return strxor(key, plaintext)


def gen_random_string(length: int) -> bytes:
    return get_random_bytes(length)



if __name__ == '__main__':
    obj = None
    try:
        obj = bytes.fromhex(input("Enter hex-encoding of your string: "))
    except:
        print("Invalid Input!")
        exit()

    for level in range(100):
        print(f"\nLevel {level+1}/100")
        print("Performing Encryption...")

        bit = random.randint(0,1)
    
        enc = one_time_pad_xor(obj)
        rand_string = gen_random_string(len(obj))

        c = [None, None]
        c[bit] = enc
        c[1-bit] = rand_string

        print(f"c1: {c[0].hex()}")
        print(f"c2: {c[1].hex()}")

        guess_bit = input("\nWhich of the two is the encryption of your message?\nEnter either c1 or c2: ")
        if guess_bit not in ['c1', 'c2']:
            print("Invalid Input!")
            exit()
        guess_bit = int(guess_bit[-1])-1
        if guess_bit == bit:
            print("Correct!")
        else:
            print("Incorrect! You cannot distinguish! Terminated!")
            exit()

    print("\nCongratulations! You have proved you can distinguish encryptions from random messages!")
    print(f"Here's your flag: {FLAG}")
