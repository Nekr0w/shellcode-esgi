#!/usr/bin/env python3
import re
import sys
import os

def header():
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("~ Shellcode Extractor by Ander Arrosteguy, Matthieu Bailly & Mohamed Bouhastine ~")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

def main():
    objdump = os.popen("objdump -d %s" % (sys.argv[1])).read()
    opcodes = re.findall("[a-f0-9]{2} ", objdump.split("\n",7)[7])

    shellcode = ""
    null_bytes = 0

    print("[+] found %d opcodes\n" % (len(opcodes)))

    for opcode in opcodes:
        if (opcode.rstrip() == '00'):
            null_bytes += 1
            print("\033[91m%s\033[0m" % (opcode), end='')
        else:
            print("%s" % (opcode), end='')
        shellcode = shellcode + "\\x" + opcode.rstrip()

    print()
    if (null_bytes > 0):
        print("\n\033[93m[!] found %d NULL bytes\033[0m" % (null_bytes),end='')

    print("\n[+] shellcode result for %s :\n\n%s" % (sys.argv[1], shellcode))

if (__name__ == "__main__"):
    header()
    if (len(sys.argv[1:]) == 1):
        main()
    else:
        print("Usage : %s <binary_file>" % (sys.argv[0].split('/')[-1]))