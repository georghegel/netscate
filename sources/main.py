from colorama import Fore, Back, Style
import hashlib
import base64

print(Fore.RED, "Please, set obfuscation mode:", sep='')
print(Fore.GREEN, "(1) HEX\t\t| ", Fore.YELLOW, "192.168.0.1 -> ", Fore.CYAN, "c02ea82e02e1", sep='')
print(Fore.GREEN, "(2) Binary\t| ", Fore.YELLOW, "192.168.0.1 -> ", Fore.CYAN, "00110001 00111001 00110010 00101110 00110001 00110110 00111000 00101110 00110000 00101110 00110001", sep='')
print(Fore.GREEN, "(3) SHA256\t| ", Fore.YELLOW, "192.168.0.1 -> ", Fore.CYAN, "b1cf87ce729d9aaa50449b9820156fa31dd47bf32396e8c9ce0f73490ac97ac0", sep='')
print(Fore.GREEN, "(4) SHA512\t| ", Fore.YELLOW, "192.168.0.1 -> ", Fore.CYAN, "67a65a55d62827b1837acc553957afa47492ebb9b0375f23d1dc628abef9f977ab3fbe9d7b31d470905ccdc20a509a0337390dcb2b57ec2cf9374215347baf36", sep='')
print(Fore.GREEN, "(5) Base64\t| ", Fore.YELLOW, "192.168.0.1 -> ", Fore.CYAN, "MTkyLjE2OC4wLjEK", sep='')
print(Fore.GREEN, "(6) MD5\t\t| ", Fore.YELLOW, "192.168.0.1 -> ", Fore.CYAN, "daaf1d27fd83421a66e32ea8d7f37e68", sep='')

mode = int(input())
print(Fore.RED, "Type IP address that you want to obfuscate", sep='')
IP = input()

def hexify(IP):
    res = ""
    IP = IP.split('.')
    IP = [int(x) for x in IP]
    IP = [(str(hex(x))[2:]) for x in IP]
    for i in range(len(IP)):
        res += IP[i]
        if i < len(IP) - 1:
            res += str(hex(ord('.')))[2:]
    return res

def binaryfy(IP):
    res = ''.join(IP)
    res = ''.join(format(ord(i), '08b') for i in res)
    return res

def sha256_(IP):
    return hashlib.sha256(str.encode(IP)).hexdigest()

def sha512_(IP):
    return hashlib.sha512(str.encode(IP)).hexdigest()

def base64_(IP):
    return base64.b64encode(str.encode(IP)).decode()

def md5_(IP):
    return hashlib.md5(str.encode(IP)).hexdigest()

def obfuscate(mode):
    if (mode == 1):
        print(Fore.LIGHTGREEN_EX, hexify(IP), sep='')
    elif (mode == 2):
        print(Fore.LIGHTGREEN_EX, binaryfy(IP), sep='')
    elif (mode == 3):
        print(Fore.LIGHTGREEN_EX, sha256_(IP), sep='')
    elif (mode == 4):
        print(Fore.LIGHTGREEN_EX, sha512_(IP), sep='')
    elif (mode == 5):
        print(Fore.LIGHTGREEN_EX, base64_(IP), sep='')
    elif (mode == 6):
        print(Fore.LIGHTGREEN_EX, md5_(IP), sep='')
    else:
        print("Please, set the correct mode.")

if __name__ == "__main__":
    obfuscate(mode)

