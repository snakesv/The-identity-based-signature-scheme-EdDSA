import os
import time
from Crypto.Random import random
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE256
import binascii

#Tham so Ed448
p = int(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff)  # 2**448 - 2**224 - 1
order = int(0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3)
Gx = int(0x4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e)
Gy = int(0x693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14)
G = ECC.EccPoint(Gx, Gy, curve='ed448')
def public_to_point(xy):
    xy = bytes.fromhex(xy)
    xy = xy.decode()
    xylist = xy.split(",")
    x = int(xylist[0])
    y = int(xylist[1])
    point = ECC.EccPoint(x, y, curve='ed448')
    return point
def Compress(x, y):
    xy = str(x) + "," + str(y)
    return xy.encode().hex()
def MK_Generation():
    print("--Ed448 MasterKey Generation--")
    start_time = time.time()
    m_prik = random.randint(1, order - 1)
    print("Master Private Key: ", m_prik)
    m_pubk = m_prik * G
    print("Master Public Key: ", Compress(m_pubk.x, m_pubk.y))
    end_time = str(round((time.time() - start_time), 15))
    print("------------------")
    print("Time to generate masterkey (sec) = ", end_time)
    m_prik_str = str(m_prik)
    #Open the file "m_prik.txt", save master private key
    f = open("D:\m_prik.txt", "w")
    f.write(m_prik_str)
    m_pubk_str = Compress(m_pubk.x, m_pubk.y)
    #Open the file "m_pubk.txt", save master public key
    f1 = open("D:\m_pubk.txt", "w")
    f1.write(m_pubk_str)
    exit = input()
def SubK_Generation():
    print("--Ed448 SubKey Generation--")
    file_path = input('Enter the master private key file: ')
    while os.path.exists(file_path) < 1:
        print('MPK file does not exist!')
        file_path = input('Re-enter the master private key file: ')
    f = open(file_path, "r")
    m_prik = int(f.read())
    m_pubk = m_prik * G
    strA = str(input("User's ID: "))
    id = strA.encode()
    start_time = time.time()
    preh_id = SHAKE256.new(str(m_prik).encode() + id)
    r = int.from_bytes(preh_id.read(32), "big") % order
    R = r * G
    R_str = Compress(R.x, R.y)
    m_pubk_str = Compress(m_pubk.x, m_pubk.y)
    pre_h = SHAKE256.new(R_str.encode() + m_pubk_str.encode() + id)
    h = int.from_bytes(pre_h.read(32), "big") % order
    u_prik = (r + h*m_prik) % order
    print("User's private key is: ", u_prik)
    u_pubk = u_prik * G
    print("User's public key is: ", Compress(u_pubk.x, u_pubk.y))
    end_time = str(round((time.time() - start_time), 15))
    print("------------------")
    print("Time to generate keys for user(sec) = ", end_time)
    #Open the file "u_prik.txt", save user's private key
    u_prik_str = str(u_prik)
    f1 = open("D:\\u_prik.txt", "w")
    f1.write(u_prik_str)
    #Open the file "u_pubk.txt", save user's public key
    u_pubk_str = Compress(u_pubk.x, u_pubk.y)
    f2 = open("D:\\u_pubk.txt", "w")
    f2.write(u_pubk_str)
    exit = input()
def Sign():
    file_path = input('Enter the file path to sign: ')
    while os.path.exists(file_path) < 1:
        print('File does not exist!')
        file_path = input('Re-enter the file path to sign: ')
    file_path1 = input("Enter the user's private key file: ")
    while os.path.exists(file_path1) < 1:
        print('UPK file does not exist!')
        file_path1 = input("Re-enter the user's private key file:")
    f = open(file_path1, "r")
    u_prik = int(f.read())
    u_pubk = u_prik * G
    u_pubk_str = Compress(u_pubk.x, u_pubk.y)
    start_time = time.time()
    with open(file_path, "rb") as f:
        data = f.read()  # read entire file as bytes
    prehashed_message = SHAKE256.new(str(u_prik).encode() + data)
    r = int.from_bytes(prehashed_message.read(32), "big") % order
    R = r * G
    R_str = Compress(R.x, R.y)
    pre_h = SHAKE256.new(R_str.encode() + u_pubk_str.encode() + data)
    h = int.from_bytes(pre_h.read(32), "big") % order
    s = (r + h*u_prik) % order
    print("User's signature is:")
    print("R = ", Compress(R.x, R.y))
    print("s = ", s)
    end_time = str(round((time.time() - start_time), 15))
    print("------------------")
    print("Time to sign (sec) = ", end_time)
    f1 = open("D:\\R.txt", "w")
    f1.write(R_str)
    f2 = open("D:\\s.txt", "w")
    f2.write(str(s))
    exit = input()
def Verify():
    fp_R = input('Enter the R file: ')
    while os.path.exists(fp_R) < 1:
        print('R file does not exist!')
        fp_R = input('Re-enter the R file: ')
    f_R = open(fp_R, "r")
    R_str = f_R.read()
    fp_s = input('Enter the s file: ')
    while os.path.exists(fp_s) < 1:
        print('s file does not exist!')
        fp_s = input('Re-enter the s file: ')
    f_s = open(fp_s, "r")
    s = int(f_s.read())
    fp_pubk = input("Enter the User's public key file: ")
    while os.path.exists(fp_pubk) < 1:
        print("User's public key does not exist!")
        fp_pubk = input("Re-enter the User's public key file: ")
    f_pubk = open(fp_pubk, "r")
    u_pubk_str = f_pubk.read()
    fp_msg = input('Enter the message file: ')
    while os.path.exists(fp_msg) < 1:
        print('Message file does not exist!')
        fp_msg = input('Re-enter the message file: ')
    with open(fp_msg, "rb") as f_msg:
        data = f_msg.read()  # read entire file as bytes
    start_time = time.time()
    pre_h = SHAKE256.new(R_str.encode() + u_pubk_str.encode() + data)
    h = int.from_bytes(pre_h.read(32), "big") % order
    P1 = s * G
    P2 = R_str
    R = public_to_point(R_str)
    u_pubk = public_to_point(u_pubk_str)
    P2 = R + h*u_pubk
    if P1 == P2:
        print("The signature is valid!")
    else:
        print("The signature is invalid!")
    end_time = str(round((time.time() - start_time), 30))
    print("------------------")
    print("Time to verify signature (sec) = ", end_time)
    exit = input()
def main():
    print("***********************************************")
    print("************ IBS-Ed448 Program ************")
    print("***********************************************")
    print("Choose one of the options below:")
    print("[1] Master Key Generation")
    print("[2] SubKey Generation")
    print("[3] Sign")
    print("[4] Verify Signature")
    print("***********************************************")
    choice = input("Enter the number [1,2,3,4]: ")
    match choice:
        case "1":
            MK_Generation()
        case "2":
            SubK_Generation()
        case "3":
            Sign()
        case "4":
            Verify()
if __name__ == '__main__':
    main()
