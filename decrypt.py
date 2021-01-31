import re
import hashlib
import base64
from Cryptodome.Cipher import AES
import sys
import argparse


def decodexml(line):
    i = 0
    dic = {}
    while i <= len(line):
        if line[i] == ' ':
            if line[i:i + 3] == ' />' or line[i:i + 2] == ' >':
                break

            i += 1
            sindex = i
            while line[i] != '=':
                i += 1
            k = line[sindex:i]

            i += 1
            sindex = i
            while line[i:i + 2] != '" ':
                i += 1
            v = line[sindex:i + 1]

            dic[k] = v.strip('"')
        i += 1
    return dic


def decryptString(encrypted_data, password="mR3m"):
    if encrypted_data == '':
        return ''

    try:
        encrypted_data = base64.b64decode(encrypted_data)

        salt = encrypted_data[:16]
        associated_data = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        ciphertext = encrypted_data[32:-16]
        tag = encrypted_data[-16:]
        key = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 1000, dklen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        print('[*]Decryption succeed! Decrypted password:', plaintext.decode())
        return plaintext.decode()
    # 解密失败
    except Exception as e:
        print('[!]Error decryption. Encrypted password:', encrypted_data)
        return encrypted_data


def decryptXML(xmlfile, password, output="data.csv"):
    print(password)
    with open(xmlfile, 'r') as f:
        content = f.readlines()

    dataPattern = re.compile(r'<Node (.*?) \/>')  # data
    titlePattern = re.compile(r'<Node (.*?)>')  # title

    writeTitle = True
    write_f = open(output, 'a+')

    for line in content:
        if dataPattern.findall(line):
            dic = decodexml(line.strip())
            if writeTitle:
                for k, v in dic.items():
                    write_f.write(k + ',')
                write_f.write('\n')
                writeTitle = False

            for k, v in dic.items():
                if k == 'Password':
                    write_f.write('"' + decryptString(v, password) + '",')
                else:
                    write_f.write('"' + v + '",')
            write_f.write('\n')

    print('[*]Finishing Decryption!!!')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Decrypt mRemoteNG passwords")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--filepath", help="config file for mRemoteNG")
    group.add_argument("-s", "--string", help="base64 string of mRemoteNG password")
    parser.add_argument("-o", "--output", help="output filename")
    parser.add_argument("-p", "--password", help="Custom password", default="mR3m")

    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    encrypted_data = ""
    if args.filepath is not None:
        decryptXML(args.filepath, args.password, args.output)
    elif args.string is not None:
        print("[*]Decryption succeed! Decrypted password: ".format(decryptString(args.string, args.password)))
