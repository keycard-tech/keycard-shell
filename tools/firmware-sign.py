# This tool is for development only, not to be used for releases

import argparse
from secp256k1Crypto import PrivateKey
import hashlib
import tempfile
import subprocess
import pathlib

PAGE_SIZE = 8192
FW_PAGE_COUNT = 76
FW_SIZE = PAGE_SIZE * FW_PAGE_COUNT
FW_IV_SIZE = 588
SIG_SIZE = 64

def hash_firmware(fw):
    h = hashlib.sha256()
    h.update(fw[:FW_IV_SIZE])
    h.update(fw[FW_IV_SIZE+SIG_SIZE:])
    return h.digest()

def sign(sign_key, m):
    key = PrivateKey(bytes(bytearray.fromhex(sign_key)), raw=True)
    sig = key.ecdsa_sign(m, raw=True)
    return key.ecdsa_serialize_compact(sig)

def elf_to_bin(elf_path, out_path):
    subprocess.run(["arm-none-eabi-objcopy", "-O", "binary", "--gap-fill=255", elf_path, out_path], check=True)

def replace_elf_section(elf_path, section_name, section_content):
    subprocess.run(["arm-none-eabi-objcopy", "--update-section", f'.{section_name}={section_content}', elf_path, elf_path], check=True)

def main():
    parser = argparse.ArgumentParser(description='Sign the firmware and convert ELF to bin')
    parser.add_argument('-s', '--secret-key', help="the secret key file")
    parser.add_argument('-e', '--elf', help="the firmware ELF file")
    parser.add_argument('-o', '--output', help="the output binary file")
    args = parser.parse_args()
    
    with open(args.secret_key) as f: 
        sign_key = f.read()

    fw = bytearray(b'\xff') * FW_SIZE
    tmp_bin = tempfile.mktemp()
    elf_to_bin(args.elf, tmp_bin)

    with open(tmp_bin, 'rb') as f:
        fw_size = f.readinto(fw)

    pathlib.Path.unlink(tmp_bin)

    m = hash_firmware(fw)
    signature = sign(sign_key, m)

    with tempfile.NamedTemporaryFile('wb', delete=False) as f:
        f.write(signature)
        f.write(fw[FW_IV_SIZE+SIG_SIZE:FW_IV_SIZE+SIG_SIZE+4])
        f.close()
        replace_elf_section(args.elf, "header", f.name)
        pathlib.Path.unlink(f.name)

    elf_to_bin(args.elf, args.output)

    if (fw_size % 16) != 0:
        with open(args.output, 'ab') as f:
            f.seek(0, 2)
            f.write(bytearray(b'\xff') * (16 - (fw_size % 16)))

if __name__ == "__main__":
    main()