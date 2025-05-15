import subprocess
import hashlib
from secp256k1Crypto import PrivateKey

PAGE_SIZE = 8192
WORD_SIZE = 16

BANK_PAGE_COUNT = 128
BANK_SIZE = BANK_PAGE_COUNT * PAGE_SIZE
FLASH_SIZE = BANK_SIZE * 2

FW_PAGE_COUNT = 76
BL_PAGE_COUNT = 4
FW_SIZE = PAGE_SIZE * FW_PAGE_COUNT
BL_SIZE = PAGE_SIZE * BL_PAGE_COUNT
FW_IV_SIZE = 588
SIG_SIZE = 64

FW1_OFFSET = BL_SIZE
FW2_OFFSET = BANK_SIZE + FW1_OFFSET

FS_OFFSET = FW1_OFFSET + FW_SIZE

def sign(sign_key, m):
    key = PrivateKey(bytes(bytearray.fromhex(sign_key)), raw=True)
    sig = key.ecdsa_sign(m, raw=True)
    return key.ecdsa_serialize_compact(sig)

def elf_to_bin(elf_path, out_path):
    subprocess.run(["arm-none-eabi-objcopy", "-O", "binary", "--gap-fill=255", elf_path, out_path], check=True)

def replace_elf_section(elf_path, section_name, section_content):
    subprocess.run(["arm-none-eabi-objcopy", "--update-section", f'.{section_name}={section_content}', elf_path, elf_path], check=True)

def hash_firmware(fw):
    h = hashlib.sha256()
    h.update(fw[:FW_IV_SIZE])
    h.update(fw[FW_IV_SIZE+SIG_SIZE:])
    return h.digest()
