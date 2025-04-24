# This tool is for development only, not to be used for releases

import argparse
import tempfile
import pathlib

from common import *

def main():
    parser = argparse.ArgumentParser(description='Replace the bootloader public key and convert ELF to bin')
    parser.add_argument('-p', '--public-key', help="the public key file")
    parser.add_argument('-e', '--elf', help="the bootloader ELF file")
    parser.add_argument('-o', '--output', help="the output binary file")
    args = parser.parse_args()
    
    with open(args.public_key) as f: 
        pub_key = bytearray.fromhex(f.read())

    with tempfile.NamedTemporaryFile('wb', delete=False) as f:
        f.write(pub_key)
        f.close()
        replace_elf_section(args.elf, "header", f.name)
        pathlib.Path.unlink(f.name)

    elf_to_bin(args.elf, args.output)

if __name__ == "__main__":
    main()