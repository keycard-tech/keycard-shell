import argparse

from common import *

def main():
    parser = argparse.ArgumentParser(description='Output the SHA256 hash of the firmware')
    parser.add_argument('-b', '--binary', help="the firmware bin file")
    args = parser.parse_args()
    
    fw = bytearray(b'\xff') * FW_SIZE

    with open(args.binary, 'rb') as f:
        f.readinto(fw)
        hash = hash_firmware(fw)
        print(hash.hex())

if __name__ == "__main__":
    main()