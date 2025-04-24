# This tool is for development only, not to be used for releases

import argparse

from common import *

def main():
    parser = argparse.ArgumentParser(description='Create a full image to load on the MCU')
    parser.add_argument('-b', '--bootloader', help="the bootloader")
    parser.add_argument('-p', '--primary-firmware', help="the primary firmware file")
    parser.add_argument('-s', '--secondary-firmware', help="the secondary firmware file")
    parser.add_argument('-f', '--filesystem', help="the filesystem file")
    parser.add_argument('-o', '--output', help="the output file")
    args = parser.parse_args()

    image = bytearray(b'\xff') * FLASH_SIZE
    image_view = memoryview(image)

    secondary_fw = args.secondary_firmware if args.secondary_firmware else args.primary_firmware

    with open(args.bootloader, 'rb') as f: 
        f.readinto(image_view)
    
    with open(args.primary_firmware, 'rb') as f:
        f.readinto(image_view[FW1_OFFSET:])

    with open(args.filesystem, 'rb') as f:
        f.readinto(image_view[FS_OFFSET:])

    with open(args.bootloader, 'rb') as f: 
        f.readinto(image_view[BANK_SIZE:])

    with open(secondary_fw, 'rb') as f:
        f.readinto(image_view[FW2_OFFSET:])

    with open(args.output, 'wb') as f:
        f.write(image)

if __name__ == "__main__":
    main()