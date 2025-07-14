import argparse

from common import *

def main():
    parser = argparse.ArgumentParser(description='Output the SHA256 hash of the database')
    parser.add_argument('-b', '--binary', help="the database bin file")
    args = parser.parse_args()
    
    with open(args.binary, 'rb') as f:
        db = f.read()
        hash = hash_db(db)
        print(hash.hex())

if __name__ == "__main__":
    main()