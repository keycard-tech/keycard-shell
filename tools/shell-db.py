# This tool is for development only, not to be used in production

from datetime import datetime
import argparse
import struct
import requests

from common import PAGE_SIZE, WORD_SIZE
from tokens import *

VERSION_MAGIC = 0x4532

def pad_write(f, buf):
    f.write(buf)
    
    size = len(buf)
    padlen = WORD_SIZE - (size % WORD_SIZE)

    while padlen > 0:
        f.write((0x80 | padlen).to_bytes(1))
        padlen = padlen - 1
        size = size + 1

    while size < PAGE_SIZE:
        f.write(0xff.to_bytes(1))
        size = size + 1

def serialize_db(f, chains, tokens, version):
    buf = struct.pack("<HHI", VERSION_MAGIC, 4, version)

    for chain in chains.values():
        serialized_chain = serialize_chain(chain)
        if len(buf) + len(serialized_chain) <= PAGE_SIZE:
            buf = buf + serialized_chain
        else:
            pad_write(f, buf)
            buf = serialized_chain

    for token in tokens.values():
        serialized_token = serialize_token(token)
        if len(buf) + len(serialized_token) <= PAGE_SIZE:
            buf = buf + serialized_token
        else:
            pad_write(f, buf)
            buf = serialized_token
    
    if len(buf) > 0:
        pad_write(f, buf)

def main():
    def_version =  datetime.now().strftime("%Y%m%d")

    parser = argparse.ArgumentParser(description='Create a database from a token, chain and ABI list')
    parser.add_argument('-t', '--token-list', help="the token list json", default="https://gateway.ipfs.io/ipns/tokens.uniswap.org")
    parser.add_argument('-c', '--chain-list', help="the chain list json", default="https://chainid.network/chains.json")
    parser.add_argument('-v', '--version', help="the version in YYYYMMDD format", default=def_version, type=int)
    parser.add_argument('-o', '--output', help="the output file")
    args = parser.parse_args()

    token_list = requests.get(args.token_list).json()
    chain_list = requests.get(args.chain_list).json()
    version = args.version

    tokens = {}
    chains = {}

    for token in token_list["tokens"]:
        process_token(tokens, chains, token, chain_list)
    
    with open(args.output, 'wb') as f:
        serialize_db(f, chains, tokens, version)

if __name__ == "__main__":
    main()