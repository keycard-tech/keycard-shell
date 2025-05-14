# This tool is for development only, not to be used in production

from datetime import datetime
import argparse
import struct
import requests
import json

from common import PAGE_SIZE, WORD_SIZE
from tokens import *
from abi import *

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

def db_write(f, buf, entry):
    if len(buf) + len(entry) <= PAGE_SIZE:
        return buf + entry
    else:
        pad_write(f, buf)
        return entry

def serialize_db(f, chains, tokens, abis, version):
    buf = struct.pack("<HHI", VERSION_MAGIC, 4, version)

    for chain in chains.values():
        serialized_chain = serialize_chain(chain)
        buf = db_write(f, buf, serialized_chain)

    for token in tokens.values():
        serialized_token = serialize_token(token)
        buf = db_write(f, buf, serialized_token)

    for abi in abis.values():
        serialized_abi = serialize_abi(abi)
        buf = db_write(f, buf, serialized_abi)
        
    if len(buf) > 0:
        pad_write(f, buf)

def read_json(url_or_path):
    if url_or_path.startswith('http'):
        return requests.get(url_or_path).json
    else:
        with open(url_or_path) as f:
            return json.load(f)

def main():
    def_version =  datetime.now().strftime("%Y%m%d")

    parser = argparse.ArgumentParser(description='Create a database from a token, chain and ABI list')
    parser.add_argument('-t', '--token-list', help="the token list json", default="https://gateway.ipfs.io/ipns/tokens.uniswap.org")
    parser.add_argument('-c', '--chain-list', help="the chain list json", default="https://chainid.network/chains.json")
    parser.add_argument('-a', '--abi-list', help="the ABI json")
    parser.add_argument('-v', '--version', help="the version in YYYYMMDD format", default=def_version, type=int)
    parser.add_argument('-o', '--output', help="the output file")
    args = parser.parse_args()

    token_list = read_json(args.token_list)
    chain_list = read_json(args.chain_list)
    abi_list = read_json(args.abi_list)

    version = args.version

    tokens = {}
    chains = {}
    abis = {}

    for token in token_list["tokens"]:
        process_token(tokens, chains, token, chain_list)
    
    for abi in abi_list:
        process_abi(abis, abi)
    
    with open(args.output, 'wb') as f:
        serialize_db(f, chains, tokens, abis, version)

if __name__ == "__main__":
    main()