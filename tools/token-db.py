# This tool is for development only, not to be used in production

from datetime import datetime
import argparse
import struct
import requests

from common import PAGE_SIZE, WORD_SIZE

CHAIN_MAGIC = 0x4348
ERC20_MAGIC = 0x3020
VERSION_MAGIC = 0x4532

def serialize_addresses(addresses):
    res = b''
    for id, address in addresses.items():
        if len(address) != 42:
            assert "Unexpected address format"
        res = res + struct.pack("<I20s", id, bytes.fromhex(address[2:]))

    return res

def serialize_chain(chain):
    chain_len = 4 + len(chain["ticker"]) + 1 + len(chain["name"]) + 1 + len(chain["shortName"]) + 1
    return struct.pack("<HHI", CHAIN_MAGIC, chain_len, chain["id"]) + \
        bytes(chain["ticker"], "ascii") + b'\0' + \
        bytes(chain["name"], "ascii") + b'\0' + \
        bytes(chain["shortName"], "ascii") + b'\0'

def serialize_token(token):
    addresses = serialize_addresses(token["addresses"])
    token_len = 1 + len(addresses) + 1 + len(token["ticker"]) + 1
    
    return struct.pack("<HHB", ERC20_MAGIC, token_len, len(token["addresses"])) + \
        addresses + \
        struct.pack("B", token["decimals"]) + \
        bytes(token["ticker"], "ascii") + b'\0'

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

def lookup_chain(chains_json, chain_id):
    for chain in chains_json:
        if chain["chainId"] == chain_id:
            return chain
    return None

def process_token(tokens, chains, token_json, chains_json):
    chain_id = token_json["chainId"]

    chain = chains.get(chain_id)
    if chain is None:
        chain_json = lookup_chain(chains_json, chain_id)
        chain = {
            "id": chain_id,
            "name": chain_json["name"],
            "shortName": chain_json["shortName"],
            "ticker": chain_json["nativeCurrency"]["symbol"],
            "decimals": chain_json["nativeCurrency"]["decimals"],
        }
        
        chains[chain_id] = chain

    symbol = token_json["symbol"]
    token = tokens.get(symbol)
    
    if token is None:
        token = {
            "addresses": {},
            "ticker": symbol,
            "decimals": token_json["decimals"]
        }
        tokens[symbol] = token

    token["addresses"][chain_id] = token_json["address"]

def main():
    def_version =  datetime.now().strftime("%Y%m%d")

    parser = argparse.ArgumentParser(description='Create a database from a token and chain list')
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