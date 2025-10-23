import struct

CHAIN_MAGIC = 0x4348
ERC20_MAGIC = 0x3020

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
        if chain_json is not None:
            chain = {
                "id": chain_id,
                "name": chain_json["name"],
                "shortName": chain_json["shortName"],
                "ticker": chain_json["nativeCurrency"]["symbol"],
                "decimals": chain_json["nativeCurrency"]["decimals"],
            }
        
            chains[chain_id] = chain

    if len(token_json["address"]) != 42:
        return
    
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
