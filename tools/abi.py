import struct
import eth_utils

ABI_MAGIC = 0x4142

ETH_ABI_NUM_SIGNED = (1 << 8)
ETH_ABI_NUM_ADDR = (1 << 9)
ETH_ABI_NUM_BOOL = (1 << 10)
ETH_ABI_NUM_FIXED = (1 << 11)

ETH_ABI_DYN_ALPHA = (1 << 8)

ETH_ABI_COMP_VARLEN = (1 << 8)
ETH_ABI_COMP_TUPLE = (1 << 9)

ETH_ABI_NUMERIC = (1 << 12)
ETH_ABI_DYNAMIC = (1 << 13)
ETH_ABI_COMPOSITE = (1 << 14)

ETH_ABI_UINT = ETH_ABI_NUMERIC
ETH_ABI_INT = (ETH_ABI_NUMERIC | ETH_ABI_NUM_SIGNED)
ETH_ABI_BOOL = (ETH_ABI_NUMERIC | ETH_ABI_NUM_BOOL)
ETH_ABI_FIXED = (ETH_ABI_NUMERIC | ETH_ABI_NUM_FIXED | ETH_ABI_NUM_SIGNED)
ETH_ABI_UFIXED = (ETH_ABI_NUMERIC | ETH_ABI_NUM_FIXED)
ETH_ABI_ADDRESS = (ETH_ABI_NUMERIC | ETH_ABI_NUM_ADDR)
ETH_ABI_BYTES = 0
ETH_ABI_VARBYTES = ETH_ABI_DYNAMIC
ETH_ABI_STRING = (ETH_ABI_DYNAMIC | ETH_ABI_DYN_ALPHA)
ETH_ABI_TUPLE = (ETH_ABI_COMPOSITE | ETH_ABI_COMP_TUPLE)
ETH_ABI_ARRAY = ETH_ABI_COMPOSITE
ETH_ABI_VARARRAY = (ETH_ABI_COMPOSITE | ETH_ABI_COMP_VARLEN)

ETH_ARG_HEADER_LEN = 6
ETH_FUNC_HEADER_LEN = 13

def serialize_argument(arg, rest):
    next = b''
    next_off = 0
    
    if len(rest) > 0:
        next = serialize_argument(rest[0], rest[1:])
        next_off = ETH_ARG_HEADER_LEN
    
    children = b''
    children_off = 0
    if (len(arg["child"]) > 0):
        children = serialize_argument(arg["child"][0], arg["child"][1:])
        children_off = ETH_ARG_HEADER_LEN + len(next)

    return struct.pack("<HHH", arg["type"], next_off, children_off) + next + children

def serialize_abi(abi):
    encoded_name = bytes(abi["name"], "ascii") + b'\0'

    args = b''
    args_off = 0

    if len(abi["arguments"]) > 0:
        args = serialize_argument(abi["arguments"][0], abi["arguments"][1:])
        args_off = ETH_FUNC_HEADER_LEN + len(encoded_name)

    data = abi["selector"] + abi["ext_selector"] + struct.pack("<HHB", ETH_FUNC_HEADER_LEN, args_off, abi["attrs"]) + encoded_name + args
    return struct.pack("<HH", ABI_MAGIC, len(data)) + data

def bitsize(size_str):
    if size_str == "":
        return 32
    else:
        return int(size_str) // 8
    
def process_type(abi_type):
    type_base = ""
    type_size = ""
    type_array = False
    type_array_size = ""
    type_in_array = False

    for c in abi_type["type"]:
        if c.isdigit():
            if type_in_array:
                type_array_size = type_array_size + c
            else:
                type_size = type_size + c
        elif (c == "["):
            type_in_array = True
        elif (c == "]"):
            type_in_array = False
            type_array = True
        else:
            type_base = type_base + c
    
    res = {"child": []}
    if type_base == "tuple":
        res["type"] = ETH_ABI_TUPLE
        for component in abi_type["components"]:
            res["child"] = res["child"] + [process_type(component)]
    elif type_base == "int":
        res["type"] = (ETH_ABI_INT | bitsize(type_size))
    elif type_base == "uint":
        res["type"] = (ETH_ABI_UINT | bitsize(type_size))
    elif (type_base == "fixed") or (type_base == "fixedx"):
        res["type"] = (ETH_ABI_FIXED | 32)       
    elif (type_base == "ufixed") or (type_base == "ufixedx"):
        res["type"] = (ETH_ABI_UFIXED | 32)
    elif type_base == "address":
        res["type"] = (ETH_ABI_ADDRESS | 20)
    elif type_base == "bytes":
        if type_size == "":
            res["type"] = ETH_ABI_VARBYTES
        else:
            res["type"] = (ETH_ABI_BYTES | int(type_size))
    elif type_base == "string":
        res["type"] = ETH_ABI_STRING
    elif type_base == "bool":
        res["type"] = (ETH_ABI_BOOL | 1)
    
    if type_array:
        arr_type = 0
        if type_array_size == "":
            arr_type = ETH_ABI_VARARRAY
        else:
            arr_type = (ETH_ABI_ARRAY | int(type_array_size))
        res = {"type": arr_type, "child": [res]}

    return res

def process_function(func):
    func_hash = eth_utils.keccak(text=eth_utils.abi_to_signature(func))
    out = {"name": func["name"], "selector": func_hash[:4], "ext_selector": eth_utils.keccak(func_hash)[:4]}

    if func["stateMutability"] == "payable":
        out["attrs"] = 1
    else:
        out["attrs"] = 0
    
    out["arguments"] = []
    for input in func["inputs"]:
        out["arguments"] = out["arguments"] + [process_type(input)]

    return (func_hash, out)

def process_abi(abis, abi):
    for func in abi:
        if (func["type"] == "function") and ((func["stateMutability"] == "payable") or (func["stateMutability"] == "nonpayable")):
            hash, res = process_function(func)
            abis[hash] = res
