import tkinter.simpledialog
from secp256k1Crypto import PrivateKey

def get_pin():
    return tkinter.simpledialog.askstring("Keycard PIN", "Enter PIN:", show='*')

def keycard_sign(digest):
    try:
        from keycard.keycard import KeyCard
    except ImportError:
        raise "Please install the Keycard module"
    
    with KeyCard() as card:
        card.select()
        pairing_index, pairing_key = card.pair("KeycardDefaultPairing")
        card.open_secure_channel(pairing_index, pairing_key)
        card.mutually_authenticate()

        pin = get_pin()

        while not card.verify_pin(pin):
            pin = get_pin()
        
        try:
            sig = card.sign_with_path(digest, "m/43'/60'/1581'/35'/0")
            ecdsa = PrivateKey()
            return ecdsa.ecdsa_serialize_compact(ecdsa.ecdsa_deserialize(sig.signature))
        finally:
            card.unpair(pairing_index)
