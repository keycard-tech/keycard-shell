def get_pin():
    try:
        import tkinter.simpledialog
    except ImportError:
        raise "Tkinter enabled version of Python required"
    return tkinter.simpledialog.askstring("Keycard PIN", "Enter PIN:", show='*')

def keycard_sign(path, digest):
    try:
        from keycard.keycard import KeyCard
    except ImportError:
        raise "Please install the Keycard module"
    
    with KeyCard() as card:
        card.select()
        pairing_index, pairing_key = card.pair("KeycardDefaultPairing")
        card.open_secure_channel(pairing_index, pairing_key)

        pin = get_pin()

        while not card.verify_pin(pin):
            pin = get_pin()
        
        try:
            sig = card.sign_with_path(digest, path)
            return sig.signature
        finally:
            card.unpair(pairing_index)
