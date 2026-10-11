def get_pin():
    try:
        import tkinter.simpledialog
    except ImportError:
        raise ImportError("Tkinter enabled version of Python required")
    return tkinter.simpledialog.askstring("Keycard PIN", "Enter PIN:", show='*')

def keycard_sign(path, digest):
    try:
        from keycard.keycard import KeyCard
        from keycard.secure_channel import SecureChannelVersion
    except ImportError:
        raise ImportError("Please install the Keycard module")

    with KeyCard() as card:
        card.select()

        # Applet 4.x has no pairing; its secure channel checks the card's certificate.
        pairing = None
        if card.secure_channel_version == SecureChannelVersion.V1:
            pairing = card.pair("KeycardDefaultPairing")
        card.open_secure_channel()

        pin = get_pin()

        while not card.verify_pin(pin):
            pin = get_pin()

        try:
            sig = card.sign_with_path(digest, path)
            return sig.signature
        finally:
            if pairing is not None:
                card.unpair(pairing.slot)
