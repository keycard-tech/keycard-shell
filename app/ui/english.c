#include "i18n.h"

const char *const i18n_english_strings[] = {
    // Main menu
    "Scan QR transaction",
    "Connect software wallet",
    "Addresses",
    "Settings",
    "Help",

    // Connect menu
    "Ethereum",
    "Bitcoin",
    "Bitcoin MultiSig",
    "Bitcoin Testnet",
    "Multiple blockchains",

    // Addresses menu
    "Ethereum",
    "Bitcoin",

    // Settings menu
    "Device",
    "Keycard",

    // Keycard menu
    "Set card name",
    "Change PIN",
    "Change PUK",
    "Change pairing pass",
    "Factory reset card",
    "Unblock with PUK",
    "Enter pairing password",

    // Device menu
    "Information",
    "Verification",
    "Update ERC-20 database",
    "Set brightness",
    "Auto-off time",
    "USB-data",

    // Help menu
    "View help documentation",

    // TX
    "Confirm transfer",
    "Confirm approval",
    "Chain",
    "To",
    "Spender",
    "Amount",
    "Signed amount",
    "Multiple recipients",
    "WARNING: recipients could change! Do not sign unless you absolutely know what you are doing.",
    "Fee",
    "Signer",
    "Data",
    "No",
    "Yes",
    "Input",
    "Output",
    "Signed",
    "Sighash",
    "ALL",
    "NONE",
    "SINGLE",
    "ANYONECANPAY",
    "Change",
    "Sat",
    "Unlimited",
    "A bit of",

    // MSG Confirmation
    "Sign message",
    "Message",

    // EIP712 Confirmation
    "Sign EIP712",
    "Contract",
    "Name",

    // QR output
    "Scan with your wallet",
    "Scan to verify",
    "Your ETH address",
    "Your BTC address",

    // PIN input
    "Keycard PIN",
    "Wrong PIN",
    "Create Keycard PIN",
    " remaining attempt(s)",
    "Repeat Keycard PIN",
    "New PIN saved",

    // PUK input
    "Keycard PUK",
    "Wrong PUK",
    "Create Keycard PUK",
    "Repeat Keycard PUK",
    "New PUK saved",
    "If your Keycard becomes blocked, you can enter your Personal Unlocking Code (PUK) to unblock it. Your PUK can be any 12 digit number. Don't forget to write it down.",

    // Duress input
    "Create duress PIN",
    "Repeat duress PIN",
    "Setup duress PIN?",
    "A duress PIN unlocks a decoy wallet if you're forced to log in under pressure.\nIt looks real but keeps your actual funds and data hidden.\nLearn more: keycard.tech/duress_pin",
    "Both PINs set",
    "Use duress PIN if forced to unlock device",

    // Pairing input
    "Insert your pairing password",
    "Input new pairing password",
    "New pairing password saved",
    "If you change the pairing pass from the default, you will have to manually enter it on pairing requests between your current Keycard and any other wallet and app.",

    // Name input
    "Card name saved",

    // Input hints
    "Hold to go back",
    "Hold to confirm",
    "Hold to proceed",
    "Skip",

    // Factory reset
    "Card factory reset",
    "Factory reset will permanently erase all keys on your card.\nEnsure you back up your seed phrase. The device will restart after resetting.",
    "Keycard reset complete",
    "The key pair has been erased",

    // Info messages
    "Keycard disconnected",
    "Please remove and reinsert it",
    "Can't read the card",
    "Make sure it is a Keycard and the chip is facing up",
    "Not a Keycard",
    "Please replace with a Keycard",
    "Keycard may be fake",
    "Do not press OK unless you loaded a custom Keycard",
    "Old applet detected",
    "This Keycard is too old. Please replace with a newer one.",
    "No free pairing slots on card.",
    "Use Keycard with a previous device or factory reset",
    "Wrong key pair",
    "This QR can't be used with this key pair. Try a different Keycard.",
    "Invalid QR",
    "Malformed data or unsupported format.",
    "Keycard blocked",
    "Key pair added to Keycard",
    "Keep your recovery phrase safe",
    "Invalid phrase entered",
    "Try again",
    "Write down and keep safe",
    "Missing",
    "Keycard paired",
    "Wrong pairing password",
    "Can't sign this transaction",
    "Key pair does not match or transaction type not supported",

    // DB Update
    "Downloading database",
    "Database updated",
    "Received database is invalid",
    "Couldn't write database",
    "No database",
    "Please use USB update",
    "Update database",
    "Incompatible delta",
    "Select the correct database version",
    "Enter this database version number at keycard.tech/update",
    "Generate the update QR code",
    "Press OK to scan",

    // FW Upgrade
    "Downloading firmware",
    "Do not disconnect your device",
    "Invalid firmware",
    "This firmware is not authentic. Please upgrade through the official site",
    "Update firmware",

    // Mnemonic input
    "Add key pair",
    "12 words",
    "12 words + passphrase",
    "24 words",
    "24 words + passphrase",
    "Import recovery phrase",
    "Generate new key pair",
    "Enter word #",
    "Select word #",
    "Ensure your recovery phrase is written down and stored securely.\nYou will need to complete a quiz to confirm the integrity of your backup.",
    "Wrong answer",
    "Phrase incorrectly recalled",
    "View phrase again",
    "Confirm recovery phrase",
    "You will now be asked to confirm your recovery phrase. You can go back and write it down if you haven't already.",
    "Enter passphrase",

    // Device verification
    "Verify device",
    "Confirm the authenticity of your Keycard Shell. Scan your device's authentication QR on on the official Keycard website. You will also scan a QR on the Keycard website with the device to ensure the site is also legitimate. Better safe than sorry!",
    "Wrong QR",
    "This is not a device verification QR code",
    "Site is not authentic",
    "Check URL or try another browser",
    "Device and site authentic",
    "You can safely use your device",

    // LCD settings
    "LCD brightness",

    // Auto off times
    "Set auto off timeout",
    "3 minutes",
    "5 minutes",
    "10 minutes" ,
    "30 minutes",
    "Never",

    // USB enable
    "Enable USB data transfer",
    "Off",
    "On",

    // Device info
    "Device information",
    "Firmware version",
    "Database version",
    "Serial number",

    // Prompts
    "Start typing to see suggestions",
    "Enter new card name",
    "Enter Keycard pairing pass",
    "Enter new Keycard pairing pass",
};
