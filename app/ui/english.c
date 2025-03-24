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
    "Sparrow Testnet",
    "Multichain",

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

    // Device menu
    "Information",
    "Verification",
    "Update ERC20 db",
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
    "Set Keycard PIN",
    " remaining attempt(s)",
    "Repeat Keycard PIN",
    "New PIN saved",

    // PUK input
    "Keycard PUK",
    "Wrong PUK",
    "Set Keycard PUK",
    "Repeat Keycard PUK",
    "New PUK saved",
    "If your Keycard becomes blocked, you can enter your Personal Unlocking Code (PUK) to unblock it. Your PUK can be any 12 digit number. Don't forget to write it down.",

    // Pairing input
    "Insert your pairing password",
    "Input new pairing password",
    "New pairing password saved",
    "If you change the pairing pass from the default, you will have to manually enter it on pairing requests between your current Keycard and any other wallet and app.",

    // Name input
    "Card name saved",

    // Input hints
    "Hold to exit",
    "Hold to save",
    "Hold to proceed",

    // Factory reset
    "Card factory reset",
    "Factory reset will permanently erase all keys on your card.\nEnsure you back up your seed phrase. The device will restart after resetting.",

    // Info messages
    "Keycard disconnected",
    "Please remove and reinsert it",
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
    "Write it down and keep it safe",
    "Missing",

    // DB Update
    "Downloading database",
    "The database update was successful.",
    "The new database data seems to be invalid.\n Check that you are using the correct site and try again.",
    "Internal error while writing the new data, please try again.",
    "No database found. Please use the USB cable to perform its installation.",
    "Update database",

    // FW Upgrade
    "Downloading firmware",
    "Do not disconnect your device",
    "The uploaded firmware's signature does not match. Please make sure you are using the official website or app.",
    "Update firmware",

    // Mnemonic input
    "Add key pair",
    "12 words",
    "18 words",
    "24 words",
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

    // Device verification
    "Wrong QR",
    "This is not a device verification QR code.",
    "This QR code does not contain a valid device verification.",
    "Device and site authentic",
    "You can safely use your device.",

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
};
