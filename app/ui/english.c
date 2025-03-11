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
    "Cross-chain",

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
    "Scan with your EVM-chain wallet",
    "Scan with your Bitcoin wallet",
    "Scan with your OKX wallet",
    "Your ETH address",
    "Your BTC address",

    // PIN input
    "Keycard PIN",
    "Wrong PIN. Please try again.",
    "Choose a new PIN",
    "Remaining attempts: ",
    "Repeat the PIN",
    "PINs don't match",
    "PIN changed successfully",

    // PUK input
    "Keycard PUK",
    "Wrong PUK. Please try again.",
    "Choose a new PUK",
    "PUK changed successfully",

    // Pairing input
    "Insert your pairing password",
    "Input new pairing password",
    "Pairing password changed successfully",
    "If you change the pairing pass from the default, you will have to manually enter it on pairing requests between your current Keycard and any other wallet and app.",
    "Change pairing password",

    // Name input
    "Card name changed successfully",

    // Factory reset
    "Card factory reset",
    "Factory reset will permanently erase all keys on your card.\nEnsure you back up your seed phrase. The device will restart after resetting.",

    // Info messages
    "Communication with the card lost.\n\nPlease remove it and insert it again",
    "The inserted card does not appear to be a Keycard. Please replace it with a Keycard",
    "Failed to verify genuineness of this card. Do not press OK unless you loaded a custom Keycard applet on this card yourself",
    "This Keycard has an old version of the applet installed. Please replace it with a newer one",
    "You can't connect this Keycard to new devices because all pairing slots are full.\nPlease use it with a device with which you used it previously or factory reset the card.",
    "This transaction is not for this key pair.\nTry again using a different Keycard.",
    "Malformed data or unsupported format.",
    "Keycard blocked",

    // DB Update
    "Downloading database",
    "The database update was successful.",
    "The new database data seems to be invalid.\n Check that you are using the correct site and try again.",
    "Internal error while writing the new data, please try again.",
    "Enter the version number below on the update website to generate the update QR, then press OK to scan.\n\n",
    "No database found. Please use the USB cable to perform its installation.",
    "Proceed updating the database?\n\n",

    // FW Upgrade
    "Downloading firmware",
    "Do not disconnect your device",
    "The uploaded firmware's signature does not match. Please make sure you are using the official website or app.",
    "Do you want to upgrade your firmware?\n\n",

    // Mnemonic input
    "Add key pair",
    "12 words",
    "18 words",
    "24 words",
    "Import recovery phrase",
    "Generate new key pair",
    "Enter word #",
    "Select word #",
    "Write down and keep safe",
    "Prepare your pen and paper",
    "Wrong answer",
    "Recovery phrase was incorrectly written",
    "Ensure your recovery phrase is written down and stored securely. You will need to complete a quiz to confirm the integrity of your backup.",

    // Device verification
    "Invalid verification QR. Please check the website you are on and try again.",
    "The response from the server is invalid. Ignore the verification results, make sure you go on the correct site and try again.",
    "The verification was successful and this was the first time this unit has been verified. You can safely use the device.",
    "The verification succeeded, however this wasn't the first time the unit has been verified. If you remember already verifying this device before, then there is nothing to worry about. Otherwise please contact us.",

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
    "Firmware version: ",
    "Database version: ",
    "S/N: ",
    "New firmware version: ",
    "New database version: ",
};
