#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of DrayTek-Tools <https://github.com/Matthew1471/DrayTek-Tools>
# Copyright (C) 2024 Matthew1471!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
DrayTek® Vigor™ DSL Status Cryptography Module.
This module provides methods for encrypting/decrypting DSL Status message broadcasts.
"""

# The hex characters of the SHA-1 digest make up the encryption/decryption key.
import binascii

# Performs the SHA-1 hash of the MAC address.
import hashlib

# Performs the decryption ("pip install pycryptodome" if getting import errors).
from Crypto.Cipher import AES


# The DSL Status broadcast protocol identifies itself with these starting bytes.
SIGNATURE_BYTES = b'\x20\x52\x05\x20'

@staticmethod
def get_key(mac_address):
    """
    Obtains the encryption/decryption key used for DSL Status broadcast messages.

    This method calculates the key by performing a SHA-1 digest on the mac_address,
    taking the first 5 digest bytes, then converting them to upper case hexadecimal,
    then padding the remaining 6 bytes with nulls as AES128 requires a key length of 16 bytes.

    Args:
        mac_address (bytes): The MAC address of the DrayTek® device sending the DSL Status message.

    Returns:
        bytes: The bytes used as a key and IV.
    """

    # If the MAC address is in string form it needs to be converted to bytes.
    if isinstance(mac_address, str):
        mac_address = binascii.unhexlify(mac_address.replace(':', ''))

    # The encryption/decryption key is the first 5 bytes from the SHA-1 digest of the MAC
    # address bytes.
    digest = hashlib.sha1(mac_address).digest()[:5]

    # Get the uppercase (Python prefers lowercase) hexadecimal characters of the digest
    # (5 bytes is 10 characters).
    digest = binascii.hexlify(digest).upper()

    # Pad to 16 bytes (AES128).
    return digest + bytearray([0x0] * 6)

@staticmethod
def decrypt_bytes(mac_address, encrypted_payload):
    """
    Decrypts DSL Status broadcast bytes into bytes.

    This method validates the correct number of bytes, the protocol signature, calculates the
    key and IV using the mac_address and then decrypts the data.

    Args:
        mac_address (bytes): The MAC address of the DrayTek® device sending the DSL Status message.
        encrypted_payload (bytes): The encrypted bytes containing the DSL Status to decrypt.

    Returns:
        bytes: The decrypted bytes.

    Raises:
        ValueError: If the incorrect number of bytes are supplied or the protocol signature bytes
                    are not found. This may indicate changes in the broadcast structure.
    """

    # DSL Status messages, as fixed binary data structures, must be a specific length to be valid.
    if len(encrypted_payload) != 116:
        raise ValueError('Incorrect number of bytes received.')

    # Check the encrypted payload is a DSL Status message.
    if encrypted_payload[:4] != SIGNATURE_BYTES:
        raise ValueError('Incorrect protocol signature bytes.')

    # Get the decryption key (derived from the MAC address) to decrypt the data.
    key = get_key(mac_address)

    # Use AES CBC mode for decryption (The IV is also the same as the key).
    aes = AES.new(key, AES.MODE_CBC, key)
    decrypted_payload = aes.decrypt(encrypted_payload[4:])

    # Return the decrypted payload (without the protocol signature bytes).
    return decrypted_payload

@staticmethod
def encrypt_bytes(mac_address, payload):
    """
    Encrypts DSL Status broadcast bytes.

    This method validates the correct number of bytes, adds the protocol signature,
    calculates the key and IV using the mac_address and then encrypts the data.

    Args:
        mac_address (bytes): The MAC address of the DrayTek® device sending the DSL Status message.
        payload (bytes): The plain-text bytes containing the DSL Status to encrypt.

    Returns:
        bytes: The encrypted bytes with the protocol signature added.

    Raises:
        ValueError: If the incorrect number of bytes are supplied.
                    This may indicate changes in the broadcast structure.
    """

    # DSL Status messages, as fixed binary data structures, must be a specific length to be valid.
    if len(payload) != 112:
        raise ValueError('Incorrect number of bytes received.')

    # Get the encryption key (derived from the MAC address) to encrypt the data.
    key = get_key(mac_address)

    # Use AES CBC mode for encryption (The IV is also the same as the key).
    aes = AES.new(key, AES.MODE_CBC, key)
    encrypted_payload = aes.encrypt(payload)

    # Return the protocol signature and encrypted payload.
    return SIGNATURE_BYTES + encrypted_payload
