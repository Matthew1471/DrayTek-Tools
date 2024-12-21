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
This example shows the various functions and methods in the DrayTek-Tools package.

The functions in this module allow you to:
- See a sample DSL Status message being decrypted and parsed.
- See a new DSL Status message being generated.
"""

# We provide some data in hex format for ease of data entry.
import binascii

# We generate and show a SHA-1 hash.
import hashlib

# All the shared DrayTek® DSL Status message functions are in this package.
from draytek_tools import dsl_status

def show_decrypt_example():
    """
    Show an encrypted DSL Status message payload being decrypted.

    Returns:
        None
    """

    print('-----------------------------------------------------------')
    print('Example 1 : Decrypting and parsing DSL Status message bytes')
    print('-----------------------------------------------------------\n')

    # Test sample data.
    mac_address = binascii.unhexlify('aabbccddeeff')

    message = binascii.unhexlify(
        '2052052030e2584e6d7f105167f7a0f4db1e921e1375577792f52fe5ed4f14e17722d021d3770aa9af3e591441'
        'a9ef02514c4e278ef5701a5ede036b232f94bd54e3b8fe4515cb163d78a8b2f40dd980f2f4841f6c9679b6bf4f'
        '94263824175b2f75bf6a51f9c2fb029590f95f39ca2d9efc7e4b'
    )

    # Show the decryption key.
    print('MAC Address (Hex):\n\n ' + str(binascii.hexlify(mac_address)) + '\n')
    print(' ->\n')
    mac_address_digest = binascii.hexlify(hashlib.sha1(mac_address).digest())
    print('MAC Address SHA-1 (Hex):\n\n ' + str(mac_address_digest) + '\n')
    print(' ->\n')
    print('Decryption Key (Bytes):\n\n ' + str(dsl_status.cryptography.get_key(mac_address)) + '\n')

    # Show the raw encrypted payload bytes.
    print(' +\n')
    print('Encrypted Payload (Bytes):\n\n ' + str(message) + '\n')

    # Perform the decryption.
    decrypted_payload = dsl_status.cryptography.decrypt_bytes(mac_address, message)

    # Show the raw decrypted payload bytes.
    print(' =\n')
    print('Decrypted Payload (Bytes):\n\n ' + str(decrypted_payload) + '\n')

    # Show the unpacked data.
    print(' ->\n')
    unpacked_payload = dsl_status.Message.convert_bytes_to_tuple(decrypted_payload)
    print('Unpacked Payload (Tuple):\n\n ' + str(unpacked_payload) + '\n')

    # Parse the DSL Status message.
    message = dsl_status.Message(decrypted_payload)

    # Output the parsed DSL Status message to the console.
    print(' ->\n')
    print('DSL Status:\n')
    print(message)

def show_generated_example():
    """
    Show a DSL Status message being generated.

    Returns:
        None
    """

    print('-----------------------------------------------')
    print('Example 2 : Generating a new DSL Status message')
    print('-----------------------------------------------\n')

    # Make a new DSL Status message.
    message = dsl_status.Message()
    message.modem_firmware_version = 'LOL!'.encode()

    # Output the generated DSL Status message to the console.
    print('DSL Status:\n')
    print(message)

    # Output the DSL Status message bytes to the console.
    print(' ->\n')
    print('Packed (Bytes):\n\n ' + str(message.convert_to_bytes()) + '\n')

# Launch the methods if invoked directly.
if __name__ == '__main__':

    # Show decrypting and parsing DSL Status message sample data.
    show_decrypt_example()

    # Show how we can create a sample DSL Status message.
    show_generated_example()
