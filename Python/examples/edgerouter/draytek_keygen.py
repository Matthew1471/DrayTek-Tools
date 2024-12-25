#!/usr/bin/env python
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
This script generates in advance the key needed to decrypt DrayTek® DSL Status broadcasts.

The key is not calculated by draytek_health.py to reduce computational workload when it is run
every >10 seconds.
"""

# The hex characters of the SHA-1 digest make up the encryption/decryption key.
import binascii

# Performs the SHA-1 hash of the MAC address.
import hashlib

# The program arguments are read.
import sys

# Pylint: f-string cannot be used in Python 2.x.
# pylint: disable=consider-using-f-string

# Check whether the user has supplied a source MAC address.
if len(sys.argv) != 2:
    print('Usage:')
    print('{} <MAC Address of Vigor™ DSL Modem>'.format(sys.argv[0]))
    print('e.g. {} aa:bb:cc:dd:ee:ff'.format(sys.argv[0]))
    sys.exit(1)

# Get the user supplied MAC address from the command line arguments.
mac_address = sys.argv[1]

# If the MAC address is in string form it needs to be converted to bytes.
if isinstance(mac_address, str):
    mac_address = binascii.unhexlify(mac_address.replace(':', ''))

# Pylint: "digest" is not a constant; false positive.
# pylint: disable=invalid-name

# The encryption/decryption key is the first 5 bytes from the SHA-1 digest of the MAC
# address bytes.
digest = hashlib.sha1(mac_address).digest()[:5]

# Get the uppercase (Python prefers lowercase) hexadecimal characters of the digest
# (5 bytes is 10 characters).
digest = binascii.hexlify(digest).upper()

# Get the uppercase hexadecimal characters for the hexadecimal characters
# (to be supplied to OpenSSL as -K).
digest = binascii.hexlify(digest).upper()

# pylint: enable=invalid-name

# Output the decryption key.
print('DECRYPT_KEY = {}'.format(digest.decode()))
