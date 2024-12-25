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
This listens for a DrayTek® Vigor DSL Status message broadcast, decrypts and parses it.
If the modem is reporting success then it returns a 0, otherwise it returns non-zero and EdgeOS
may then choose to initiate WAN failover.
"""

# We use the system socket APIs to listen for network traffic.
import socket

# We have to rely on calling OpenSSL as we cannot install packages.
import subprocess

# The program arguments are read.
import sys


# Get the key for your specific modem from the keygen script.
DECRYPT_KEY = '31424143373742324339'

# Pylint: f-string cannot be used in Python 2.x.
# pylint: disable=consider-using-f-string

# Check whether the user has invoked this directly.
if len(sys.argv) != 4:
    print('Usage: {} <load_balance_group> <test_interface> <current_status>'.format(sys.argv[0]))
    sys.exit(1)

# Create a UDP socket to listen for DSL Status messages.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set a timeout of 11 seconds (the modem should broadcast every 10 seconds).
sock.settimeout(11)

# Bind to all interfaces on port 4944.
sock.bind(('0.0.0.0', 4944))

# Maximum number of bytes to receive.
MAX_RECEIVE_BYTES = 116

try:
    # If a payload of the incorrect length is received we try again.
    while True:
        # Attempt to receive a broadcast packet.
        receive_buffer, ip_address = sock.recvfrom(MAX_RECEIVE_BYTES)

        # Check to see if this would be the right length for a DSL Status message.
        if len(receive_buffer) != 116:
            # Wait for another message as this is not a DSL Status message.
            continue

        # Run the OpenSSL command using subprocess to perform the decryption.
        # Pylint: Context manager for subprocess not available in Python 2.x.
        # pylint: disable=consider-using-with
        process = subprocess.Popen([
            "openssl", "enc", "-d", "-aes-128-cbc",
            "-K", DECRYPT_KEY,
            "-iv", DECRYPT_KEY,
            "-nopad"
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # pylint: enable=consider-using-with

        # Pass the encrypted data through stdin and obtain the output and any errors.
        stdout, stderr = process.communicate(input=receive_buffer[4:])

        # Did OpenSSL fail to decrypt the contents?
        if process.returncode != 0:
            # Failed to decrypt (DSL status unknown); Write to log.
            subprocess.call([
                'logger',
                '-t draytek_health',
                'WLB: Decryption failed "{}".'.format(stderr)
            ])

            # Return a DSL Status success out of caution.
            sys.exit(0)

        # Only obtain the status (this script needs to be performant)
        # PyLint: Not a constant; false positive.
        # pylint: disable=invalid-name
        decrypted_status = str(stdout[86:-14].split(b'\0', 1)[0])

        # Check the DSL status.
        if decrypted_status == 'SHOWTIME':

            # If the connection is not marked as currently okay, log that it now seems okay.
            if sys.argv[3] != 'OK':
                subprocess.call([
                    'logger',
                    '-t draytek_health',
                    'WLB: Load-Balance group {} interface {} ({}) DSL status now good.'.format(
                        sys.argv[1],
                        sys.argv[2],
                        sys.argv[3]
                    )
                ])

            # Return Success.
            sys.exit(0)
        else:
            # Failed; Write to log.
            subprocess.call([
                'logger',
                '-t draytek_health',
                'WLB: Load-Balance group {} interface {} ({}) DSL status bad ({}).'.format(
                    sys.argv[1],
                    sys.argv[2],
                    sys.argv[3],
                    str(decrypted_status)
                )
            ])

            # Return failure.
            sys.exit(1)

except socket.timeout:

    # Failed; Write to log.
    subprocess.call([
        'logger',
        '-t draytek_health',
        'WLB: Load-Balance group {} interface {} ({}) Timeout waiting for DSL status.'.format(
            sys.argv[1],
            sys.argv[2],
            sys.argv[3]
         )
    ])

    # Return failure.
    sys.exit(1)
finally:
    # Clean up any resources.
    sock.close()
