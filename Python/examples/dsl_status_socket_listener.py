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
This example listens for DrayTek® Vigor™ DSL Status message broadcasts and decrypts and parses them.
"""

# We use the system socket APIs to listen for network traffic.
import socket

# The program arguments are read.
import sys

# All the shared DrayTek® DSL Status message functions are in this package.
from draytek_tools import dsl_status


def receive_data(mac_address):
    """
    Listens to DSL Status message broadcasts on the network.

    This method takes a MAC address, listens for DSL Status
    message broadcasts, decrypts them and displays them.

    Args:
        mac_address (string): The MAC address of the sending device.

    Returns:
        None
    """

    # Create a UDP socket to listen for DSL Status messages.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Bind to all interfaces on port 4944.
        sock.bind(('0.0.0.0', 4944))

        # Maximum number of bytes to receive.
        max_receive_bytes = 116

        # Keep listening for messages until the program is exited.
        while True:

            # Attempt to receive a broadcast packet.
            receive_buffer, ip_address = sock.recvfrom(max_receive_bytes)

            # Check to see if this would be the right length for a DSL Status message.
            if len(receive_buffer) != 116:
                # Wait for another message as this is not a DSL Status message.
                continue

            # Notify the user a message has been received.
            print(f'Received UDP Datagram from {ip_address[0]} of correct size;'
                    f' using MAC address {mac_address} to decrypt contents:\n')

            # Perform the decryption.
            decrypted_payload = dsl_status.cryptography.decrypt_bytes(
                mac_address,
                receive_buffer
            )

            # Debugging.
            # print('Raw (Bytes):\n\n ' + str(decrypted_payload) + '\n')
            # print(' ->\n')
            # unpacked_payload = dsl_status.Message.convert_bytes_to_tuple(decrypted_payload)
            # print('Unpacked (Tuple):\n\n ' + str(unpacked_payload) + '\n')
            # print(' ->\n')

            # Parse the DSL Status message.
            message = dsl_status.Message(decrypted_payload)

            # Output to console.
            print(message)

if __name__ == '__main__':

    # Check whether the user has supplied a source MAC address.
    if len(sys.argv) != 2:
        print('Usage:')
        print(f'{sys.argv[0]} <MAC Address of Vigor™ DSL Modem>')
        print(f'e.g. {sys.argv[0]} aa:bb:cc:dd:ee:ff')
        sys.exit(1)

    # Start listening for data.
    receive_data(sys.argv[1])
