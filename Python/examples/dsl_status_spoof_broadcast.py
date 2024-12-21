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
This example spoofs DrayTek® Vigor DSL Status broadcasts.
"""

# We use a socket to send the broadcasts.
import socket

# The program arguments are read.
import sys

# We use the sleep function to prevent flooding the receivers.
from time import sleep

# All the shared DrayTek® DSL Status cryptographic functions are in this package.
from draytek_tools.dsl_status import cryptography


def send_data(mac_address):
    """
    Sends DSL Status broadcasts on the network.

    This method takes a MAC address, encrypts DSL Status
    samples and sends them.

    Args:
        mac_address (string): The MAC address of the sending device.

    Returns:
        None
    """

    # Sample DSL Status messages.
    messages = [
     '0130d71004624c98000000006163ef60617667a0617667a00000000600000000000000030000000360430e8c0083'
     'd60131322d332d322d332d302d3500ffffff6032c88831374100609400006093c5b0617867a0616453484f575449'
     '4d450000617667a00022ea980000000761990000',

     '0130d71004624c98000000006163ef60617667a0617667a00000000600000000000000030000000360430e8c6163'
     '1d6431322d332d322d332d302d3500ffffff6032c88831374100609400006093c5b0617867a0616453484f575449'
     '4d450000617667a00022eaa20000000761990000',

     '0130d71004624c986152fa6000000001617667a0617667a00000000600000000000000030000000360430e8cffff'
     'fffe31322d332d322d332d302d350000fc036032c92c31374100609400006093c5b0617867a0616453484f575449'
     '4d450000617667a00022eaac0000000761990000',

     '0130d71004624c98000000006163ef60617667a0617667a000000006000000000000000300000003616800000000'
     '000031322d332d322d332d302d35000000010000000531374100609c2800609c2800609c2800ffff53484f575449'
     '4d4500006152fa60fffffffc0002000018800003',

     '0130d71004624c980008bab000000000617667a0617667a00000000600000000000000030000000360430e8c0083'
     'd60131322d332d322d332d302d3500ffffff6032c88831374100609400006093c5b0617867a0616453484f575449'
     '4d450000617667a00022eac00000000761990000'
    ]

    # Repeat until the program is exited.
    while True:

        # Create a socket to send messages.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:

            # Permit sending of broadcast messages.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Take each of our sample messages.
            for message in messages:

                # Notify the user a DSL Status message is being sent.
                print('Sending DSL Status sample via UDP broadcast.')

                # Get the actual bytes for the current message.
                message_bytes = bytes.fromhex(message)

                # Get the encrypted payload for the specified MAC address.
                encrypted_message = cryptography.encrypt_bytes(
                    mac_address,
                    message_bytes
                )

                # Send the DSL Status message to the broadcast address on UDP port 4944.
                sock.sendto(encrypted_message, ("255.255.255.255", 4944))

                # Wait 10 seconds to avoid flooding the broadcast receivers.
                sleep(10)

if __name__ == '__main__':
    # Check whether the user has supplied a source MAC address.
    if len(sys.argv) != 2:
        print('Usage:')
        print(f'{sys.argv[0]} <Network Card\'s MAC Address>')
        print(f'e.g. {sys.argv[0]} aa:bb:cc:dd:ee:ff')
        sys.exit(1)

    # Start sending data.
    send_data(sys.argv[1])
