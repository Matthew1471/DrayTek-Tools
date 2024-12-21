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
DrayTek® Vigor DSL Status Message Module.
This module provides methods for representing DSL Status broadcasts.
"""

# We use the struct library to interpret bytes as packed binary data.
import struct

# pylint: disable=too-many-instance-attributes
# This is a data class so is expected to have many instance attributes.
class Message:
    """
    A class to represent a single DrayTek® Vigor DSL Status broadcast message.
    """

    # The format string for the struct pack and unpack methods.
    FORMAT_STRING = '!IIIIIIIIIIII20s4s14s14s12s'

    @staticmethod
    def _truncate_string(string_bytes):
        """
        Truncate the string bytes at the first null terminator.

        C typically uses a null byte to indicate the end of a string in a fixed length structure.
        This internal method truncates any byte array after the first null byte.

        Args:
            string_bytes (bytes): A string encoded as bytes.

        Returns:
            str: The bytes truncated up to the first null byte.
        """

        # Unlike Python, C uses null terminated strings, truncate them.
        return string_bytes.split(b'\0', 1)[0]

    @staticmethod
    def convert_bytes_to_tuple(payload):
        """
        Convert DSL Status bytes to a tuple.

        This static method takes DSL Status bytes, converts the data types and
        separates the fields into a tuple.

        Args:
            payload (bytes): A DSL Status message in bytes.

        Returns:
            tuple: A tuple of each of the fields.
        """

        # We use struct to unpack the payload data.
        return struct.unpack(Message.FORMAT_STRING, payload)

    def __init__(self, payload=None, truncate_strings=True):
        """
        Initialize a DrayTek® Vigor DSL Status message instance, optionally with existing data.

        Args:
            payload (bytes, optional):
                The bytes of a DSL Status message to optionally initalise this instance with.
                Defaults to None.
            truncate_strings (bool, optional):
                Whether to truncate any excess data in the null terminated strings.
                Defaults to True.

        Raises:
            ValueError: If the payload type is not a supported type.
        """

        # Is an empty DSL Status instance being requested?
        if payload is None:
            # Set blank initial values.
            self.vdsl_upload_speed = 0
            self.vdsl_download_speed = 0
            self.adsl_tx_cells = 0
            self.adsl_rx_cells = 0
            self.adsl_tx_crc_errors = 0
            self.adsl_rx_crc_errors = 0
            self.dsl_type = 0
            self.timestamp = 0
            self.vdsl_snr_upload = 0
            self.vdsl_snr_download = 0
            self.adsl_loop_att = 0
            self.adsl_snr_margin = 0
            self.modem_firmware_version = bytearray(20)
            self.vdsl_profile = bytearray(4)
            self.padding = bytearray(14)
            self.state = bytearray(14)
            self.padding2 = bytearray(12)
        # Has the user asked to initialise this object from a byte array?
        elif isinstance(payload, bytes):
            # We use struct to unpack the payload data bytes.
            converted_tuple = self.convert_bytes_to_tuple(payload)

            # Set the fields from the unpacked tuple.
            self.set_from_tuple(converted_tuple, truncate_strings)
        # Unsupported type supplied.
        else:
            raise ValueError(f'Initialising from a {type(payload)} is not supported.')

    def convert_to_bytes(self):
        """
        Converts this instance to a packed series of bytes.

        Returns:
            bytes: The packed bytes representing this DSLStatus instance.
        """
        return struct.pack(
            Message.FORMAT_STRING,
            self.vdsl_upload_speed,
            self.vdsl_download_speed,
            self.adsl_tx_cells,
            self.adsl_rx_cells,
            self.adsl_tx_crc_errors,
            self.adsl_rx_crc_errors,
            self.dsl_type,
            self.timestamp,
            self.vdsl_snr_upload,
            self.vdsl_snr_download,
            self.adsl_loop_att,
            self.adsl_snr_margin,
            self.modem_firmware_version,
            self.vdsl_profile,
            self.padding,
            self.state,
            self.padding2
        )

    def set_from_tuple(self, tuple_data, truncate_arrays = True):
        """
        Sets the fields in this instance to the supplied tuple data.

        Args:
            tuple_data (tuple): The data to set this instance's fields to.

            truncate_strings (bool, optional):
                Whether to truncate any excess data in the null terminated strings.
                Defaults to True.

        Returns:
            None
        """

        # Set fields from the tuple.
        self.vdsl_upload_speed = tuple_data[0]
        self.vdsl_download_speed = tuple_data[1]
        self.adsl_tx_cells = tuple_data[2]
        self.adsl_rx_cells = tuple_data[3]
        self.adsl_tx_crc_errors = tuple_data[4]
        self.adsl_rx_crc_errors = tuple_data[5]
        self.dsl_type = tuple_data[6]
        self.timestamp = tuple_data[7]
        self.vdsl_snr_upload = tuple_data[8]
        self.vdsl_snr_download = tuple_data[9]
        self.adsl_loop_att = tuple_data[10]
        self.adsl_snr_margin = tuple_data[11]

        if truncate_arrays:
            self.modem_firmware_version = self._truncate_string(tuple_data[12])
            self.vdsl_profile = self._truncate_string(tuple_data[13])
            self.padding = tuple_data[14]
            self.state = self._truncate_string(tuple_data[15])
        else:
            self.modem_firmware_version = tuple_data[12]
            self.vdsl_profile = tuple_data[13]
            self.padding = tuple_data[14]
            self.state = tuple_data[15]

        self.padding2 = tuple_data[16]

    def __str__(self):
        """
        Converts this instance to a string representation of its contents.

        Returns:
            string: A string representing this DSLStatus instance.
        """
        result = (f' VDSL Upload Speed: {self.vdsl_upload_speed} bps'
                  f' ({self.vdsl_upload_speed // 1000000} Mbps)\n')
        result += (f' VDSL Download Speed: {self.vdsl_download_speed} bps'
                   f' ({self.vdsl_download_speed // 1000000} Mbps)\n')
        result += f' ADSL TX Cells: {self.adsl_tx_cells}\n'
        result += f' ADSL RX Cells: {self.adsl_rx_cells}\n'
        result += f' ADSL TX CRC Errors: {self.adsl_tx_crc_errors}\n'
        result += f' ADSL RX CRC Errors: {self.adsl_rx_crc_errors}\n'
        result += f' xDSL Type: {self.dsl_type} (6 = VDSL, 1 = ADSL)\n'
        result += f' Timestamp: {self.timestamp}\n'
        result += f' VDSL SNR Upload: {self.vdsl_snr_upload}\n'
        result += f' VDSL SNR Download: {self.vdsl_snr_download}\n'
        result += f' ADSL Loop Attenuation: {self.adsl_loop_att}\n'
        result += f' ADSL SNR Margin: {self.adsl_snr_margin}\n'
        result += f' Modem Firmware Version: {bytes(self.modem_firmware_version)}\n'
        result += f' VDSL Profile: {bytes(self.vdsl_profile)}\n'
        result += f' Padding: {bytes(self.padding)}\n'
        result += f' State: {bytes(self.state)}\n'
        result += f' Padding2: {bytes(self.padding2)}\n'

        return result
