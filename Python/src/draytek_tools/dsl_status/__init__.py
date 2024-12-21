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
A module for interacting with DrayTek® Vigor's DSL Status broadcast packets.

This module provides functionality to interact with the DrayTek® Vigor DSL Status broadcast packets.
"""

# Allow the user to use cryptography and Message by just importing draytek_tools.dsl_status.
from . import cryptography
from .message import Message

# Declare what should be offered in the public API when a wildcard import statement is used.
__all__ = ['cryptography', 'Message']
