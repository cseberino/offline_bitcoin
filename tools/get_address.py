# Copyright 2020 Christian Seberino
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import crypto.hash160
import crypto.hash256
import binascii
import re

ADD_VER      = "00"
ADD_BASE     = 58
ADD_CHARS    = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ADD_CHK_SIZE = 4
PUB_KEY_PRE  = "04"
ZERO         = "00"
ZEROES_RE    = "({})*".format(ZERO)
HEXADECIMAL  = 16

def base_58_enc(number):
        """
        Returns the base 58 encoding of a number.
        """

        encoding = []
        n_zeroes = len(re.match(ZEROES_RE, number).group(0)) // len(ZERO)
        number   = int(number, HEXADECIMAL)
        while number:
                encoding.append(number % ADD_BASE)
                number = (number - encoding[-1]) // ADD_BASE

        return n_zeroes * "1" + "".join([ADD_CHARS[e] for e in encoding])[::-1]

def get_check(hash_):
        """
        Gets the check of a HASH160 hash.
        """

        extended = binascii.unhexlify(ADD_VER + hash_)

        return crypto.hash256.hex_str(extended)[:2 * ADD_CHK_SIZE]

def hex_str(public_key):
        """
        Calculates the addresses of public keys.
        """

        public_key = "".join("{:064x}".format(e) for e in public_key)
        public_key = PUB_KEY_PRE + public_key
        hash_      = crypto.hash160.hex_str(binascii.unhexlify(public_key))

        return base_58_enc(ADD_VER + hash_ + get_check(hash_))
