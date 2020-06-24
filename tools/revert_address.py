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

ADD_BASE     = 58
ADD_CHARS    = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ADD_CHK_SIZE = 4
ADD_2_SIZE   = 20

def hex_str(address):
        """
        Reverts an address to the HASH160 hash of the corresponding public key.
        """

        while address.startswith("1"):
                address = address[1:]
        number = 0
        power  = ADD_BASE ** 0
        for e in address[::-1]:
                number += ADD_CHARS.index(e) * power
                power  *= ADD_BASE
        hash_  = hex(number)[2:][:-2 * ADD_CHK_SIZE]
        hash_  = (2 * ADD_2_SIZE - len(hash_)) * "0" + hash_

        return hash_
