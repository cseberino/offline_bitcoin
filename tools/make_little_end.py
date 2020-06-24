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

import binascii

def hex_str(x, n_bytes):
        """
        Converts a number to little endian.
        """

        little_end = hex(x)[2:]
        little_end = (2 * n_bytes - len(little_end)) * "0" + little_end
        little_end = binascii.unhexlify(little_end)[::-1]
        little_end = binascii.hexlify(little_end).decode()

        return little_end
