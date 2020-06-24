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

import tools.make_little_end
import binascii

BINARY      =  2
HEXADECIMAL = 16
BYTE_SIZE   =  8
INT_SIZE    =  4
BLOCK_SIZE  = 64
N_BITS_SIZE =  8
H           = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
K           = 16 * [0x00000000] + 16 * [0x5a827999] + 16 * [0x6ed9eba1] +      \
                                         16 * [0x8f1bbcdc] + 16 * [0xa953fd4e]
KP          = 16 * [0x50a28be6] + 16 * [0x5c4dd124] + 16 * [0x6d703ef3] +      \
                                         16 * [0x7a6d76e9] + 16 * [0x00000000]
R           = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13,
               1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15,
               8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13,
               3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11,
               6, 15, 13]
RP          = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12 , 6, 11, 3,
               7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2 , 15, 5, 1, 3, 7, 14,
               6, 9, 11, 8, 12, 2, 10, 0, 4, 13 , 8, 6, 4, 1, 3, 11, 15, 0, 5,
               12, 2, 13, 9, 7, 10, 14 , 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13,
               14, 0, 3, 9, 11]
S           = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8,
               13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14,
               9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9,
               8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12,
               13, 14, 11, 8, 5, 6]
SP          = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13,
               15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8,
               6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6,
               14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13,
               6, 5, 15, 13, 11, 11]

def mod_add(x, y):
        """
        modular add
        """

        return (x + y) % (2 ** (INT_SIZE * BYTE_SIZE))

def left_circ_shift(x, n):
        """
        left circular shift
        """

        return mod_add(x << n, x >> (INT_SIZE * BYTE_SIZE - n))

def get_n_zeroes(bytes_):
        """
        Calculates the number of zeroes to append.
        """

        n_zeroes = len(bytes_) % BLOCK_SIZE
        n_zeroes = (BLOCK_SIZE - N_BITS_SIZE - n_zeroes) % BLOCK_SIZE

        return n_zeroes

def f(i, x, y, z):
        """
        RIPEMD-160 helper function
        """

        if    0 <= i <= 15:
                f_ = x ^ y ^ z
        elif 16 <= i <= 31:
                f_ = (x & y) | (~x & z)
        elif 32 <= i <= 47:
                f_ = (x | ~y) ^ z
        elif 48 <= i <= 63:
                f_ = (x & z) | (y & ~z)
        elif 64 <= i <= 79:
                f_ = x ^ (y | ~z)

        return f_

def hex_str(bytes_):
        """
        RIPEMD-160 function
        """

        n_bits  = tools.make_little_end.hex_str(len(bytes_) * BYTE_SIZE,
                                                N_BITS_SIZE)
        n_bits  = binascii.unhexlify(n_bits)
        bytes_ += b"\x80" + get_n_zeroes(bytes_ + b"\x80") * b"\x00" + n_bits
        ints_   = []
        for i in range(0, len(bytes_), BLOCK_SIZE):
                block = []
                for j in range(0, BLOCK_SIZE, INT_SIZE):
                        int_ = bytes_[i + j:i + j + INT_SIZE][::-1]
                        int_ = int(binascii.hexlify(int_), HEXADECIMAL)
                        block.append(int_)
                ints_.append(block)
        H_ = H[:]
        for ints in ints_:
                a  = H_[0]
                b  = H_[1]
                c  = H_[2]
                d  = H_[3]
                e  = H_[4]
                ap = H_[0]
                bp = H_[1]
                cp = H_[2]
                dp = H_[3]
                ep = H_[4]
                for i in range(80):
                        t  = mod_add(a, f(i, b, c, d))
                        t  = mod_add(t, ints[R[i]])
                        t  = mod_add(t, K[i])
                        t  = mod_add(left_circ_shift(t, S[i]), e)
                        a  = e
                        e  = d
                        d  = left_circ_shift(c, 10)
                        c  = b
                        b  = t
                        t  = mod_add(ap, f(79 - i, bp, cp, dp))
                        t  = mod_add(t, ints[RP[i]])
                        t  = mod_add(t, KP[i])
                        t  = mod_add(left_circ_shift(t, SP[i]), ep)
                        ap = ep
                        ep = dp
                        dp = left_circ_shift(cp, 10)
                        cp = bp
                        bp = t
                t     = mod_add(mod_add(H_[1], c), dp)
                H_[1] = mod_add(mod_add(H_[2], d), ep)
                H_[2] = mod_add(mod_add(H_[3], e), ap)
                H_[3] = mod_add(mod_add(H_[4], a), bp)
                H_[4] = mod_add(mod_add(H_[0], b), cp)
                H_[0] = t

        return "".join([tools.make_little_end.hex_str(e, INT_SIZE) for e in H_])
