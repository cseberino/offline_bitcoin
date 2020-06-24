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

BINARY      =   2
HEXADECIMAL =  16
BYTE_SIZE   =   8
INT_SIZE    =   4
BLOCK_SIZE  =  64
N_BITS_SIZE =   8
H           = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
               0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
K           = [None,       0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
               0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
               0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
               0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
               0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
               0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
               0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
               0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
               0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
               0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
               0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
               0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
               0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def mod_add(x, y):
        """
        modular add
        """

        return (x + y) % (2 ** (INT_SIZE * BYTE_SIZE))

def right_shift(x, n):
        """
        right shift
        """

        return x >> n

def right_circ_shift(x, n):
        """
        right circular shift
        """

        return mod_add(x >> n, x << (INT_SIZE * BYTE_SIZE - n))

def get_n_zeroes(bytes_):
        """
        Calculates the number of zeroes to append.
        """

        return (BLOCK_SIZE - len(bytes_) - N_BITS_SIZE) % BLOCK_SIZE

def ch(x, y, z):
        """
        SHA-256 helper function
        """

        return (x & y) ^ (~x & z)

def maj(x, y, z):
        """
        SHA-256 helper function
        """

        return (x & y) ^ (x & z) ^ (y & z)

def low_sigma_0(x):
        """
        SHA-256 helper function
        """

        return right_circ_shift(x,  7) ^ right_circ_shift(x, 18) ^             \
                                                       right_shift(x, 3)

def low_sigma_1(x):
        """
        SHA-256 helper function
        """

        return right_circ_shift(x, 17) ^ right_circ_shift(x, 19) ^             \
                                                       right_shift(x, 10)

def cap_sigma_0(x):
        """
        SHA-256 helper function
        """

        return right_circ_shift(x,  2) ^ right_circ_shift(x, 13) ^             \
                                                       right_circ_shift(x, 22)

def cap_sigma_1(x):
        """
        SHA-256 helper function
        """

        return right_circ_shift(x,  6) ^ right_circ_shift(x, 11) ^             \
                                                       right_circ_shift(x, 25)

def hex_str(bytes_):
        """
        SHA-256 function
        """

        n_bits  = hex(len(bytes_) * BYTE_SIZE)[2:]
        n_bits  = (2 * N_BITS_SIZE - len(n_bits)) * "0" + n_bits
        n_bits  = binascii.unhexlify(n_bits)
        bytes_ += b"\x80" + get_n_zeroes(bytes_ + b"\x80") * b"\x00" + n_bits
        H_      = H[:]
        for i in range(0, len(bytes_), BLOCK_SIZE):
                ints = [None]
                for j in range(0, BLOCK_SIZE, INT_SIZE):
                        int_ = bytes_[i + j:i + j + INT_SIZE]
                        int_ = int(binascii.hexlify(int_), HEXADECIMAL)
                        ints.append(int_)
                for j in range(17, 65):
                        int_ = mod_add(low_sigma_0(ints[j - 15]) + ints[j - 16],
                                       low_sigma_1(ints[j - 2])  + ints[j - 7])
                        ints.append(int_)
                a = H_[0]
                b = H_[1]
                c = H_[2]
                d = H_[3]
                e = H_[4]
                f = H_[5]
                g = H_[6]
                h = H_[7]
                for j in range(1, 65):
                        t1 = mod_add(h + cap_sigma_1(e),
                                     ch(e, f, g) + K[j] + ints[j])
                        t2 = mod_add(cap_sigma_0(a), maj(a, b, c))
                        h  = g
                        g  = f
                        f  = e
                        e  = mod_add(d, t1)
                        d  = c
                        c  = b
                        b  = a
                        a  = mod_add(t1, t2)
                H_[0] = mod_add(H_[0], a)
                H_[1] = mod_add(H_[1], b)
                H_[2] = mod_add(H_[2], c)
                H_[3] = mod_add(H_[3], d)
                H_[4] = mod_add(H_[4], e)
                H_[5] = mod_add(H_[5], f)
                H_[6] = mod_add(H_[6], g)
                H_[7] = mod_add(H_[7], h)

        return "".join(["{:08x}".format(e) for e in H_])
