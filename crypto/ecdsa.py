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

import crypto.hash256
import random

A           = 0
N           = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P           = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
GX          = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
GY          = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
HEXADECIMAL = 16

def mod_inv(number, modulus):
        """
        Finds the modular inverse of a number with respect to a prime modulus.
        """

        inverse = 1
        power   = number
        for e in bin(modulus - 2)[2:][::-1]:
                if int(e):
                        inverse = (inverse * power) % modulus
                power = (power ** 2) % modulus

        return inverse

def add_vec(vector_1, vector_2):
        """
        Adds two vectors.
        """

        if   vector_1 == "identity":
                sum_ = vector_2
        elif vector_2 == "identity":
                sum_ = vector_1
        else:
                if vector_1 == vector_2:
                        numer   = 3 * vector_1[0] ** 2 + A
                        lambda_ = (numer * mod_inv(2 * vector_1[1], P)) % P
                else:
                        numer   = vector_2[1] - vector_1[1]
                        denom   = vector_2[0] - vector_1[0]
                        lambda_ = (numer * mod_inv(denom, P)) % P
                x    = (lambda_ ** 2 - vector_1[0] - vector_2[0])  % P
                y    = (lambda_ * (vector_1[0] - x) - vector_1[1]) % P
                sum_ = (x, y)

        return sum_

def mult_vec(number, vector):
        """
        Multiplies a vector by a number.
        """

        product = "identity"
        power   = vector[:]
        for e in bin(number)[2:][::-1]:
                if int(e):
                        product = add_vec(power, product)
                power = add_vec(power, power)

        return product

def make_private_key():
        """
        Creates a private key.
        """

        return random.randint(1, N - 1)

def calc_public_key(private_key):
        """
        Calculates the public key corresponding to a private key.
        """

        return mult_vec(private_key, (GX, GY))

def make_sig(bytes_, private_key):
        """
        Signs bytes.
        """

        r = s = 0
        while r == 0 or s == 0:
                k = random.randint(1, N - 1)
                x = mult_vec(k, (GX, GY))[0]
                r = x % N
                z = int(crypto.hash256.hex_str(bytes_), HEXADECIMAL)
                s = ((z + r * private_key) *  mod_inv(k, N)) % N
                if s > N / 2:
                        s = N - s

        return (r, s)

def verify_sig(sig, bytes_, public_key):
        """
        Verifies signatures.
        """

        z  = int(crypto.hash256.hex_str(bytes_), HEXADECIMAL)
        w  = mod_inv(sig[1], N)
        u1 = (z      * w) % N
        u2 = (sig[0] * w) % N
        x  = add_vec(mult_vec(u1, (GX, GY)), mult_vec(u2, public_key))[0]

        return sig[0] == (x % N)
