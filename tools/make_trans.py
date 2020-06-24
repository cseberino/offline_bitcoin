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
import crypto.ecdsa
import tools.make_little_end
import binascii

TRANS_VER      = "01000000"
TRANS_H_VER    = "01"
TRANS_LOCK     = "00000000"
TRANS_SEQ      = "ffffffff"
TRANS_TEMP     = TRANS_VER + 4 * "{}" + TRANS_LOCK
DER_SEQ        = "30"
DER_INT        = "02"
OP_DUP         = "76"
OP_HASH160     = "a9"
OP_EQUALVERIFY = "88"
OP_CHECKSIG    = "ac"
PUB_KEY_PRE    = "04"
PUB_KEY_SIZE   = 64
SAT_PER_COIN   = 10 ** 8
HEXADECIMAL    = 16

def format_pub_key(public_key):
        """
        Formats public keys.
        """

        formatted = PUB_KEY_PRE
        for e in public_key:
                e          = hex(e)[2:]
                formatted += (PUB_KEY_SIZE - len(e)) * "0" + e

        return formatted

def make_sig_data(public_key):
        """
        Makes signature data.
        """

        hash_ = format_pub_key(public_key)
        hash_ = crypto.hash160.hex_str(binascii.unhexlify(hash_))
        data  = make_output_script(hash_)
        data  = (tools.make_little_end.hex_str(len(data) // 2, 1), data)

        return data

def make_sig_der(sig):
        """
        Makes a DER encoding of a signature.
        """

        r    = hex(sig[0])[2:]
        r    = (PUB_KEY_SIZE - len(r)) * "0" + r
        if int(r[0], HEXADECIMAL) >= 8:
                r = "00" + r
        s    = hex(sig[1])[2:]
        s    = (PUB_KEY_SIZE - len(s)) * "0" + s
        if int(s[0], HEXADECIMAL) >= 8:
                s = "00" + s
        der  = DER_INT + tools.make_little_end.hex_str(len(r)   // 2, 1) +   r
        der += DER_INT + tools.make_little_end.hex_str(len(s)   // 2, 1) +   s
        der  = DER_SEQ + tools.make_little_end.hex_str(len(der) // 2, 1) + der

        return der

def make_input_data(trans, private_key, public_key):
        """
        Makes input data.
        """

        trans += tools.make_little_end.hex_str(int(TRANS_H_VER, HEXADECIMAL), 4)
        sig    = crypto.ecdsa.make_sig(binascii.unhexlify(trans),
                                       int(private_key, HEXADECIMAL))
        sig    = make_sig_der(sig)
        pub    = format_pub_key(public_key)
        len_   = tools.make_little_end.hex_str((len(sig) // 2) + 1, 1)
        data   = len_ + sig + TRANS_H_VER
        data  += tools.make_little_end.hex_str(len(pub) // 2, 1) + pub
        data   = (tools.make_little_end.hex_str(len(data) // 2, 1), data)

        return data

def make_input_temp(hash_, index):
        """
        Makes an input template.
        """

        temp  = tools.make_little_end.hex_str(int(hash_,     HEXADECIMAL), 32)
        temp += tools.make_little_end.hex_str(index,                        4)
        temp += "{}"
        temp += "{}"
        temp += tools.make_little_end.hex_str(int(TRANS_SEQ, HEXADECIMAL),  4)

        return temp

def make_input(e, src_info, dest_info, sig):
        """
        Makes an input component.
        """

        if sig:
                data  = make_sig_data(e[3]) if sig == e else ("00", "")
        else:
                trans = hex_str(src_info, dest_info, e)
                data  = make_input_data(trans, e[2], e[3])
        input_ = make_input_temp(e[0], e[1])
        input_ = input_.format(data[0], data[1])

        return input_

def make_output_script(hash_):
        """
        Makes an output script to check if data allows the spending of coins.
        """

        script  = OP_DUP + OP_HASH160
        script += tools.make_little_end.hex_str(len(hash_) // 2, 1)
        script += hash_ + OP_EQUALVERIFY + OP_CHECKSIG

        return script

def make_output(e):
        """
        Makes an output component.
        """

        output  = tools.make_little_end.hex_str(int(e[1] * SAT_PER_COIN), 8)
        script  = make_output_script(e[0])
        output += tools.make_little_end.hex_str(len(script) // 2, 1)
        output += script

        return output

def hex_str(src_info, dest_info, sig = False):
        """
        Makes a transaction.

        src_info is a list of tuples with each tuple containing source
        information.  Each tuple contains the following four elements in order:

                source transaction HASH256 hash                  (hex string)
                source transaction output  index (first is zero) (integer)
                source address     private key                   (hex string)
                source address     public  key                   (two integers)

        dest_info is a list of tuples with each tuple containing destination
        information.  Each tuple contains the following two elements in order:

                destination address public key HASH160 hash      (hex string)
                number of coins to spend                         (float)
        """

        n_inputs  = tools.make_little_end.hex_str(len(src_info), 1)
        inputs    = ""
        for e in src_info:
                inputs += make_input(e, src_info, dest_info, sig)
        n_outputs = tools.make_little_end.hex_str(len(dest_info), 1)
        outputs   = ""
        for e in dest_info:
                outputs += make_output(e)

        return TRANS_TEMP.format(n_inputs, inputs, n_outputs, outputs)
