#!/usr/bin/env python3
#
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

import sys
sys.path.append("..")

import crypto.ripemd160
import crypto.sha256
import crypto.hash160
import crypto.hash256
import crypto.ecdsa
import tools.make_trans
import tools.get_address
import tools.revert_address
import binascii
import hashlib
import unittest
import random
import tempfile
import importlib
import subprocess
import os

DER_SEQ      = "30"
DER_INT      = "02"
HASH_VER     = "01000000"
PUB_KEY_PRE  = "04"
PUB_KEY_SIZE = 64
HEXADECIMAL  = 16

class Tester(unittest.TestCase):
        def random_bytes(self):
                bytes_ = ""
                length = random.randint(1, 1000)
                for i in range(length):
                        bytes_ += chr(random.randint(0, 256))

                return bytes_.encode()

        def test_sha256(self):
                answer = \
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                output = crypto.sha256.hex_str(b"abc")
                self.assertEqual(output, answer)

                bytes_ = b"2r3fkf23aze"
                answer = hashlib.sha256(bytes_).hexdigest()
                output = crypto.sha256.hex_str(bytes_)
                self.assertEqual(output, answer)

                bytes_ = \
                     b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                answer = hashlib.sha256(bytes_).hexdigest()
                output = crypto.sha256.hex_str(bytes_)
                self.assertEqual(output, answer)

                for i in range(100):
                        bytes_ = self.random_bytes()
                        answer = hashlib.sha256(bytes_).hexdigest()
                        output = crypto.sha256.hex_str(bytes_)
                        self.assertEqual(output, answer)

        def test_ripemd160(self):

                bytes_ = b"abc"
                answer = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
                output = crypto.ripemd160.hex_str(bytes_)
                self.assertEqual(output, answer)

                bytes_ = b"message digest"
                answer = "5d0689ef49d2fae572b881b123a85ffa21595f36"
                output = crypto.ripemd160.hex_str(bytes_)
                self.assertEqual(output, answer)

                for i in range(100):
                        bytes_ = self.random_bytes()
                        h      = hashlib.new("ripemd160")
                        h.update(bytes_)
                        answer = h.hexdigest()
                        output = crypto.ripemd160.hex_str(bytes_)
                        self.assertEqual(output, answer)

        def test_hash256(self):
                for i in range(100):
                        bytes_ = self.random_bytes()
                        answer = hashlib.sha256(bytes_).digest()
                        answer = hashlib.sha256(answer).hexdigest()
                        output = crypto.hash256.hex_str(bytes_)
                        self.assertEqual(output, answer)

        def test_hash160(self):
                for i in range(100):
                        bytes_ = self.random_bytes()
                        answer = hashlib.sha256(bytes_).digest()
                        h      = hashlib.new("ripemd160")
                        h.update(answer)
                        answer = h.hexdigest()
                        output = crypto.hash160.hex_str(bytes_)
                        self.assertEqual(output, answer)

        def make_key_pair(self):
                pem = tempfile.mkstemp(dir = ".", suffix = ".pem")[1]
                subprocess.call(["openssl", "ecparam", "-genkey", "-name",
                                                      "secp256k1", "-out", pem])
                key_pair = subprocess.check_output(["openssl", "ec", "-in", pem,
                                                      "-text", "-noout"],
                                                   stderr = subprocess.STDOUT)
                key_pair = key_pair.decode()
                os.remove(pem)
                private_key = key_pair[key_pair.find("priv:") + len("priv:"):
                                       key_pair.find("pub:")]
                private_key = "".join(private_key.split()).replace(":", "")
                private_key = int(private_key, HEXADECIMAL)
                public_key  = key_pair[key_pair.find("pub:")  + len("pub:"):
                                       key_pair.find("ASN1")]
                public_key  = "".join(public_key.split()).replace(":", "")[2:]
                public_key  = (int(public_key[:PUB_KEY_SIZE], HEXADECIMAL),
                               int(public_key[PUB_KEY_SIZE:], HEXADECIMAL))

                return private_key, public_key

        def test_ecdsa_1(self):
                crypto.ecdsa.P  = 67
                crypto.ecdsa.GX = 2
                crypto.ecdsa.GY = 22
                crypto.ecdsa.N  = 79
                answer          = (52, 7)
                output          = crypto.ecdsa.calc_public_key(2)
                self.assertEqual(output, answer)

                importlib.reload(crypto.ecdsa)
                for i in range(10):
                        priv, pub = self.make_key_pair()
                        answer    = pub
                        output    = crypto.ecdsa.calc_public_key(priv)
                        self.assertEqual(output, answer)

        def test_ecdsa_2(self):
                for i in range(5):
                        priv, pub = self.make_key_pair()
                        for j in range(100):
                                bytes_ = ""
                                length = random.randint(1, 1000)
                                for k in range(length):
                                        bytes_ += chr(random.randint(0, 256))
                                bytes_ = bytes_.encode()
                        sig    = crypto.ecdsa.make_sig(bytes_, priv)
                        answer = True
                        output = crypto.ecdsa.verify_sig(sig, bytes_, pub)
                        self.assertEqual(output, answer)

                for i in range(5):
                        priv, pub = self.make_key_pair()
                        for j in range(100):
                                bytes_ = ""
                                length = random.randint(1, 1000)
                                for k in range(length):
                                        bytes_ += chr(random.randint(0, 256))
                                bytes_ = bytes_.encode()
                        sig    = crypto.ecdsa.make_sig(bytes_, priv)
                        sig    = (sig[0] + 1, sig[1])
                        answer = False
                        output = crypto.ecdsa.verify_sig(sig, bytes_, pub)
                        self.assertEqual(output, answer)

                for i in range(5):
                        priv, pub = self.make_key_pair()
                        for j in range(100):
                                bytes_ = ""
                                length = random.randint(1, 1000)
                                for k in range(length):
                                        bytes_ += chr(random.randint(0, 256))
                                bytes_ = bytes_.encode()
                        sig    = crypto.ecdsa.make_sig(bytes_, priv)
                        sig    = (sig[0], sig[1] + 1)
                        answer = False
                        output = crypto.ecdsa.verify_sig(sig, bytes_, pub)
                        self.assertEqual(output, answer)

        def test_get_address(self):
                public_key = \
            (0x50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352,
             0x2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6)
                answer     = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
                output     = tools.get_address.hex_str(public_key)
                self.assertEqual(output, answer)

                public_key = \
            (0x2c6b7e6da7633c8f226891cc7fa8e5ec84f8eacc792a46786efc869a408d2953,
             0x9a5e6f8de3f71c0014e8ea71691c7b41f45c083a074fef7ab5c321753ba2b3fe)
                answer     = "13mtgVARiB1HiRyCHnKTi6rEwyje5TYKBW"
                output     = tools.get_address.hex_str(public_key)
                self.assertEqual(output, answer)

                public_key = \
            (0x4da6a80fc83a71c6c43ac819985983d15797610b348b6123dcc093866baed2d2,
             0x6d3156ebfe5b05e997e3337a11958abee5060a67e12f1dd7cf785cac1c090ee2)
                answer     = "1Et6amCcirkyRqfTE69Fdk2xUkaCnp7uY1"
                output     = tools.get_address.hex_str(public_key)
                self.assertEqual(output, answer)

                public_key = \
            (0x91acdd91710e4f4205194efc6d1d6758c27c058e35adcbf1b650d15e8ee6456a,
             0xb27aa62b849ab55221f2f3500d8a3a4b80192336ea7102365d76c7c26f89c5ba)
                answer     = "1J2dgP3pDwGC94bqAuwsDcAbHJneHQWaRF"
                output     = tools.get_address.hex_str(public_key)
                self.assertEqual(output, answer)

        def test_revert_address(self):
                address = "1KTS9utxJouo3ArXYaEuiZZkj9ZVaituE1"
                output  = tools.revert_address.hex_str(address)
                answer  = "ca72138a41c0b544377e683f08e473878fd3f597"
                self.assertEqual(output, answer)

                address = "1DiFjHivi4w2CtHmoWm2GhRXWKLkA297mT"
                output  = tools.revert_address.hex_str(address)
                answer  = "8b6edbeca6796237bca39f4653f89d23eb8fd556"
                self.assertEqual(output, answer)

                for i in range(10):
                        priv   = crypto.ecdsa.make_private_key()
                        pub    = crypto.ecdsa.calc_public_key(priv)
                        add    = tools.get_address.hex_str(pub)
                        output = tools.revert_address.hex_str(add)

                        pub    = "".join("{:064x}".format(e) for e in pub)
                        pub    = PUB_KEY_PRE + pub
                        answer = crypto.hash160.hex_str(binascii.unhexlify(pub))

                        self.assertEqual(output, answer)

        def test_make_trans(self):

                # Create a transaction.
                src_trans_hash = \
             "eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2"
                src_trans_ind  = 1
                src_trans_priv = \
             "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
                src_trans_pub  = int(src_trans_priv, HEXADECIMAL)
                src_trans_pub  = crypto.ecdsa.calc_public_key(src_trans_pub)
                src_i          = [(src_trans_hash,
                                   src_trans_ind,
                                   src_trans_priv,
                                   src_trans_pub)]
                dest_hash      = "097072524438d003d23a2f23edb65aae1bb3e469"
                n_coins        = 0.999
                dst_i          = [(dest_hash, n_coins)]
                out_p          = tools.make_trans.hex_str(src_i, dst_i)

                # Define the correct transaction.
                ans_p          = \
"0100000001f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec" + \
"010000008c493046022100801d997007b873bfdd866ddce40d9b83cd3deaad9d56aef159b8" + \
"51e088e4683b0221009e91b71dafd0149c32b5402f75763f6d012560b39a4289bef509c745" + \
"5ab8183601410450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b" + \
"23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6ffffff" + \
"ff01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac00" + \
"000000"

                # Checks everything from the hash version on.
                n_bytes        = 4 + 25 + 1 + 8 + 1 + 4 + 32 + 32 + 1 + 1 + 1
                output         = out_p[-2 * n_bytes:]
                answer         = ans_p[-2 * n_bytes:]
                self.assertEqual(output, answer)

                # Checks everything up to and including the source index.
                n_bytes        = 4 + 1 + 32 + 4
                output         = out_p[:2 * n_bytes]
                answer         = ans_p[:2 * n_bytes]
                self.assertEqual(output, answer)

                # Gets the input.
                inp_data_out   = out_p[2 * n_bytes:out_p.find("ffffffff")]
                inp_data_ans   = ans_p[2 * n_bytes:ans_p.find("ffffffff")]

                # Checks the length byte of the input.
                output         = hex((len(inp_data_out) // 2) - 1)[2:]
                answer         = hex((len(inp_data_ans) // 2) - 1)[2:]
                self.assertEqual(output, inp_data_out[:2])
                self.assertEqual(answer, inp_data_ans[:2])

                # Checks the hash version byte, pub key length byte and pub key.
                output         = inp_data_out[-2 * (32 + 32 + 1 + 1 + 1):]
                answer         = inp_data_ans[-2 * (32 + 32 + 1 + 1 + 1):]
                self.assertEqual(output, answer)

                # Gets the DER signature of the input.
                der_out        = inp_data_out[2 * 2:-2 * (32 + 32 + 1 + 1 + 1)]
                der_ans        = inp_data_ans[2 * 2:-2 * (32 + 32 + 1 + 1 + 1)]

                # Checks the length (DER signature and hash version) byte.
                output         = hex((len(der_out) // 2) + 1)[2:]
                answer         = hex((len(der_ans) // 2) + 1)[2:]
                self.assertEqual(output, inp_data_out[2:4])
                self.assertEqual(answer, inp_data_ans[2:4])

                # Checks the DER_SEQ byte.
                output         = der_out[:2]
                answer         = der_ans[:2]
                self.assertEqual(output, DER_SEQ)
                self.assertEqual(answer, DER_SEQ)

                # Checks the DER sequence length byte.
                output         = hex(len(der_out[4:]) // 2)[2:]
                answer         = hex(len(der_ans[4:]) // 2)[2:]
                self.assertEqual(output, der_out[2:4])
                self.assertEqual(answer, der_ans[2:4])

                # Checks the first DER_INT byte.
                output         = der_out[4:6]
                answer         = der_ans[4:6]
                self.assertEqual(output, DER_INT)
                self.assertEqual(answer, DER_INT)

                # Checks the validity of the signature.
                bytes_for_sig  = tools.make_trans.hex_str(src_i,
                                                          dst_i,
                                                          src_i[0])
                bytes_for_sig += HASH_VER
                bytes_for_sig  = binascii.unhexlify(bytes_for_sig)

                len_r_out      = int(der_out[6:8], HEXADECIMAL)
                r_out          = int(der_out[8:8 + 2 * len_r_out], HEXADECIMAL)
                der_int_out    = der_out[8 + 2 * len_r_out:
                                         8 + 2 * len_r_out + 2]
                len_s_out      = der_out[8 + 2 * len_r_out + 2:
                                         8 + 2 * len_r_out + 4]
                len_s_out      = int(len_s_out, HEXADECIMAL)
                s_out          = der_out[8 + 2 * len_r_out + 4:
                                         8 + 2 * len_r_out + 4 + 2 * len_s_out]
                s_out          = int(s_out, HEXADECIMAL)
                output         = crypto.ecdsa.verify_sig((r_out, s_out),
                                                         bytes_for_sig,
                                                         src_trans_pub)
                len_r_ans      = int(der_ans[6:8], HEXADECIMAL)
                r_ans          = int(der_ans[8:8 + 2 * len_r_ans], HEXADECIMAL)
                der_int_ans    = der_ans[8 + 2 * len_r_ans:
                                         8 + 2 * len_r_ans + 2]
                len_s_ans      = der_ans[8 + 2 * len_r_ans + 2:
                                         8 + 2 * len_r_ans + 4]
                len_s_ans      = int(len_s_ans, HEXADECIMAL)
                s_ans          = der_ans[8 + 2 * len_r_ans + 4:
                                         8 + 2 * len_r_ans + 4 + 2 * len_s_ans]
                s_ans          = int(s_ans, HEXADECIMAL)
                answer         = crypto.ecdsa.verify_sig((r_ans, s_ans),
                                                         bytes_for_sig,
                                                         src_trans_pub)
                self.assertEqual(output, True)
                self.assertEqual(answer, True)

                # Checks the r and s length bytes.
                len_seq_out    = len(der_out[4:]) // 2
                len_r_out      = int(der_out[6:8], HEXADECIMAL)
                len_s_out      = der_out[8 + 2 * len_r_out + 2:
                                         8 + 2 * len_r_out + 4]
                len_s_out      = int(len_s_out, HEXADECIMAL)
                self.assertEqual(len_seq_out, len_r_out + len_s_out + 4)
                len_seq_ans    = len(der_ans[4:]) // 2
                len_r_ans      = int(der_ans[6:8], HEXADECIMAL)
                len_s_ans      = der_ans[8 + 2 * len_r_ans + 2:
                                         8 + 2 * len_r_ans + 4]
                len_s_ans      = int(len_s_ans, HEXADECIMAL)
                self.assertEqual(len_seq_ans, len_r_ans + len_s_ans + 4)

                # Checks the second DER_INT byte.
                output         = der_int_out
                answer         = der_int_ans
                self.assertEqual(output, DER_INT)
                self.assertEqual(answer, DER_INT)

                # Create a transaction.
                src_trans_hash = \
             "fc60ca319289fc5599f109d545a09c92b09ca8b0af7bcfb7b3a6b4fac2616358"
                src_trans_ind  = 0
                src_trans_priv = "430ea2480a9f95810dcf3fcc43048b41c36343a3"
                src_trans_pub  = int(src_trans_priv, HEXADECIMAL)
                src_trans_pub  = crypto.ecdsa.calc_public_key(src_trans_pub)
                src_i          = [(src_trans_hash,
                                   src_trans_ind,
                                   src_trans_priv,
                                   src_trans_pub)]
                dest_hash      = "8b6edbeca6796237bca39f4653f89d23eb8fd556"
                n_coins        = 0.00005
                dst_i          = [(dest_hash, n_coins)]
                out_p          = tools.make_trans.hex_str(src_i, dst_i)

                # Define the correct transaction.
                ans_p          = \
"0100000001586361c2fab4a6b3b7cf7bafb0a89cb0929ca045d509f19955fc899231ca60fc" + \
"000000008b483045022100d9e7ac2548d315bd8231ad7ee2ba53aaad12f13a5e4ac6ee5b9b" + \
"298b7f73954f02203dfe25d5106beac8355636030b33150a0b61fc0564991d9adb8125595e" + \
"d6896d014104235734ba8a50b929529786d06a0faaab9792f7587ee3dc45d12e7b0cdc0332" + \
"81baec1e02d38797d4857a79225f70c59914752c5998cfcc370c48f986cdb47fb8ffffffff" + \
"0188130000000000001976a9148b6edbeca6796237bca39f4653f89d23eb8fd55688ac0000" + \
"0000"

                # Checks everything from the hash version on.
                n_bytes        = 4 + 25 + 1 + 8 + 1 + 4 + 32 + 32 + 1 + 1 + 1
                output         = out_p[-2 * n_bytes:]
                answer         = ans_p[-2 * n_bytes:]
                self.assertEqual(output, answer)

                # Checks everything up to and including the source index.
                n_bytes        = 4 + 1 + 32 + 4
                output         = out_p[:2 * n_bytes]
                answer         = ans_p[:2 * n_bytes]
                self.assertEqual(output, answer)

                # Gets the input.
                inp_data_out   = out_p[2 * n_bytes:out_p.find("ffffffff")]
                inp_data_ans   = ans_p[2 * n_bytes:ans_p.find("ffffffff")]

                # Checks the length byte of the input.
                output         = hex((len(inp_data_out) // 2) - 1)[2:]
                answer         = hex((len(inp_data_ans) // 2) - 1)[2:]
                self.assertEqual(output, inp_data_out[:2])
                self.assertEqual(answer, inp_data_ans[:2])

                # Checks the hash version byte, pub key length byte and pub key.
                output         = inp_data_out[-2 * (32 + 32 + 1 + 1 + 1):]
                answer         = inp_data_ans[-2 * (32 + 32 + 1 + 1 + 1):]
                self.assertEqual(output, answer)

                # Gets the DER signature of the input.
                der_out        = inp_data_out[2 * 2:-2 * (32 + 32 + 1 + 1 + 1)]
                der_ans        = inp_data_ans[2 * 2:-2 * (32 + 32 + 1 + 1 + 1)]

                # Checks the length (DER signature and hash version) byte.
                output         = hex((len(der_out) // 2) + 1)[2:]
                answer         = hex((len(der_ans) // 2) + 1)[2:]
                self.assertEqual(output, inp_data_out[2:4])
                self.assertEqual(answer, inp_data_ans[2:4])

                # Checks the DER_SEQ byte.
                output         = der_out[:2]
                answer         = der_ans[:2]
                self.assertEqual(output, DER_SEQ)
                self.assertEqual(answer, DER_SEQ)

                # Checks the DER sequence length byte.
                output         = hex(len(der_out[4:]) // 2)[2:]
                answer         = hex(len(der_ans[4:]) // 2)[2:]
                self.assertEqual(output, der_out[2:4])
                self.assertEqual(answer, der_ans[2:4])

                # Checks the first DER_INT byte.
                output         = der_out[4:6]
                answer         = der_ans[4:6]
                self.assertEqual(output, DER_INT)
                self.assertEqual(answer, DER_INT)

                # Checks the validity of the signature.
                bytes_for_sig  = tools.make_trans.hex_str(src_i,
                                                          dst_i,
                                                          src_i[0])
                bytes_for_sig += HASH_VER
                bytes_for_sig  = binascii.unhexlify(bytes_for_sig)

                len_r_out      = int(der_out[6:8], HEXADECIMAL)
                r_out          = int(der_out[8:8 + 2 * len_r_out], HEXADECIMAL)
                der_int_out    = der_out[8 + 2 * len_r_out:
                                         8 + 2 * len_r_out + 2]
                len_s_out      = der_out[8 + 2 * len_r_out + 2:
                                         8 + 2 * len_r_out + 4]
                len_s_out      = int(len_s_out, HEXADECIMAL)
                s_out          = der_out[8 + 2 * len_r_out + 4:
                                         8 + 2 * len_r_out + 4 + 2 * len_s_out]
                s_out          = int(s_out, HEXADECIMAL)
                output         = crypto.ecdsa.verify_sig((r_out, s_out),
                                                         bytes_for_sig,
                                                         src_trans_pub)
                len_r_ans      = int(der_ans[6:8], HEXADECIMAL)
                r_ans          = int(der_ans[8:8 + 2 * len_r_ans], HEXADECIMAL)
                der_int_ans    = der_ans[8 + 2 * len_r_ans:
                                         8 + 2 * len_r_ans + 2]
                len_s_ans      = der_ans[8 + 2 * len_r_ans + 2:
                                         8 + 2 * len_r_ans + 4]
                len_s_ans      = int(len_s_ans, HEXADECIMAL)
                s_ans          = der_ans[8 + 2 * len_r_ans + 4:
                                         8 + 2 * len_r_ans + 4 + 2 * len_s_ans]
                s_ans          = int(s_ans, HEXADECIMAL)
                answer         = crypto.ecdsa.verify_sig((r_ans, s_ans),
                                                         bytes_for_sig,
                                                         src_trans_pub)
                self.assertEqual(output, True)
                self.assertEqual(answer, True)

                # Checks the r and s length bytes.
                len_seq_out    = len(der_out[4:]) // 2
                len_r_out      = int(der_out[6:8], HEXADECIMAL)
                len_s_out      = der_out[8 + 2 * len_r_out + 2:
                                         8 + 2 * len_r_out + 4]
                len_s_out      = int(len_s_out, HEXADECIMAL)
                self.assertEqual(len_seq_out, len_r_out + len_s_out + 4)
                len_seq_ans    = len(der_ans[4:]) // 2
                len_r_ans      = int(der_ans[6:8], HEXADECIMAL)
                len_s_ans      = der_ans[8 + 2 * len_r_ans + 2:
                                         8 + 2 * len_r_ans + 4]
                len_s_ans      = int(len_s_ans, HEXADECIMAL)
                self.assertEqual(len_seq_ans, len_r_ans + len_s_ans + 4)

                # Checks the second DER_INT byte.
                output         = der_int_out
                answer         = der_int_ans
                self.assertEqual(output, DER_INT)
                self.assertEqual(answer, DER_INT)

                # Create a transaction.
                src_trans_hash = \
             "53bee0d4c8231e008ba5019e67661de19a9f4fc304ca456f1019c1d9d1357704"
                src_trans_ind  = 0
                src_trans_priv = \
             "257cd0b8ee2ab00a9d4934709cd21f79ef6075cfa9728c50"
                src_trans_pub  = int(src_trans_priv, HEXADECIMAL)
                src_trans_pub  = crypto.ecdsa.calc_public_key(src_trans_pub)
                src_i          = [(src_trans_hash,
                                   src_trans_ind,
                                   src_trans_priv,
                                   src_trans_pub)]
                dest_hash      = "329f894b359de9621b356b47c8df2d42187a35e9"
                n_coins        = 0.00001
                dst_i          = [(dest_hash, n_coins)]
                out_p          = tools.make_trans.hex_str(src_i, dst_i)

                # Define the correct transaction.
                ans_p          = \
"0100000001047735d1d9c119106f45ca04c34f9f9ae11d66679e01a58b001e23c8d4e0be53" + \
"000000008b4830450221009b7dd6031f17414685d390910dac802751e966b6f4f3c563df22" + \
"c1d995b8288c02205a05206f365ca7f296470562a80e7ba6275135c3d20bc886b93383fe11" + \
"642fb70141046562edcf88053a624581abeb641a0410d47fd0f3b3363e1af540b151b00b71" + \
"e7379ca7f8fa095d4026460138159022560a9ed40833857e88b4b20f0b58518470ffffffff" + \
"01e8030000000000001976a914329f894b359de9621b356b47c8df2d42187a35e988ac00000000"

                # Checks everything from the hash version on.
                n_bytes        = 4 + 25 + 1 + 8 + 1 + 4 + 32 + 32 + 1 + 1 + 1
                output         = out_p[-2 * n_bytes:]
                answer         = ans_p[-2 * n_bytes:]
                self.assertEqual(output, answer)

                # Checks everything up to and including the source index.
                n_bytes        = 4 + 1 + 32 + 4
                output         = out_p[:2 * n_bytes]
                answer         = ans_p[:2 * n_bytes]
                self.assertEqual(output, answer)

                # Gets the input.
                inp_data_out   = out_p[2 * n_bytes:out_p.find("ffffffff")]
                inp_data_ans   = ans_p[2 * n_bytes:ans_p.find("ffffffff")]

                # Checks the length byte of the input.
                output         = hex((len(inp_data_out) // 2) - 1)[2:]
                answer         = hex((len(inp_data_ans) // 2) - 1)[2:]
                self.assertEqual(output, inp_data_out[:2])
                self.assertEqual(answer, inp_data_ans[:2])

                # Checks the hash version byte, pub key length byte and pub key.
                output         = inp_data_out[-2 * (32 + 32 + 1 + 1 + 1):]
                answer         = inp_data_ans[-2 * (32 + 32 + 1 + 1 + 1):]
                self.assertEqual(output, answer)

                # Gets the DER signature of the input.
                der_out        = inp_data_out[2 * 2:-2 * (32 + 32 + 1 + 1 + 1)]
                der_ans        = inp_data_ans[2 * 2:-2 * (32 + 32 + 1 + 1 + 1)]

                # Checks the length (DER signature and hash version) byte.
                output         = hex((len(der_out) // 2) + 1)[2:]
                answer         = hex((len(der_ans) // 2) + 1)[2:]
                self.assertEqual(output, inp_data_out[2:4])
                self.assertEqual(answer, inp_data_ans[2:4])

                # Checks the DER_SEQ byte.
                output         = der_out[:2]
                answer         = der_ans[:2]
                self.assertEqual(output, DER_SEQ)
                self.assertEqual(answer, DER_SEQ)

                # Checks the DER sequence length byte.
                output         = hex(len(der_out[4:]) // 2)[2:]
                answer         = hex(len(der_ans[4:]) // 2)[2:]
                self.assertEqual(output, der_out[2:4])
                self.assertEqual(answer, der_ans[2:4])

                # Checks the first DER_INT byte.
                output         = der_out[4:6]
                answer         = der_ans[4:6]
                self.assertEqual(output, DER_INT)
                self.assertEqual(answer, DER_INT)

                # Checks the validity of the signature.
                bytes_for_sig  = tools.make_trans.hex_str(src_i,
                                                          dst_i,
                                                          src_i[0])
                bytes_for_sig += HASH_VER
                bytes_for_sig  = binascii.unhexlify(bytes_for_sig)

                len_r_out      = int(der_out[6:8], HEXADECIMAL)
                r_out          = int(der_out[8:8 + 2 * len_r_out], HEXADECIMAL)
                der_int_out    = der_out[8 + 2 * len_r_out:
                                         8 + 2 * len_r_out + 2]
                len_s_out      = der_out[8 + 2 * len_r_out + 2:
                                         8 + 2 * len_r_out + 4]
                len_s_out      = int(len_s_out, HEXADECIMAL)
                s_out          = der_out[8 + 2 * len_r_out + 4:
                                         8 + 2 * len_r_out + 4 + 2 * len_s_out]
                s_out          = int(s_out, HEXADECIMAL)
                output         = crypto.ecdsa.verify_sig((r_out, s_out),
                                                         bytes_for_sig,
                                                         src_trans_pub)
                len_r_ans      = int(der_ans[6:8], HEXADECIMAL)
                r_ans          = int(der_ans[8:8 + 2 * len_r_ans], HEXADECIMAL)
                der_int_ans    = der_ans[8 + 2 * len_r_ans:
                                         8 + 2 * len_r_ans + 2]
                len_s_ans      = der_ans[8 + 2 * len_r_ans + 2:
                                         8 + 2 * len_r_ans + 4]
                len_s_ans      = int(len_s_ans, HEXADECIMAL)
                s_ans          = der_ans[8 + 2 * len_r_ans + 4:
                                         8 + 2 * len_r_ans + 4 + 2 * len_s_ans]
                s_ans          = int(s_ans, HEXADECIMAL)
                answer         = crypto.ecdsa.verify_sig((r_ans, s_ans),
                                                         bytes_for_sig,
                                                         src_trans_pub)
                self.assertEqual(output, True)
                self.assertEqual(answer, True)

                # Checks the r and s length bytes.
                len_seq_out    = len(der_out[4:]) // 2
                len_r_out      = int(der_out[6:8], HEXADECIMAL)
                len_s_out      = der_out[8 + 2 * len_r_out + 2:
                                         8 + 2 * len_r_out + 4]
                len_s_out      = int(len_s_out, HEXADECIMAL)
                self.assertEqual(len_seq_out, len_r_out + len_s_out + 4)
                len_seq_ans    = len(der_ans[4:]) // 2
                len_r_ans      = int(der_ans[6:8], HEXADECIMAL)
                len_s_ans      = der_ans[8 + 2 * len_r_ans + 2:
                                         8 + 2 * len_r_ans + 4]
                len_s_ans      = int(len_s_ans, HEXADECIMAL)
                self.assertEqual(len_seq_ans, len_r_ans + len_s_ans + 4)

                # Checks the second DER_INT byte.
                output         = der_int_out
                answer         = der_int_ans
                self.assertEqual(output, DER_INT)
                self.assertEqual(answer, DER_INT)

test_suite = unittest.makeSuite(Tester)
unittest.TextTestRunner(verbosity = 2).run(test_suite)
