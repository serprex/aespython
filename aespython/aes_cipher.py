#!/usr/bin/env python
"""
AES Block Cipher.

Performs single block cipher decipher operations on a 16 element list of integers.
These integers represent 8 bit bytes in a 128 bit block.
The result of cipher or decipher operations is the transformed 16 element list of integers.

Running this file as __main__ will result in a self-test of the algorithm.

Algorithm per NIST FIPS-197 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"

#Normally use relative import. In test mode use local import.
try:from .aes_tables import sbox,i_sbox,galI,galNI
except ValueError:from aes_tables import sbox,i_sbox,galI,galNI
#Perform mix_column for each column in the state
exec("def _mix_columns(s,g):g0,g1,g2,g3=g;%s=s;return ["%",".join("s%x"%i for i in range(16))+",".join((
"g0[s%x]^g1[s%x]^g2[s%x]^g3[s%x],g3[s%x]^g0[s%x]^g1[s%x]^g2[s%x],g2[s%x]^g3[s%x]^g0[s%x]^g1[s%x],g1[s%x]^g2[s%x]^g3[s%x]^g0[s%x]"%(i,i1,i2,i3,i,i1,i2,i3,i,i1,i2,i3,i,i1,i2,i3)
for i,i1,i2,i3,i4 in ((0,1,2,3,4),(4,5,6,7,8),(8,9,10,11,12),(12,13,14,15,16))))+"]")
#Run state through sbox
exec("def _sub_bytes(s):%s=s;"%",".join("s%x"%i for i in range(16))+";".join("s[%d]=sbox[s%x]"%(i,i) for i in range(16)))
#Run state through inverted sbox
exec("def _i_sub_bytes(s):%s=s;"%",".join("s%x"%i for i in range(16))+";".join("s[%d]=i_sbox[s%x]"%(i,i) for i in range(16)))
#XOR the state with the current round key
exec("def _add_round_key(s,r):"+";".join("s[%d]^=r[%d]"%(i,i) for i in range(16)))
def _shift_rows(state):
    #Extract rows as every 4th item starting at [1..3]
    #Replace row with shift_row operation
    state[1::4]=state[5::4]+state[1:5:4]
    state[2::4]=state[10::4]+state[2:10:4]
    state[3::4]=state[15:]+state[3:15:4]
def _i_shift_rows(state):
    #Extract rows as every 4th item starting at [1..3]
    #Replace row with inverse shift_row operation
    state[1::4]=state[13::4]+state[1:13:4]
    state[2::4]=state[10::4]+state[2:10:4]
    state[3::4]=state[7::4]+state[3:7:4]
#def _add_round_key(state,round):
    #XOR the state with the current round key
    #for i in 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15:state[i]^=round[i]
class AESCipher:
    """Perform single block AES cipher/decipher"""
    def __init__ (self, expanded_key):
        #Store epanded key
        self._expanded_key = expanded_key
        #Number of rounds determined by expanded key length
        self._Nr = len(expanded_key)-16
    def cipher_block (self, state):
        """Perform AES block cipher on input"""
        state=state+[0]*(16-len(state))#Fails test if it changes the input with +=
        sek=self._expanded_key
        _add_round_key(state,sek[:16])
        for i in range(16,self._Nr,16):
            _sub_bytes(state)
            _shift_rows(state)
            state=_mix_columns(state,galNI)
            _add_round_key(state,sek[i:i+16])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state,sek[self._Nr:])
        return state
    def decipher_block (self, state):
        """Perform AES block decipher on input"""
        state=state+[0]*(16-len(state))
        sek=self._expanded_key
        _add_round_key(state,sek[self._Nr:])
        for i in range(self._Nr-16,0,-16):
            _i_shift_rows(state)
            _i_sub_bytes(state)
            _add_round_key(state,sek[i:i+16])
            state=_mix_columns(state,galI)
        _i_shift_rows(state)
        _i_sub_bytes(state)
        _add_round_key(state,sek[:16])
        return state

import unittest
class TestCipher(unittest.TestCase):
    def test_cipher(self):
        """Test AES cipher with all key lengths"""
        import test_keys
        import key_expander

        test_data = test_keys.TestKeys()

        for key_size in 128, 192, 256:
            test_key_expander = key_expander.KeyExpander(key_size)
            test_expanded_key = test_key_expander.expand(test_data.test_key[key_size])
            test_cipher = AESCipher(test_expanded_key)
            test_result_ciphertext = test_cipher.cipher_block(test_data.test_block_plaintext)
            self.assertEquals(len([i for i, j in zip(test_result_ciphertext, test_data.test_block_ciphertext_validated[key_size]) if i == j]),
                16,
                msg='Test %d bit cipher'%key_size)

            test_result_plaintext = test_cipher.decipher_block(test_data.test_block_ciphertext_validated[key_size])
            self.assertEquals(len([i for i, j in zip(test_result_plaintext, test_data.test_block_plaintext) if i == j]),
                16,
                msg='Test %d bit decipher'%key_size)

if __name__ == "__main__":
    unittest.main()