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
ups="(s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,sa,sb,sc,sd,se,sf)"
upr=ups.replace("s","r")
mix="(%s)"%",".join(("g0[s%x]^g1[s%x]^g2[s%x]^g3[s%x]^r%x,g3[s%x]^g0[s%x]^g1[s%x]^g2[s%x]^r%x,g2[s%x]^g3[s%x]^g0[s%x]^g1[s%x]^r%x,g1[s%x]^g2[s%x]^g3[s%x]^g0[s%x]^r%x"%(i0,i1,i2,i3,i0,i0,i1,i2,i3,i1,i0,i1,i2,i3,i2,i0,i1,i2,i3,i3) for (i0,i1,i2,i3) in ((0,1,2,3),(4,5,6,7),(8,9,10,11),(12,13,14,15))))
imix="(%s)"%",".join(("g0[s%x]^g1[s%x]^g2[s%x]^g3[s%x],g3[s%x]^g0[s%x]^g1[s%x]^g2[s%x],g2[s%x]^g3[s%x]^g0[s%x]^g1[s%x],g1[s%x]^g2[s%x]^g3[s%x]^g0[s%x]"%(i*4) for i in ((0,1,2,3),(4,5,6,7),(8,9,10,11),(12,13,14,15))))
csl="s0 s5 sa sf s4 s9 se s3 s8 sd s2 s7 sc s1 s6 sb".split()
csr="s0 sd sa s7 s4 s1 se sb s8 s5 s2 sf sc s9 s6 s3".split()
box=",".join("sbox[%s]"%i for i in csl)
ibox=",".join("i_sbox[%s]^%s"%i for i in zip(csr,upr[1:-1].split(",")))
xor=",".join("sbox[%s]^r%x"%i for i in zip(csl,range(16)))
ixor=",".join("i_sbox[%s]^r%x"%i for i in zip(csr,range(16)))
xori=";".join("s%x^=r%x"%(i,i) for i in range(16))
ciph="""def decipher_block(f,s):
    sek=f._expanded_key
    g0,g1,g2,g3=galNI
    %(ups)=s+[0]*(16-len(s))
    %(upr)=k0
    %(xori)
    for i in range(!16):
        %(upr)=sek[i:i+16]
        %(ups)=%(box)
        %(ups)=%(mix)
    %(upr)=k2
    return %(xor)""".replace("%(ups)",ups).replace("%(xori)",xori).replace("%(upr)",upr)
class AESCipher:
    def __init__(self, expanded_key):
        self._expanded_key = expanded_key
        self._Nr = len(expanded_key)-16
    exec(ciph.replace("dec","c").replace("k0","sek[:16]").replace("!","16,f._Nr,").replace("k2","sek[f._Nr:]").replace("%(xor)",xor).replace("%(box)",box).replace("%(mix)",mix))
    exec(ciph.replace("NI","I").replace("k0","sek[f._Nr:]").replace("!","f._Nr-16,0,-").replace("k2","sek[:16]").replace("%(xor)",ixor).replace("%(box)",ibox).replace("%(mix)",imix))

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
                16,msg='Test %d bit cipher'%key_size)

            test_result_plaintext = test_cipher.decipher_block(test_data.test_block_ciphertext_validated[key_size])
            self.assertEquals(len([i for i, j in zip(test_result_plaintext, test_data.test_block_plaintext) if i == j]),
                16,msg='Test %d bit decipher'%key_size)

if __name__ == "__main__":
    unittest.main()