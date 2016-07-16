#!/usr/bin/env python
"""
AES Block Cipher.

Performs single block cipher decipher operations on a 16 element list of integers.
These integers represent 8 bit bytes in a 128 bit block.
The result of cipher or decipher operations is the transformed 16 element list of integers.

Algorithm per NIST FIPS-197 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__all__ = "AESCipher",

from .aes_tables import sbox,i_sbox,galI,galNI
ups=",".join("s%x"%x for x in range(16))
upr=ups.replace("s","r")
mix=",".join(",".join(("g{0}[s%x]^g{1}[s%x]^g{2}[s%x]^g{3}[s%x]^r%x"%(i+(i[0]+(0,3,2,1)[j],))).format(j&3,j+1&3,j+2&3,j+3&3) for j in (0,3,2,1)) for i in ((0,1,2,3),(4,5,6,7),(8,9,10,11),(12,13,14,15))).replace("g2","g").replace("g3","g")
i=mix.find("g[")
while i!=-1:
    mix=mix[:i]+mix[i+2:i+4]+mix[i+5:]
    i=mix.find("g[",i)
imix=",".join(",".join(("g{0}[s%x]^g{1}[s%x]^g{2}[s%x]^g{3}[s%x]"%i).format(j&3,j+1&3,j+2&3,j+3&3) for j in (0,3,2,1)) for i in ((0,1,2,3),(4,5,6,7),(8,9,10,11),(12,13,14,15)))
csl=["s%x"%(x&15) for x in range(0,80,5)]
csr=["s%x"%(x&15) for x in range(0,-48,-3)]
box=",".join("s[%s]"%i for i in csl)
ibox=",".join("s[%s]^r%x"%i for i in zip(csr,range(16)))
xor=",".join("s[%s]^r%x"%i for i in zip(csl,range(16)))
xori=";".join("s%x^=r%x"%(i,i) for i in range(16))
ciph="""def decipher_block(z,s):
 g0,g1,g2,g3=galNI;S=s;s=sbox;R=z._f16;X
 for f in z._Nr:R=f;S=B;S=M
 R=z._l16
 return """.replace("S",ups).replace("R",upr).replace("X",xori)
class AESCipher:
    __slots__ = "_Nr", "_Nrr", "_f16","_l16"
    def __init__(self,expanded_key):
        self._Nr=[expanded_key[i:i+16] for i in range(16,len(expanded_key)-16,16)]
        self._Nrr=self._Nr[::-1]
        self._f16=expanded_key[:16]
        self._l16=expanded_key[-16:]
    exec(ciph.replace("g2,g3","").replace("dec","c").replace("B",box).replace("M",mix)+xor)
    exec(ciph.replace("NI","I").replace("l16\n","f16\n").replace("f16;","l16;").replace("Nr","Nrr").replace("sbox","i_sbox").replace("B",ibox).replace("M",imix)+ibox)