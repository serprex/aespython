"""
CBC Mode of operation

Algorithm per NIST SP 800-38A http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"
__all__ = "CBCMode",
from .mode import Mode

class CBCMode(Mode):
    """Perform CBC operation on a block and retain IV information for next operation"""

    def encrypt_block(self, plaintext):
        iv = self._iv = self._block_cipher.cipher_block([i ^ j for i,j in zip(plaintext, self._iv)])
        return iv

    def decrypt_block(self, ciphertext):
        plaintext = self._block_cipher.decipher_block(ciphertext)
        for i,v in enumerate(self._iv):plaintext[i] ^= v
        self._iv = ciphertext
        return plaintext
