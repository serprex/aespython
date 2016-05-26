"""
OFB Mode of operation

Algorithm per NIST SP 800-38A http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"
__all__ = "OFBMode",
from .mode import Mode

class OFBMode(Mode):
    """Perform OFB operation on a block and retain IV information for next operation"""

    def encrypt_block(self, plaintext):
        self._iv = cipher_iv = self._block_cipher.cipher_block(self._iv)
        return [i ^ j for i,j in zip(plaintext, cipher_iv)]

    def decrypt_block(self, ciphertext):
        self._iv = cipher_iv = self._block_cipher.cipher_block(self._iv)
        return [i ^ j for i,j in zip(cipher_iv, ciphertext)]