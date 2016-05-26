#!/usr/bin/env python
"""
CFB Mode of operation

Algorithm per NIST SP 800-38A http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"
__all__ = "CFBMode",
from .mode import Mode

class CFBMode(Mode):
    """Perform CFB operation on a block and retain IV information for next operation"""

    def encrypt_block(self, plaintext):
        cipher_iv = self._block_cipher.cipher_block(self._iv)
        iv = self._iv = [i ^ j for i,j in zip(plaintext, cipher_iv)]
        return iv

    def decrypt_block(self, ciphertext):
        cipher_iv = self._block_cipher.cipher_block(self._iv)
        self._iv = ciphertext
        return [i ^ j for i,j in zip(cipher_iv, ciphertext)]
