import unittest
from aespython.test_keys import TestKeys
from aespython import KeyExpander, AESCipher, CBCMode, CFBMode, OFBMode

class TestCipher(unittest.TestCase):
    def test_cipher(self):
        """Test AES cipher with all key lengths"""
        test_data = TestKeys()
        for key_size in 128, 192, 256:
            test_key_expander = KeyExpander(key_size)
            test_expanded_key = test_key_expander.expand(test_data.test_key[key_size])
            test_cipher = AESCipher(test_expanded_key)
            test_result_ciphertext = test_cipher.cipher_block(test_data.test_block_plaintext)
            self.assertEqual(len([i for i, j in zip(test_result_ciphertext, test_data.test_block_ciphertext_validated[key_size]) if i == j]),
                16,msg='Test %d bit cipher'%key_size)
            test_result_plaintext = test_cipher.decipher_block(test_data.test_block_ciphertext_validated[key_size])
        self.assertEqual(len([i for i, j in zip(test_result_plaintext, test_data.test_block_plaintext) if i == j]),
            16,msg='Test %d bit decipher'%key_size)

class TestEncryptionModeCBC(unittest.TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expander = KeyExpander(256)
        test_expanded_key = test_expander.expand(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_cbc = CBCMode(test_cipher, 16)

        test_cbc.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_cbc_ciphertext[k],test_cbc.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16,
                msg='CBC encrypt test block %d'%k)

        test_cbc.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_cbc.decrypt_block(test_data.test_cbc_ciphertext[k])) if i == j]),
                16,
                msg='CBC decrypt test block %d'%k)

class TestEncryptionModeCFB(unittest.TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expander = KeyExpander(256)
        test_expanded_key = test_expander.expand(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_cfb = CFBMode(test_cipher, 16)

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_cfb_ciphertext[k],test_cfb.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16,
                msg='CFB encrypt test block' + str(k))

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_cfb.decrypt_block(test_data.test_cfb_ciphertext[k])) if i == j]),
                16,
                msg='CFB decrypt test block' + str(k))

class TestKeyExpander(unittest.TestCase):
    def test_keys(self):
        """Test All Key Expansions"""
        test_data = TestKeys()
        for key_size in 128, 192, 256:
            test_expander = KeyExpander(key_size)
            test_expanded_key = test_expander.expand(test_data.test_key[key_size])
            self.assertEqual (len([i for i, j in zip(test_expanded_key, test_data.test_expanded_key_validated[key_size]) if i == j]),
                len(test_data.test_expanded_key_validated[key_size]),
                msg='Key expansion ' + str(key_size) + ' bit')

class TestEncryptionModeOFB(unittest.TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expander = KeyExpander(256)
        test_expanded_key = test_expander.expand(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_ofb = OFBMode(test_cipher, 16)

        test_ofb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_ofb_ciphertext[k],test_ofb.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16,
                msg='OFB encrypt test block' + str(k))

        test_ofb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_ofb.decrypt_block(test_data.test_ofb_ciphertext[k])) if i == j]),
                16,
                msg='OFB decrypt test block' + str(k))

if __name__ == "__main__":
    unittest.main()
