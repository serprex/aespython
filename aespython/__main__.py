from unittest import TestCase, main
from aespython import *

class TestCipher(TestCase):
    def test_cipher(self):
        """Test AES cipher with all key lengths"""
        test_data = TestKeys()
        for key_size in 128, 192, 256:
            test_key_expander = KeyExpander(key_size)
            test_expanded_key = test_key_expander.expand(test_data.test_key[key_size])
            test_cipher = AESCipher(test_expanded_key)
            test_result_ciphertext = test_cipher.cipher_block(test_data.test_block_plaintext)
            self.assertEqual(len([i for i, j in zip(test_result_ciphertext, test_data.test_block_ciphertext_validated[key_size]) if i == j]),
                16, msg='Test %d bit cipher'%key_size)
            test_result_plaintext = test_cipher.decipher_block(test_data.test_block_ciphertext_validated[key_size])
        self.assertEqual(len([i for i, j in zip(test_result_plaintext, test_data.test_block_plaintext) if i == j]),
            16,msg='Test %d bit decipher'%key_size)

class TestKeyExpander(TestCase):
    def test_keys(self):
        """Test All Key Expansions"""
        test_data = TestKeys()
        for key_size in 128, 192, 256:
            test_expander = KeyExpander(key_size)
            test_expanded_key = test_expander.expand(test_data.test_key[key_size])
            self.assertEqual(len([i for i, j in zip(test_expanded_key, test_data.test_expanded_key_validated[key_size]) if i == j]),
                len(test_data.test_expanded_key_validated[key_size]),
                msg='Key expansion %d bit'%key_size)

class TestEncryptionModeCBC(TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expander = KeyExpander(256)
        test_expanded_key = test_expander.expand(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_cbc = CBCMode(test_cipher, 16)

        test_cbc.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_cbc_ciphertext[k],test_cbc.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16, msg='CBC encrypt test block %d'%k)

        test_cbc.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_cbc.decrypt_block(test_data.test_cbc_ciphertext[k])) if i == j]),
                16, msg='CBC decrypt test block %d'%k)

class TestEncryptionModeCFB(TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expander = KeyExpander(256)
        test_expanded_key = test_expander.expand(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_cfb = CFBMode(test_cipher, 16)

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_cfb_ciphertext[k],test_cfb.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16, msg='CFB encrypt test block%d'%k)

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_cfb.decrypt_block(test_data.test_cfb_ciphertext[k])) if i == j]),
                16, msg='CFB decrypt test block%d'%k)

class TestEncryptionModeOFB(TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expander = KeyExpander(256)
        test_expanded_key = test_expander.expand(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_ofb = OFBMode(test_cipher, 16)

        test_ofb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_ofb_ciphertext[k],test_ofb.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16, msg='OFB encrypt test block%d'%k)

        test_ofb.set_iv(test_data.test_mode_iv)
        for k in range(4):
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_ofb.decrypt_block(test_data.test_ofb_ciphertext[k])) if i == j]),
                16, msg='OFB decrypt test block%d'%k)

class Benchmark(TestCase):
    def test_mode(self):
        from time import time
        from random import getrandbits
        def mkmode(mode):
            test_mode = mode(AESCipher(test_expander.expand(test_data.test_mode_key[:])), 16)
            test_mode.set_iv(test_data.test_mode_iv[:])
            return test_mode
        payload = [getrandbits(8) for a in range(16)]
        payload0 = payload[:]
        test_data = TestKeys()
        test_expander = KeyExpander(256)
        test_cbc = mkmode(CBCMode)
        test_cfb = mkmode(CFBMode)
        test_ofb = mkmode(OFBMode)
        t0 = time()
        for a in range(1024):
            payload = test_cbc.encrypt_block(payload)
            payload = test_cfb.encrypt_block(payload)
            payload = test_ofb.encrypt_block(payload)
        test_cbc.set_iv(test_data.test_mode_iv[:])
        test_cfb.set_iv(test_data.test_mode_iv[:])
        test_ofb.set_iv(test_data.test_mode_iv[:])
        for a in range(1024):
            payload = test_ofb.decrypt_block(payload)
            payload = test_cfb.decrypt_block(payload)
            payload = test_cbc.decrypt_block(payload)
        print(time() - t0)

class TestKeys:
    """Test data, keys, IVs, and output to use in self-tests"""
    def __init__(self):
        self.test_key = { 128: bytearray(range(0x10)), 192: bytearray(range(0x18)), 256: bytearray(range(0x20)) }

        self.test_expanded_key_validated = {
            128: bytearray(b"\
\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
\xd6\xaa\x74\xfd\xd2\xaf\x72\xfa\xda\xa6\x78\xf1\xd6\xab\x76\xfe\
\xb6\x92\xcf\x0b\x64\x3d\xbd\xf1\xbe\x9b\xc5\x00\x68\x30\xb3\xfe\
\xb6\xff\x74\x4e\xd2\xc2\xc9\xbf\x6c\x59\x0c\xbf\x04\x69\xbf\x41\
\x47\xf7\xf7\xbc\x95\x35\x3e\x03\xf9\x6c\x32\xbc\xfd\x05\x8d\xfd\
\x3c\xaa\xa3\xe8\xa9\x9f\x9d\xeb\x50\xf3\xaf\x57\xad\xf6\x22\xaa\
\x5e\x39\x0f\x7d\xf7\xa6\x92\x96\xa7\x55\x3d\xc1\x0a\xa3\x1f\x6b\
\x14\xf9\x70\x1a\xe3\x5f\xe2\x8c\x44\x0a\xdf\x4d\x4e\xa9\xc0\x26\
\x47\x43\x87\x35\xa4\x1c\x65\xb9\xe0\x16\xba\xf4\xae\xbf\x7a\xd2\
\x54\x99\x32\xd1\xf0\x85\x57\x68\x10\x93\xed\x9c\xbe\x2c\x97\x4e\
\x13\x11\x1d\x7f\xe3\x94\x4a\x17\xf3\x07\xa7\x8b\x4d\x2b\x30\xc5"),
            192: bytearray(b"\
\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
\x10\x11\x12\x13\x14\x15\x16\x17\x58\x46\xf2\xf9\x5c\x43\xf4\xfe\
\x54\x4a\xfe\xf5\x58\x47\xf0\xfa\x48\x56\xe2\xe9\x5c\x43\xf4\xfe\
\x40\xf9\x49\xb3\x1c\xba\xbd\x4d\x48\xf0\x43\xb8\x10\xb7\xb3\x42\
\x58\xe1\x51\xab\x04\xa2\xa5\x55\x7e\xff\xb5\x41\x62\x45\x08\x0c\
\x2a\xb5\x4b\xb4\x3a\x02\xf8\xf6\x62\xe3\xa9\x5d\x66\x41\x0c\x08\
\xf5\x01\x85\x72\x97\x44\x8d\x7e\xbd\xf1\xc6\xca\x87\xf3\x3e\x3c\
\xe5\x10\x97\x61\x83\x51\x9b\x69\x34\x15\x7c\x9e\xa3\x51\xf1\xe0\
\x1e\xa0\x37\x2a\x99\x53\x09\x16\x7c\x43\x9e\x77\xff\x12\x05\x1e\
\xdd\x7e\x0e\x88\x7e\x2f\xff\x68\x60\x8f\xc8\x42\xf9\xdc\xc1\x54\
\x85\x9f\x5f\x23\x7a\x8d\x5a\x3d\xc0\xc0\x29\x52\xbe\xef\xd6\x3a\
\xde\x60\x1e\x78\x27\xbc\xdf\x2c\xa2\x23\x80\x0f\xd8\xae\xda\x32\
\xa4\x97\x0a\x33\x1a\x78\xdc\x09\xc4\x18\xc2\x71\xe3\xa4\x1d\x5d"),
            256: bytearray(b"\
\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\
\xa5\x73\xc2\x9f\xa1\x76\xc4\x98\xa9\x7f\xce\x93\xa5\x72\xc0\x9c\
\x16\x51\xa8\xcd\x02\x44\xbe\xda\x1a\x5d\xa4\xc1\x06\x40\xba\xde\
\xae\x87\xdf\xf0\x0f\xf1\x1b\x68\xa6\x8e\xd5\xfb\x03\xfc\x15\x67\
\x6d\xe1\xf1\x48\x6f\xa5\x4f\x92\x75\xf8\xeb\x53\x73\xb8\x51\x8d\
\xc6\x56\x82\x7f\xc9\xa7\x99\x17\x6f\x29\x4c\xec\x6c\xd5\x59\x8b\
\x3d\xe2\x3a\x75\x52\x47\x75\xe7\x27\xbf\x9e\xb4\x54\x07\xcf\x39\
\x0b\xdc\x90\x5f\xc2\x7b\x09\x48\xad\x52\x45\xa4\xc1\x87\x1c\x2f\
\x45\xf5\xa6\x60\x17\xb2\xd3\x87\x30\x0d\x4d\x33\x64\x0a\x82\x0a\
\x7c\xcf\xf7\x1c\xbe\xb4\xfe\x54\x13\xe6\xbb\xf0\xd2\x61\xa7\xdf\
\xf0\x1a\xfa\xfe\xe7\xa8\x29\x79\xd7\xa5\x64\x4a\xb3\xaf\xe6\x40\
\x25\x41\xfe\x71\x9b\xf5\x00\x25\x88\x13\xbb\xd5\x5a\x72\x1c\x0a\
\x4e\x5a\x66\x99\xa9\xf2\x4f\xe0\x7e\x57\x2b\xaa\xcd\xf8\xcd\xea\
\x24\xfc\x79\xcc\xbf\x09\x79\xe9\x37\x1a\xc2\x3c\x6d\x68\xde\x36"),
        }

        self.test_block_ciphertext_validated = {
            128: [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a],
            192: [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91],
            256: [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89],
        }

        self.test_block_plaintext = list(range(0, 0x100, 0x11))

        #After initial validation, these deviated from test in SP 800-38A to use same key, iv, and plaintext on tests.
        #Still valid, just easier to test with.
        self.test_mode_key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]
        self.test_mode_iv = list(range(0x10))
        self.test_mode_plaintext = [
            [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
            [0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
            [0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
            [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10]]
        self.test_cbc_ciphertext = [
            [0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6],
            [0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d],
            [0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61],
            [0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b]]
        self.test_cfb_ciphertext = [
            [0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, 0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60],
            [0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8, 0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b],
            [0xdf, 0x10, 0x13, 0x24, 0x15, 0xe5, 0x4b, 0x92, 0xa1, 0x3e, 0xd0, 0xa8, 0x26, 0x7a, 0xe2, 0xf9],
            [0x75, 0xa3, 0x85, 0x74, 0x1a, 0xb9, 0xce, 0xf8, 0x20, 0x31, 0x62, 0x3d, 0x55, 0xb1, 0xe4, 0x71]]
        self.test_ofb_ciphertext = [
            [0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, 0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60],
            [0x4f, 0xeb, 0xdc, 0x67, 0x40, 0xd2, 0x0b, 0x3a, 0xc8, 0x8f, 0x6a, 0xd8, 0x2a, 0x4f, 0xb0, 0x8d],
            [0x71, 0xab, 0x47, 0xa0, 0x86, 0xe8, 0x6e, 0xed, 0xf3, 0x9d, 0x1c, 0x5b, 0xba, 0x97, 0xc4, 0x08],
            [0x01, 0x26, 0x14, 0x1d, 0x67, 0xf3, 0x7b, 0xe8, 0x53, 0x8f, 0x5a, 0x8b, 0xe7, 0x40, 0xe4, 0x84]]

if __name__ == "__main__":
    main()
