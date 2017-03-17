from unittest import TestCase, main
from aespython import *

class TestCipher(TestCase):
    def test_cipher(self):
        """Test AES cipher with all key lengths"""
        test_data = TestKeys()
        for key_size in 128, 192, 256:
            test_expanded_key = expandKey(test_data.test_key[key_size])
            test_cipher = AESCipher(test_expanded_key)
            test_result_ciphertext = test_cipher.cipher_block(test_data.test_block_plaintext)
            self.assertEqual(len([i for i, j in zip(test_result_ciphertext, test_data.test_block_ciphertext_validated[key_size]) if i == j]),
                16, msg='Test %d bit cipher'%key_size)
            test_result_plaintext = test_cipher.decipher_block(test_data.test_block_ciphertext_validated[key_size])
        self.assertEqual(len([i for i, j in zip(test_result_plaintext, test_data.test_block_plaintext) if i == j]),
            16, msg='Test %d bit decipher'%key_size)

class TestKeyExpander(TestCase):
    def test_keys(self):
        """Test All Key Expansions"""
        test_data = TestKeys()
        for key_size in 128, 192, 256:
            test_expanded_key = expandKey(test_data.test_key[key_size])
            self.assertEqual(len([i for i, j in zip(test_expanded_key, test_data.test_expanded_key_validated[key_size]) if i == j]),
                len(test_data.test_expanded_key_validated[key_size]),
                msg='Key expansion %d bit'%key_size)

class TestEncryptionModeCBC(TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expanded_key = expandKey(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_cbc = CBCMode(test_cipher)

        test_cbc.set_iv(test_data.test_mode_iv)
        for k in 0,1,2,3:
            self.assertEqual(len([i for i, j in zip(test_data.test_cbc_ciphertext[k],test_cbc.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16, msg='CBC encrypt test block %d'%k)

        test_cbc.set_iv(test_data.test_mode_iv)
        for k in 0,1,2,3:
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_cbc.decrypt_block(test_data.test_cbc_ciphertext[k])) if i == j]),
                16, msg='CBC decrypt test block %d'%k)

class TestEncryptionModeCFB(TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expanded_key = expandKey(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_cfb = CFBMode(test_cipher)

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in 0,1,2,3:
            self.assertEqual(len([i for i, j in zip(test_data.test_cfb_ciphertext[k],test_cfb.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16, msg='CFB encrypt test block%d'%k)

        test_cfb.set_iv(test_data.test_mode_iv)
        for k in 0,1,2,3:
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_cfb.decrypt_block(test_data.test_cfb_ciphertext[k])) if i == j]),
                16, msg='CFB decrypt test block%d'%k)

class TestEncryptionModeOFB(TestCase):
    def test_mode(self):
        test_data = TestKeys()

        test_expanded_key = expandKey(test_data.test_mode_key)

        test_cipher = AESCipher(test_expanded_key)

        test_ofb = OFBMode(test_cipher)

        test_ofb.set_iv(test_data.test_mode_iv)
        for k in 0,1,2,3:
            self.assertEqual(len([i for i, j in zip(test_data.test_ofb_ciphertext[k],test_ofb.encrypt_block(test_data.test_mode_plaintext[k])) if i == j]),
                16, msg='OFB encrypt test block%d'%k)

        test_ofb.set_iv(test_data.test_mode_iv)
        for k in 0,1,2,3:
            self.assertEqual(len([i for i, j in zip(test_data.test_mode_plaintext[k],test_ofb.decrypt_block(test_data.test_ofb_ciphertext[k])) if i == j]),
                16, msg='OFB decrypt test block%d'%k)

class Benchmark(TestCase):
    def test_mode(self):
        from time import time
        from random import getrandbits
        def mkmode(mode):
            test_mode = mode(AESCipher(expandKey(test_data.test_mode_key[:])))
            test_mode.set_iv(test_data.test_mode_iv)
            return test_mode
        payload = [getrandbits(8) for a in range(24576)] # 16*3*512
        payloaden = []
        test_data = TestKeys()
        test_cbc = mkmode(CBCMode)
        test_cfb = mkmode(CFBMode)
        test_ofb = mkmode(OFBMode)
        t0 = time()
        for a in range(0, 24576, 48):
            payloaden += test_cbc.encrypt_block(payload[a:a+16])
            payloaden += test_cfb.encrypt_block(payload[a+16:a+32])
            payloaden += test_ofb.encrypt_block(payload[a+32:a+48])
        test_cbc.set_iv(test_data.test_mode_iv)
        test_cfb.set_iv(test_data.test_mode_iv)
        test_ofb.set_iv(test_data.test_mode_iv)
        payloadde = []
        for a in range(0, 24576, 48):
            payloadde += test_cbc.decrypt_block(payloaden[a:a+16])
            payloadde += test_cfb.decrypt_block(payloaden[a+16:a+32])
            payloadde += test_ofb.decrypt_block(payloaden[a+32:a+48])
        print(time() - t0)
        assert payload == payloadde

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
            128: bytearray(b"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a"),
            192: bytearray(b"\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91"),
            256: bytearray(b"\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89"),
        }

        self.test_block_plaintext = list(range(0, 0x100, 0x11))

        #After initial validation, these deviated from test in SP 800-38A to use same key, iv, and plaintext on tests.
        #Still valid, just easier to test with.
        self.test_mode_key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]
        self.test_mode_iv = bytearray(range(0x10))
        self.test_mode_plaintext = (
            bytearray(b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"),
            bytearray(b"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"),
            bytearray(b"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"),
            bytearray(b"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"))
        self.test_cbc_ciphertext = (
            bytearray(b"\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6"),
            bytearray(b"\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d"),
            bytearray(b"\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61"),
            bytearray(b"\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b"))
        self.test_cfb_ciphertext = (
            bytearray(b"\xdc\x7e\x84\xbf\xda\x79\x16\x4b\x7e\xcd\x84\x86\x98\x5d\x38\x60"),
            bytearray(b"\x39\xff\xed\x14\x3b\x28\xb1\xc8\x32\x11\x3c\x63\x31\xe5\x40\x7b"),
            bytearray(b"\xdf\x10\x13\x24\x15\xe5\x4b\x92\xa1\x3e\xd0\xa8\x26\x7a\xe2\xf9"),
            bytearray(b"\x75\xa3\x85\x74\x1a\xb9\xce\xf8\x20\x31\x62\x3d\x55\xb1\xe4\x71"))
        self.test_ofb_ciphertext = (
            bytearray(b"\xdc\x7e\x84\xbf\xda\x79\x16\x4b\x7e\xcd\x84\x86\x98\x5d\x38\x60"),
            bytearray(b"\x4f\xeb\xdc\x67\x40\xd2\x0b\x3a\xc8\x8f\x6a\xd8\x2a\x4f\xb0\x8d"),
            bytearray(b"\x71\xab\x47\xa0\x86\xe8\x6e\xed\xf3\x9d\x1c\x5b\xba\x97\xc4\x08"),
            bytearray(b"\x01\x26\x14\x1d\x67\xf3\x7b\xe8\x53\x8f\x5a\x8b\xe7\x40\xe4\x84"))

if __name__ == "__main__":
    main()
