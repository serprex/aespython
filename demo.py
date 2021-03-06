#!/usr/bin/env python
"""
Demonstration the pythonaes package. Requires Python 2.6 or 3.x

This program was written as a test. It should be reviewed before use on classified material.
You should also keep a copy of your original file after it is encrypted, all of my tests were
able to get the file back 100% in tact and identical to the original. Your mileage may vary.

***This is a demo program.***

The method for creating the key and iv from a password is something that I made up, not an industry standard.
    There are 256 bits of salt pulled from OS's cryptographically strong random source.
    Any specific password will generate 2^128 different Keys.
    Any specific password will generate 2^128 different IVs independent of Key

On decryption, salt is read from first 32 bytes of encrypted file.

In the encrypted file, after salt(if present), are 4 bytes representing file size. 4GB file size limit.
It would also take quite a while to process 4GB.

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
from __future__ import print_function
__author__ = "Adam Newman"

import os
import hashlib
import struct
import getopt
import sys
import time

from aespython import expandKey, AESCipher, CBCMode

if bytes is str:
    def fix_bytes(byte_list):
        #bytes function is broken in python < 3. It appears to be an alias to str()
        #Either that or I have insufficient magic to make it work properly. Calling bytes on my
        #array returns a string of the list as if you fed the list to print() and captured stdout
        return ''.join(map(chr, byte_list))
else:
    fix_bytes = bytes

class AESdemo:
    def __init__(self):
        self._salt = None
        self._iv = None
        self._key = None

    def new_salt(self):
        self._salt = os.urandom(32)

    def set_iv(self, iv):
        self._iv = iv

    def set_key(self, key):
        self._key = key

    def hex_string_to_int_array(self, hex_string):
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

    def create_key_from_password(self, password):
        if self._salt is None:
            return
        sha512 = hashlib.sha512(password.encode('utf-8') + self._salt[:16]).digest()
        self._key = bytearray(sha512[:32])
        self._iv = [i ^ j for i, j in zip(bytearray(self._salt[16:]), bytearray(sha512[32:48]))]

    def decrypt_file(self, in_file_path, out_file_path, password = None):
        with open(in_file_path, 'rb') as in_file:

            #If a password is provided, generate key and iv using salt from file.
            if password is not None:
                self._salt = in_file.read(32)
                self.create_key_from_password(password)

            #Key and iv have not been generated or provided, bail out
            if self._key is None or self._iv is None:
                return False

            #Initialize encryption using key and iv
            expanded_key = expandKey(self._key)
            aes_cipher_256 = AESCipher(expanded_key)
            aes_cbc_256 = CBCMode(aes_cipher_256)
            aes_cbc_256.set_iv(self._iv)

            #Read original file size
            filesize = struct.unpack('!L',in_file.read(4))[0]

            #Decrypt to eof
            with open(out_file_path, 'wb') as out_file:
                while 1:
                    in_data = in_file.read(16)
                    if not in_data:
                        self._salt = None
                        return True
                    else:
                        out_data = aes_cbc_256.decrypt_block(bytearray(in_data))
                        #At end of file, if end of original file is within < 16 bytes slice it out.
                        out_file.write(fix_bytes(
                            out_data[:filesize - out_file.tell()] if filesize - out_file.tell() < 16
                            else fix_bytes(out_data)))

    def encrypt_file(self, in_file_path, out_file_path, password = None):
        #If a password is provided, generate new salt and create key and iv
        if password is not None:
            self.new_salt()
            self.create_key_from_password(password)
        else:
            self._salt = None

        #If key and iv are not provided are established above, bail out.
        if self._key is None or self._iv is None:
            return False

        #Initialize encryption using key and iv
        expanded_key = expandKey(self._key)
        aes_cipher_256 = AESCipher(expanded_key)
        aes_cbc_256 = CBCMode(aes_cipher_256)
        aes_cbc_256.set_iv(self._iv)

        #Get filesize of original file for storage in encrypted file
        try:
            filesize = os.stat(in_file_path)[6]
        except:
            return False

        with open(in_file_path, 'rb') as in_file:
            with open(out_file_path, 'wb') as out_file:
                #Write salt if present
                if self._salt is not None:
                    out_file.write(self._salt)

                #Write filesize of original
                out_file.write(struct.pack('!L',filesize))

                #Encrypt to eof
                while 1:
                    in_data = bytearray(in_file.read(16))
                    if not in_data:
                        self._salt = None
                        return True
                    else:
                        while len(in_data) < 16:in_data.append(0)
                        out_data = aes_cbc_256.encrypt_block(in_data)
                        out_file.write(fix_bytes(out_data))

def usage():
    print('AES Demo.py usage:')
    print('-d \t\t\t\t Use decryption mode.')
    print('-i INFILE   or --in=INFILE \t Specify input file.')
    print('-o OUTFILE  or --out=OUTFILE \t Specify output file.')
    print('-p PASSWORD or --pass=PASSWORD \t Specify password. precludes key/iv')
    print('-k HEXKEY   or --key=HEXKEY \t Provide 256 bit key manually. Requires iv.')
    print('-v HEXIV    or --iv=HEXIV \t Provide 128 bit IV manually. Requires key.')

def main():

    if sys.version_info < (2,6):
        print('Requires Python 2.6 or greater')
        sys.exit(1)

    if len(sys.argv) < 2:
        usage()
        sys.exit(2)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'dk:v:i:o:p:', ('key=','iv=','in=','out=','pass='))
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    in_file = None
    out_file = None
    key = None
    iv = None
    password = None
    decrypt = False

    demo = AESdemo()
    for o, a in opts:
        if o == '-d':
            decrypt=True
        elif o in ('-i','--in'):
            in_file = a
        elif o in ('-o','--out'):
            out_file = a
        elif o in ('-k','--key'):
            key = demo.hex_string_to_int_array(a)
        elif o in ('-v','--iv'):
            iv = demo.hex_string_to_int_array(a)
        elif o in ('-p','--pass'):
            password = a

    if key is password is None or (key is not None and password is not None):
        print('provide either key and iv or password')
        sys.exit(2)
    elif key is not None is iv:
        print('iv must be provided with key')
        sys.exit(2)
    elif key is not None:
        demo.set_key(key)
        demo.set_iv(iv)

    if in_file is None or out_file is None:
        print('Both input and output filenames are required')
        sys.exit(2)

    start = time.time()
    if decrypt:
        print('Decrypting', in_file, 'to', out_file)
        demo.decrypt_file(in_file, out_file, password)
    else:
        print('Encrypting', in_file, 'to', out_file)
        demo.encrypt_file(in_file, out_file, password)
    end = time.time()

    print('Time %ds', end - start)

if __name__ == "__main__":
    main()
