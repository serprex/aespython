[![Test](https://github.com/serprex/aespython/workflows/.github/workflows/test.yml/badge.svg)](https://github.com/serprex/aespython/actions?query=workflow%3A.github%2Fworkflows%2Ftest.yml)

This repo is the pure speed fork of caller9's original library. This version does not handle padding. It implements CBC, CFB, & OFB

	# given a key, iv, & blocksize
	from aespython import expandKey, AESCipher, CBCMode
	expandedkey = expandKey(key) # key must be of length 16, 24, or 32
	cipher = AESCipher(expandedkey)
	cbc = CBCMode(cipher)
	cbc.set_iv(iv) # iv must be of length 16

	# user is responsible to make sure data is padded to a multiple of 16 in length
	encryptedblock0 = cbc.encrypt_block(data[0:16])
	encryptedblock1 = cbc.encrypt_block(data[16:32])
