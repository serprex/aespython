try:
    from .aes_cipher import AESCipher
    from .key_expander import KeyExpander
    from .mode import Mode
    from .cbc_mode import CBCMode
    from .cfb_mode import CFBMode
    from .ofb_mode import OFBMode
except ImportError:
    from aespython.aes_cipher import AESCipher
    from aespython.key_expander import KeyExpander
    from aespython.mode import Mode
    from aespython.cbc_mode import CBCMode
    from aespython.cfb_mode import CFBMode
    from aespython.ofb_mode import OFBMode

