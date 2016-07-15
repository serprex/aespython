__all__ = "Mode",
class Mode:
    __slots__ = "_iv", "_block_cipher"

    def __init__(self, block_cipher, block_size):
        self._block_cipher = block_cipher
        self._iv = [0] * block_size

    def set_iv(self, iv):
        if len(iv) == len(self._iv):
            self._iv = iv
