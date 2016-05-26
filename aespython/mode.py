__all__ = "Mode",
class Mode:
    __slots__ = "_iv", "_block_size", "_block_cipher"

    def __init__(self, block_cipher, block_size):
        self._block_cipher = block_cipher
        self._block_size = block_size
        self._iv = [0] * block_size

    def set_iv(self, iv):
        if len(iv) == self._block_size:
            self._iv = iv
