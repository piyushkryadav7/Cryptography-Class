class MultiplicativeCipher:
    ALPHABET_SIZE = 26

    def __init__(self, key: int):
        if self.gcd(key, self.ALPHABET_SIZE) != 1:
            raise ValueError(f"Key {key} is not coprime with {self.ALPHABET_SIZE}.")
        self.key = key
        self.key_inv = self._mod_inverse(key, self.ALPHABET_SIZE)

    @staticmethod
    def gcd(a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    @classmethod
    def _mod_inverse(cls, a: int, m: int) -> int:
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 % m0

    def encrypt(self, plaintext: str) -> str:
        result = []
        for ch in plaintext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                num = ord(ch) - base
                enc = (num * self.key) % self.ALPHABET_SIZE
                result.append(chr(enc + base))
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        result = []
        for ch in ciphertext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                num = ord(ch) - base
                dec = (num * self.key_inv) % self.ALPHABET_SIZE
                result.append(chr(dec + base))
            else:
                result.append(ch)
        return "".join(result)


if __name__ == "__main__":
    mc = MultiplicativeCipher(key=15)
    msg = "Attack at dawn!"
    enc = mc.encrypt(msg)
    dec = mc.decrypt(enc)
    print(f"Plaintext : {msg}")
    print(f"Encrypted : {enc}")
    print(f"Decrypted : {dec}")
