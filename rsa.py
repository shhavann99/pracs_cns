import random
from sympy import nextprime
from sympy import mod_inverse

class RSA:
    BIT_LENGTH = 1024

    def __init__(self):
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)
        self.e = 89897  # Public exponent
        self.d = mod_inverse(self.e, phi)

    def generate_prime(self):
        #Generate a random prime number of specified bit length
        while True:
            prime_no = random.getrandbits(self.BIT_LENGTH // 2)
            prime_no = nextprime(prime_no)
            if prime_no.bit_length() == self.BIT_LENGTH // 2:
                return prime_no 

    def encrypt(self, message):
        #Encrypt the message using the public key
        return pow(message, self.e, self.n)

    def decrypt(self, ciphertext):
        #Decrypt the message using the private key
        return pow(ciphertext, self.d, self.n)

    def get_public_key(self):
        return self.e

    def get_modulus(self):
        return self.n


if __name__ == "__main__":
    rsa = RSA()

        
    print("Public Key (e):", rsa.get_public_key())
    print("Modulus (n):", rsa.get_modulus())

    plaintext = input("Enter a message to encrypt: ")
    message = int.from_bytes(plaintext.encode(), 'big')

    encrypted_message = rsa.encrypt(message)
    print("Encrypted Message:", encrypted_message)

    decrypted_message = rsa.decrypt(encrypted_message)
    decrypted_text = decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, 'big').decode()
    print("Decrypted Message:", decrypted_text)



