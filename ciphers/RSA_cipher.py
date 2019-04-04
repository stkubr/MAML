from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64


class RSACipher:

    @staticmethod
    def generate_keys(modulus_length=1024):
        privatekey = RSA.generate(modulus_length, Random.new().read)
        publickey = privatekey.publickey()
        return privatekey, publickey

    @staticmethod
    def key_from_string(pubkey_as_string: str):
        return RSA.importKey(pubkey_as_string)

    @staticmethod
    def encrypt_message(a_message, publickey):
        cipher = PKCS1_OAEP.new(publickey)
        encrypted_msg = cipher.encrypt(a_message)
        encoded_encrypted_msg = base64.b64encode(encrypted_msg)  # base64 encoded strings are database friendly
        return encoded_encrypted_msg

    @staticmethod
    def decrypt_message(encoded_encrypted_msg, privatekey):
        cipher = PKCS1_OAEP.new(privatekey)
        decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
        decoded_decrypted_msg = cipher.decrypt(decoded_encrypted_msg)
        return decoded_decrypted_msg

    @staticmethod
    def sign_message(message, privatekey):
        digest = SHA256.new()
        digest.update(message)
        signer = PKCS1_PSS.new(privatekey)
        signature = signer.sign(digest)
        encoded_signature = base64.b64encode(signature)
        return encoded_signature

    @staticmethod
    def verify_signature(message, enc_signature, publickey):
        digest = SHA256.new()
        digest.update(message)
        signature = base64.b64decode(enc_signature)
        verifier = PKCS1_PSS.new(publickey)
        is_verified = verifier.verify(digest, signature)
        return is_verified
