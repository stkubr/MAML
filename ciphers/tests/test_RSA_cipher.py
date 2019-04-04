from unittest import TestCase

from ciphers import RSACipher


class TestRSACipher(TestCase):

    def setUp(self):
        self.prikey, self.pubkey = RSACipher.generate_keys()

    def test_generate_keys(self):
        prikey, pubkey = RSACipher.generate_keys()
        self.assertTrue(prikey)
        self.assertTrue(pubkey)

    def test_key_from_string(self):
        pubkey_as_str = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1yZCkFgdm7okZRjFwv18VatuW\nPs+c9EKfeO374mMscTqKzrBm1dtsBZP/x6Xwu6BBA2caPh9KJpUVN2y32znZebDf\nV3ZlGbSVsAZAiXbO0cVDqhW7WDetJNEFRkkt/57NuWTSKrfmB3F13Ig2ZGIGOfeo\nr1//zhOTR5vL6VxA5QIDAQAB\n-----END PUBLIC KEY-----'
        pubkey = RSACipher.key_from_string(pubkey_as_str)
        self.assertTrue(pubkey)

    def test_decrypt_message(self):
        msg = b'top_secret'
        msg_enc = RSACipher.encrypt_message(msg, self.pubkey)
        msg_dec = RSACipher.decrypt_message(msg_enc, self.prikey)
        self.assertEqual(msg, msg_dec)

    def test_verify_signature(self):
        msg = 'data_to_be_signed'
        signature = RSACipher.sign_message(msg.encode(), self.prikey)
        verified = RSACipher.verify_signature(msg.encode(), signature, self.pubkey)
        self.assertTrue(verified)
