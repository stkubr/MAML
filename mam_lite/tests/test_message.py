from unittest import TestCase
from ciphers import Ed25519Cipher
from mam_lite import AuthMessage
from mam_lite.auth_message import StreamAuthMessage, FactoryAuthMsg


class TestAuthMessage(TestCase):
    def test_finalize(self):
        auth_msg = AuthMessage()
        prikey, pubkey = Ed25519Cipher.generate_keys()
        auth_msg.finalize(payload='data_to_be_sent',
                          pubkey=pubkey,
                          prikey=prikey)
        is_valid = Ed25519Cipher.verify_signature(
            (auth_msg.payload + auth_msg.salt).encode(),
            auth_msg.signature.encode(),
            Ed25519Cipher.verifying_key_from_string(auth_msg.pubkey))
        self.assertTrue(is_valid)

    def test_validate(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        auth_msg = AuthMessage().finalize(payload='data_to_be_sent',
                                          pubkey=pubkey,
                                          prikey=prikey)
        is_valid_actual = Ed25519Cipher.verify_signature(
            (auth_msg.payload + auth_msg.salt).encode(),
            auth_msg.signature.encode(),
            Ed25519Cipher.verifying_key_from_string(auth_msg.pubkey))
        is_valid_expected = auth_msg.validate()
        self.assertEqual(is_valid_actual, is_valid_expected)


class TestStreamAuthMessage(TestCase):
    def test_finalize(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        auth_msg = StreamAuthMessage().finalize(payload='data_to_be_sent',
                                          pubkey=pubkey,
                                          prikey=prikey,
                                          addr='TESTADDRESS',
                                          forward_addr="TESTFORWARDADDRESS")
        is_valid = Ed25519Cipher.verify_signature(
            (auth_msg.payload + auth_msg.salt + auth_msg.addr + auth_msg.forward_addr).encode(),
            auth_msg.signature.encode(),
            Ed25519Cipher.verifying_key_from_string(auth_msg.pubkey))
        self.assertTrue(is_valid)

    def test_validate(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        auth_msg = StreamAuthMessage().finalize(payload='data_to_be_sent',
                                          pubkey=pubkey,
                                          prikey=prikey,
                                          addr='TESTADDRESS',
                                          forward_addr="TESTFORWARDADDRESS")
        is_valid_actual = Ed25519Cipher.verify_signature(
            (auth_msg.payload + auth_msg.salt + auth_msg.addr + auth_msg.forward_addr).encode(),
            auth_msg.signature.encode(),
            Ed25519Cipher.verifying_key_from_string(auth_msg.pubkey))
        is_valid_expected = auth_msg.validate()
        self.assertEqual(is_valid_actual, is_valid_expected)


class TestFactoryAuthMsg(TestCase):
    def test_create_auth_msg(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        auth_msg = AuthMessage().finalize(payload='data_to_be_sent',
                                      pubkey=pubkey,
                                      prikey=prikey)
        auth_msg_json = auth_msg.to_json()
        obj1 = FactoryAuthMsg.create_auth_msg_from_json(auth_msg_json)
        self.assertTrue(isinstance(obj1, AuthMessage))

        stream_auth_msg = StreamAuthMessage().finalize(payload='data_to_be_sent',
                                                pubkey=pubkey,
                                                prikey=prikey,
                                                addr='TESTADDRESS',
                                                forward_addr="TESTFORWARDADDRESS")
        stream_auth_msg_json = stream_auth_msg.to_json()
        obj2 = FactoryAuthMsg.create_auth_msg_from_json(stream_auth_msg_json)
        self.assertTrue(isinstance(obj2, StreamAuthMessage))
