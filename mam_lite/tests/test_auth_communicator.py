import random
import string
from unittest import TestCase
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import AuthMessage, AuthCommunicator


class TestAuthCommunicator(TestCase):
    def setUp(self):
        self.address = Address(''.join(random.choices(string.ascii_uppercase + '9', k=81)))
        self.prikey, self.pubkey = Ed25519Cipher.generate_keys()
        self.auth_msg = AuthMessage().finalize(payload='data_to_be_sent',
                                               pubkey=self.pubkey,
                                               prikey=self.prikey)
        self.auth_comm = AuthCommunicator()

    def test_get_msgs_auth_by(self):
        prikey_1, pubkey_1 = Ed25519Cipher.generate_keys()
        prikey_2, pubkey_2 = Ed25519Cipher.generate_keys()
        auth_msg_1 = AuthMessage().finalize(payload='data_to_be_sent_1',
                                            pubkey=pubkey_1,
                                            prikey=prikey_1)
        auth_msg_2 = AuthMessage().finalize(payload='data_to_be_sent_2',
                                            pubkey=pubkey_2,
                                            prikey=prikey_2)
        auth_tx_1 = self.auth_comm.send_msg(auth_msg_1, self.address)
        auth_tx_2 = self.auth_comm.send_msg(auth_msg_2, self.address)

        # get all auth msgs
        all_auth_tx = self.auth_comm.get_auth_txs_from_address(self.address)
        self.assertEqual(len(all_auth_tx), 2)

        # get only auth msgs from pubkey_1
        pubkey_1_str = pubkey_1.to_ascii(encoding='base64').decode()
        pubkey_1_auth_tx = self.auth_comm.get_auth_txs_from_address(self.address, [pubkey_1_str])
        self.assertEqual(pubkey_1_auth_tx[0].hash,auth_tx_1.hash)
        self.assertEqual(pubkey_1_auth_tx[0].auth_msg.pubkey, auth_tx_1.auth_msg.pubkey)

    def test_send_msg(self):
        auth_tx = self.auth_comm.send_msg(self.auth_msg, self.address)
        self.assertTrue(auth_tx)
