import random
import string
from unittest import TestCase

from iota import Address

from ciphers import Ed25519Cipher
from mam_lite import MaskedAuthMsgStream, hash_tryte


class TestMaskedAuthMsgStream(TestCase):

    def setUp(self):
        self.addr_test = Address(''.join(random.choices(string.ascii_uppercase + '9', k=81)))
        self.mam_stream = MaskedAuthMsgStream(self.addr_test, 'testpwd', 'testpwd')

    def test_hash_tryte(self):
        msg = 'data_to_be_hashed'
        actual_hash = hash_tryte(msg)
        expected_hash = 'SCTCYAXA9B9BVAQCXATCZAABWATCPCTCUAZAUAYATCPCZACBUCTCUAWAZAQCUATCPCUAUCQCXAUCQCBBA'
        self.assertTrue(expected_hash, actual_hash)

    def test_write(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        res = self.mam_stream.write('data_to_be_sent', pubkey, prikey)
        self.assertEqual('data_to_be_sent', res.msgs[0].payload)

    def test_read(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        self.mam_stream.write('data_to_be_sent', pubkey, prikey)
        read_res = self.mam_stream.read()
        self.assertEqual('data_to_be_sent', read_res.msgs[0].payload)

    def test_read_trusted(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        self.mam_stream.add_trusted_pubkey('test', pubkey)
        self.mam_stream.write_pwd = 'test'
        test_mam_stream = MaskedAuthMsgStream(self.mam_stream.root_address, self.mam_stream.write_pwd, self.mam_stream.read_pwd)

        write_res1 = self.mam_stream.write('data_to_be_sent1', pubkey, prikey)
        write_res2 = self.mam_stream.write('data_to_be_sent2', pubkey, prikey)
        write_res3 = self.mam_stream.write('data_to_be_sent3', pubkey, prikey)

        test_mam_stream.add_trusted_pubkey('test', pubkey)
        read_res = test_mam_stream.read()
        self.assertEqual('data_to_be_sent1', read_res.msgs[0].payload)
        read_res = test_mam_stream.read()
        self.assertEqual('data_to_be_sent2', read_res.msgs[0].payload)
        read_res = test_mam_stream.read()
        self.assertEqual('data_to_be_sent3', read_res.msgs[0].payload)

    def test_split(self):
        prikey, pubkey = Ed25519Cipher.generate_keys()
        self.mam_stream.write_pwd = 'test1'
        test_mam_stream = MaskedAuthMsgStream(self.mam_stream.root_address, self.mam_stream.write_pwd, self.mam_stream.read_pwd)
        write_res_1 = self.mam_stream.write('data_to_be_sent1', pubkey, prikey)
        write_res_2 = test_mam_stream.write('data_to_be_sent2', pubkey, prikey)
        self.mam_stream.split_channel('test2')
        write_res_3 = self.mam_stream.write('data_to_be_sent3', pubkey, prikey)
        test_mam_stream.split_channel('test2')
        read_res = test_mam_stream.read()
        self.assertEqual('data_to_be_sent3', read_res.msgs[0].payload)







