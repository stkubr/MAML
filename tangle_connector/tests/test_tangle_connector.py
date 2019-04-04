from unittest import TestCase

from iota import Address, TransactionHash

from tangle_connector import TangleConnector


class TestTangleConnector(TestCase):
    def setUp(self):
        self.tangle_con = TangleConnector()

    def test_get_node(self):
        res = self.tangle_con.get_node()
        self.assertEqual(res['appName'], 'IRI')

    def test_get_tips(self):
        res = self.tangle_con.get_tips()
        self.assertTrue(res['hashes'])

    def test_get_hashes_from_addr(self):
        addr = Address('CBGEYVNQIBTQFLR999YHPIDSKBBN9FFLDZPAXHWULQDRTFNDHFYEPNEKQOEF9OCKQTPXFRLOCRXMBCOFCODPNDPNPZ')
        tx_list = self.tangle_con.get_hashes_from_addr(addr)
        self.assertTrue(tx_list)

    def test_get_trytes_from_hashes(self):
        tx = TransactionHash(b'LFHPLTGTTNCYZRCHHCQCBMGUJKFMEHWUDRMHHRUVWNTERXHVEYKWSMZDRLKSYLBFUVTTOFKOFLJI99999')
        trytes_list = self.tangle_con.get_trytes_from_hashes([tx])
        self.assertTrue(trytes_list)

    def test_get_all_trytes_from_address(self):
        addr = Address('CBGEYVNQIBTQFLR999YHPIDSKBBN9FFLDZPAXHWULQDRTFNDHFYEPNEKQOEF9OCKQTPXFRLOCRXMBCOFCODPNDPNPZ')
        hashes_and_trytes = self.tangle_con.get_all_trytes_from_address(addr)
        self.assertTrue(hashes_and_trytes)

    def test_send_msg_to_addr(self):
        addr = Address('CBGEYVNQIBTQFLR999YHPIDSKBBN9FFLDZPAXHWULQDRTFNDHFYEPNEKQOEF9OCKQTPXFRLOCRXMBCOFCODPNDPNPZ')
        res = self.tangle_con.send_msg_to_addr(addr, 'test_string', 'TESTTAG')
        self.assertNotIn('Error', res.keys())

    def test_get_bundles_from_addr(self):
        addr = Address('CBGEYVNQIBTQFLR999YHPIDSKBBN9FFLDZPAXHWULQDRTFNDHFYEPNEKQOEF9OCKQTPXFRLOCRXMBCOFCODPNDPNPZ')
        res = self.tangle_con.get_bundles_from_addr(addr)
        self.assertTrue(res)

    def test_get_messages_from_bundles(self):
        addr = Address('CBGEYVNQIBTQFLR999YHPIDSKBBN9FFLDZPAXHWULQDRTFNDHFYEPNEKQOEF9OCKQTPXFRLOCRXMBCOFCODPNDPNPZ')
        res = self.tangle_con.get_bundles_from_addr(addr)
        output = self.tangle_con.get_messages_from_bundles(res)
        self.assertTrue(output)


