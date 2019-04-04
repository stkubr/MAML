import json
import logging
from iota import Iota, TryteString, TransactionHash, ProposedTransaction, Address, Tag, BadApiResponse
from typing import List, Dict
from iota.adapter.wrappers import RoutingWrapper

logger = logging.getLogger('TangleConnector')

class TangleConnector:
    def __init__(self, url='https://perma.iota.partners:443', seed="TESTSEED9"):
        self.iri_url = url
        self.iota_api = Iota(url, seed)

    def get_node(self) -> Dict:
        """
        Get IRI node info
        """
        try:
            res = self.iota_api.get_node_info()
        except BadApiResponse as e:
            logger.warning("Failed to IRI node info for " + self.iri_url, e)
            res = None
        return res

    def get_tips(self) -> Dict:
        """
        Get all unreferenced transactions
        """
        try:
            res = self.iota_api.get_tips()
        except BadApiResponse as e:
            logger.warning("Failed to get tips", e)
            res = None
        return res

    def get_hashes_from_addr(self, address: Address) -> List[TransactionHash]:
        """
        Get all tx from address
        """
        try:
            response = self.iota_api.find_transactions(addresses=[address])
            hashes = response['hashes']
        except (BadApiResponse, KeyError) as e:
            logger.warning("Failed to get all tx from address " + address.__str__(), e)
            hashes = None
        return hashes

    def get_trytes_from_hashes(self, hashes: List[TransactionHash]) -> List[TryteString]:
        """
        Get tryte signature fragments from hashes
        """
        try:
            response = self.iota_api.get_trytes(hashes)
            trytes = [tryte[0:2187] for tryte in response['trytes']]
        except (BadApiResponse, KeyError) as e:
            logger.warning("Failed to get all signature fragments", e)
            trytes = None
        return trytes

    def get_all_trytes_from_address(self, address: Address) -> Dict[TransactionHash, TryteString]:
        """
        Get all trytes from address
        """
        hashes = self.get_hashes_from_addr(address)
        trytes = self.get_trytes_from_hashes(hashes)
        if hashes and trytes:
            result = dict(zip(hashes, trytes))
        else:
            result = None
        return result

    @staticmethod
    def get_json_from_tryte(tryte: TryteString) -> Dict:
        try:
            str_from_tryte = tryte.as_string()
            dict_from_tryte = json.loads(str_from_tryte)
        except ValueError as e:
            logger.error("Failed to convet trytes to JSON", e)
            dict_from_tryte = None
        return dict_from_tryte

    def send_msg_to_addr(self, address: Address, msg: str, tag: str) -> Dict:
        """
        Sends msg on Tangle to address with a tag
        """
        try:
            response = self.iota_api.send_transfer(
                depth=2,
                transfers=[ProposedTransaction(address=address, value=0,
                                               tag=Tag(tag), message=TryteString.from_string(msg))]
            )
        except BadApiResponse as e:
            logger.warning("Message '" + msg + "' has failed to be stored in " + address.__str__(),e)
            response = None
        return response

    def get_bundles_from_addr(self, address: Address) -> List[Dict]:
        '''
        Retrive all bundles sent to this address from IRI
        # requres IRI 1.6+ (or it seems so)
        '''
        hashes = self.get_hashes_from_addr(address)
        bundles = []
        if hashes:
            for tx in hashes:
                try:
                    # have to loop through all txs, if tx is not 'tail' of a bundle then get_bundles() throws error
                    bundle = self.iota_api.get_bundles(tx)
                except BadApiResponse:
                    bundle = None

                if bundle:
                    bundles.append(bundle)
        return bundles

    def get_messages_from_bundles(self, bundles: List) -> Dict:
        """
        Loop through list of bundles and get string per bundle
        # requres IRI 1.6+ (or it seems so)
        """
        output_msgs = {}
        for bundle in bundles:
            tx_list = bundle['bundles'][0].as_json_compatible()
            msg = ''
            for tx in tx_list:
                # if its a bundle with iotas, just get text from first tx in bundle, the rest are signatures
                if tx['current_index'] == 0 and tx['value'] > 0:
                    msg = tx['signature_message_fragment'].as_string()
                    break
                # if its a bundle without iota value, then consequently get all message fields and join strings
                if tx['value'] == 0:
                    msg = msg + tx['signature_message_fragment'].as_string()
            bundle_hash = tx_list[0]['bundle_hash'].__str__()
            addr = tx_list[0]['address'].__str__()
            timestamp = tx_list[0]['timestamp']
            value = tx_list[0]['value']
            output_msgs[bundle_hash] = {'msg': msg, 'address': addr, 'timestamp': timestamp, 'value': value}
        return output_msgs

    def get_all_msg_from_addr_by_bundle(self, address: Address) -> Dict:
        '''
        Get dict of all msg with timestamps from address by bundle hash as key
        # requres IRI 1.6+ (or it seems so)
        '''
        bundles = self.get_bundles_from_addr(address)
        hashes_and_msgs = self.get_messages_from_bundles(bundles)
        return hashes_and_msgs
