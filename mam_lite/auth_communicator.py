import logging
from typing import List, Dict
from iota import Address
from mam_lite import AuthMessage, AuthTransaction, hash_tryte
from mam_lite.auth_message import FactoryAuthMsg
from tangle_connector import TangleConnector

logger = logging.getLogger('AuthCommunicator')

class AuthCommunicator:

    def __init__(self):
        self.tangle_con = TangleConnector()

    def extract_valid_auth_txs(self, raw_messages: Dict) -> List[AuthTransaction]:
        '''
        Extract valid AuthTransactions from list of raw messages
        :param raw_messages: Dict
        :return: List[AuthTransaction]
        '''
        output_auth_tx = []
        for tx_hash, raw_msg in raw_messages.items():
            auth_msg = FactoryAuthMsg.create_auth_msg_from_json(raw_msg['msg'])
            is_valid = auth_msg.validate()
            if is_valid:
                auth_tx = AuthTransaction(tx_hash, raw_msg['address'], raw_msg['timestamp'], raw_msg['value'], auth_msg)
                output_auth_tx.append(auth_tx)
        return output_auth_tx

    def filter_valid_auth_txs(self, auth_txs: List[AuthTransaction], pubkeys_list: List[str] = None) \
            -> List[AuthTransaction]:
        '''
        Filter list of AuthTransactions against pubkeys_list.
        If pubkeys_list is not provided, all AuthTransactions pass the filter
        :param auth_txs: List[AuthTransaction]
        :param pubkeys_list: List[str]
        :return: List[AuthTransaction]
        '''
        filtered_auth_txs = []
        for tx in auth_txs:
            is_in_pubkey_list = (pubkeys_list and tx.auth_msg.pubkey in (pubkeys_list or []))
            if (not pubkeys_list) or is_in_pubkey_list:
                filtered_auth_txs.append(tx)
        return filtered_auth_txs

    def get_auth_txs_from_address(self, address: Address, pubkeys_list: List[str] = None) -> List[AuthTransaction]:
        '''
        Retrieve list of AuthTransaction from address, optionaly filter for some specific pubkeys
        :param address: Address
        :param pubkeys_list: List[str]
        :return: List[AuthTransaction]
        '''
        raw_messages = self.tangle_con.get_all_msg_from_addr_by_bundle(address)
        auth_txs = self.extract_valid_auth_txs(raw_messages)
        return self.filter_valid_auth_txs(auth_txs, pubkeys_list)

    def send_msg(self, auth_msg: AuthMessage, address: Address, tag: str = 'AUTH9MSG') -> AuthTransaction:
        '''
        Send AuthMessage to address
        :param auth_msg: AuthMessage
        :param address: Address
        :param tag: str
        :return: AuthTransaction
        '''
        auth_tx = None
        if auth_msg.validate():
            res = self.tangle_con.send_msg_to_addr(address, auth_msg.to_json(), tag)
            if res:
                bundle = res['bundle'].as_json_compatible()[0]
                auth_tx = AuthTransaction(bundle['bundle_hash'].__str__(),
                                          address.__str__(),
                                          bundle['timestamp'],
                                          0, # value
                                          auth_msg)
        return auth_tx

    def send_msg_to_endpoint(self, auth_msg: AuthMessage, pubkey: str, tag: str = 'AUTH9MSG') -> AuthTransaction:
        '''
        Send AuthMessage to the endpoint authenticated by the pubkey
        :param auth_msg: AuthMessage
        :param pubkey: str
        :param tag: str
        :return: AuthTransaction
        '''
        endpoint_address = Address(hash_tryte(pubkey))
        auth_tx = self.send_msg(auth_msg, endpoint_address, tag)
        return auth_tx

    def get_self_auth_txs_from_endpoint(self, pubkey: str) -> List[AuthTransaction]:
        '''
        Retrieve list of AuthTransaction from endpoint authenticated by the pubkey
        and authored by the same pubkey
        :param address: Address
        :param pubkeys_list: List[str]
        :return: List[AuthTransaction]
        '''
        endpoint_address = Address(hash_tryte(pubkey))
        auth_tx = self.get_auth_txs_from_address(endpoint_address, [pubkey])
        return auth_tx
