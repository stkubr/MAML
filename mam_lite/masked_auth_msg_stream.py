import logging
from typing import List
from iota import Address
from ciphers import AESCipher
from mam_lite import Response, hash_tryte, AuthCommunicator
from mam_lite.auth_message import StreamAuthMessage

logger = logging.getLogger('MaskedAuthMsgStream')

class MaskedAuthMsgStream:
    '''
    Masked Authenticated Messaging Stream allows to create communication channels for several entities.
    '''
    def __init__(self, root_address: Address, write_pwd: str ='', read_pwd: str = ''):
        self.auth_comm = AuthCommunicator()
        self.root_address = root_address.__str__()
        self.write_pwd = write_pwd
        self.read_pwd = read_pwd
        self.current_write_addr = root_address.__str__()
        self.current_read_addr = root_address.__str__()
        self.trusted_pubkeys = {}
        self.set_stream_type(write_pwd, read_pwd)

    def set_stream_type(self, write_pwd: str, read_pwd: str):
        # TODO need better control on stream_type and a way to switch stream_type
        if write_pwd and read_pwd:
            self.stream_type = 'private'
        elif write_pwd:
            self.stream_type = 'broadcast'
        else:
            self.stream_type = 'public'

    def _find_empty_addr(self):
        '''
        Loops from current_read_addr till the empty address,
        moves self.current_write_addr address pointer to the discovered empty address
        '''
        check_addr = self.current_read_addr
        while True:
            previous_addr = check_addr
            response = self._get_MAM_from_address(Address(check_addr))
            check_addr = hash_tryte(check_addr + self.write_pwd)
            if not response:
                self.current_write_addr = previous_addr
                break

    def _decrypt_msgs(self, auth_msgs):
        if self.read_pwd:
            for msg in auth_msgs:
                msg.payload = AESCipher(self.read_pwd).decrypt(msg.payload)
        return auth_msgs

    def _get_MAM_from_address(self, address: Address) -> Response or None:
        '''
        Discover whether the address contains messages that belong to the stream
        '''
        try:
            auth_txs = self.auth_comm.get_auth_txs_from_address(address, list(self.trusted_pubkeys.keys()))
            if auth_txs:
                auth_msgs = [tx.auth_msg for tx in auth_txs]
                auth_msgs = self._decrypt_msgs(auth_msgs)
                response = Response(address.__str__(),
                                    hash_tryte(address.__str__() + self.write_pwd),
                                    auth_msgs, True, True)
            else:
                response = None
        except:
            response = None
        return response

    def write(self, data: str, pubkey, prikey) -> Response or None:
        '''
        First discovers the empty address, then writes into it,
        if successful, moves self.current_write_addr one hash further
        '''
        self._find_empty_addr()
        if self.read_pwd:
            data = AESCipher(self.read_pwd).encrypt(data).decode()
        if self.stream_type == 'broadcast':
            forward_addr = hash_tryte(self.current_write_addr + self.write_pwd)
        else:
            forward_addr = ''

        msg = StreamAuthMessage().finalize(data, pubkey, prikey, self.current_write_addr, forward_addr)
        response_tangle = self.auth_comm.tangle_con.send_msg_to_addr(Address(self.current_write_addr),
                                         msg.to_json(),
                                         tag='PYTHONMAML')
        if response_tangle:
            if self.read_pwd:
                msg.payload = AESCipher(self.read_pwd).decrypt(msg.payload)
            response = Response(self.current_write_addr,
                                hash_tryte(self.current_write_addr + self.write_pwd),
                                [msg], True, True)
            self.current_write_addr = hash_tryte(self.current_write_addr + self.write_pwd)
        else:
            logger.error(f'Could not write into: {self.current_write_addr}')
            response = None
        return response

    def read(self) -> Response or None:
        '''
        Reads from self.current_read_addr, if successful moves self.current_read_addr one hash further
        '''
        response = self._get_MAM_from_address(Address(self.current_read_addr))
        if response:
            self.current_read_addr = hash_tryte(self.current_read_addr + self.write_pwd)
            return response
        else:
            return None

    def read_all(self) -> List[Response]:
        '''
        Calls read() several time until there is None response
        '''
        responses = []
        while(True):
            res = self.read()
            if res:
                responses.append(res)
            else:
                break
        return responses

    def split_channel(self, new_channel_pwd: str):
        '''
        Moves till the end of stream, then resets self.write_pwd,
        sets self.current_read_addr, self.current_write_addr to new positions
        '''
        self._find_empty_addr()
        self.write_pwd = new_channel_pwd
        self.current_write_addr = hash_tryte(self.current_write_addr + self.write_pwd)
        self.current_read_addr = self.current_write_addr

    def add_trusted_pubkey(self, name: str, pubkey):
        if isinstance(pubkey, str):
            self.trusted_pubkeys[pubkey] = name
        else:
            pubkey_str = pubkey.to_ascii(encoding = 'base64').decode()
            if pubkey_str:
                self.trusted_pubkeys[pubkey_str] = name

    def delete_trusted_pubkey(self, pubkey_str: str):
        if pubkey_str:
            self.trusted_pubkeys.pop(pubkey_str)
