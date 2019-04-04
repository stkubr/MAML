import json
import logging
import random
import string
from typing import Dict
from ciphers import Ed25519Cipher

logger = logging.getLogger('AuthMessage')

class FactoryAuthMsg:
    '''
    Factory for AuthMessage
    '''
    @staticmethod
    def create_auth_msg_from_json(json_str: str):
        try:
            json_dict = json.loads(json_str)
        except ValueError:
            logger.warning('Decoding of JSON has failed')
            json_dict = None

        return FactoryAuthMsg.create_auth_msg_from_dict(json_dict)

    @staticmethod
    def create_auth_msg_from_dict(json_dict):
        # default invalid msg
        auth_msg = AuthMessage()
        if json_dict:
            if json_dict.get('addr', None):
                auth_msg = StreamAuthMessage.from_dict(json_dict)
            else:
                auth_msg = AuthMessage.from_dict(json_dict)
        return auth_msg

class AuthMessage:
    def __init__(self, payload = None, pubkey = None, signature = None, salt=None):
        self.payload = payload
        self.pubkey = pubkey
        self.signature = signature
        self.salt = salt

    def _set_data_payload(self, payload: str):
        self.payload = payload

    def _set_addr(self, addr: str):
        self.addr = addr

    def _set_pubkey(self, pubkey):
        self.pubkey = pubkey.to_ascii(encoding = 'base64').decode()

    def _set_signature(self, signature: str):
        self.signature = signature

    def _generate_salt(self):
        self.salt = ''.join(random.choices(string.ascii_lowercase, k=5))

    def finalize(self, payload: str, pubkey, prikey):
        self._set_data_payload(payload)
        self._set_pubkey(pubkey)
        self._generate_salt()
        self._set_signature(Ed25519Cipher.sign_message((payload + self.salt).encode(), prikey).decode())
        return self

    def validate(self):
        try:
            is_valid = Ed25519Cipher.verify_signature(
                (self.payload + self.salt).encode(),
                self.signature.encode(),
                Ed25519Cipher.verifying_key_from_string(self.pubkey))
        except:
            logger.warning('Failed to validate message')
            is_valid = False
        return is_valid

    def to_json(self):
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_str: str):
        json_dict = json.loads(json_str)
        return cls(**json_dict)

    @classmethod
    def from_dict(cls, json_dict: Dict):
        try:
            obj = cls(**json_dict)
        except:
            logger.warning('Failed to create message from dict')
            obj = None
        return obj

class StreamAuthMessage(AuthMessage):
    def __init__(self, payload = None, pubkey = None, signature = None, salt=None , addr=None, forward_addr=None):
        super(StreamAuthMessage, self).__init__(payload, pubkey, signature, salt)
        self.addr = addr
        self.forward_addr = forward_addr

    def _set_addr(self, addr: str):
        self.addr = addr

    def __set_forward_addr(self, forward_addr: str):
        self.forward_addr = forward_addr

    def finalize(self, payload: str, pubkey, prikey, addr, forward_addr):
        self._set_data_payload(payload)
        self._set_pubkey(pubkey)
        self._generate_salt()
        self._set_addr(addr)
        self.__set_forward_addr(forward_addr)
        self._set_signature(Ed25519Cipher.sign_message((payload + self.salt + addr + forward_addr).encode(), prikey).decode())
        return self

    def validate(self):
        try:
            is_valid = Ed25519Cipher.verify_signature(
                (self.payload + self.salt + self.addr + self.forward_addr
                ).encode(),
                self.signature.encode(),
                Ed25519Cipher.verifying_key_from_string(self.pubkey))
        except:
            is_valid = False
        return is_valid