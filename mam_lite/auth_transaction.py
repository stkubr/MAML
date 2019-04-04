import json
import logging
from mam_lite import AuthMessage
from mam_lite.auth_message import FactoryAuthMsg

logger = logging.getLogger('AuthTransaction')

class AuthTransaction:

    def __init__(self, hash: str, address: str, timestamp: int, value: int, auth_msg: AuthMessage):
        self.hash = hash
        self.address = address
        self.timestamp = timestamp
        self.value = value
        self.auth_msg = auth_msg

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    @staticmethod
    def from_json(json_str):
        try:
            json_dict = json.loads(json_str)
            auth_msg = FactoryAuthMsg.create_auth_msg_from_dict(json_dict['auth_msg'])
            auth_tx = AuthTransaction(json_dict['hash'], json_dict['address'], json_dict['timestamp'], json_dict['value'], auth_msg)
        except:
            logger.warning('Decoding JSON has failed')
            auth_tx = None
        return auth_tx


