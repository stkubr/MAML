import json
from typing import List
from mam_lite import AuthMessage


class Response:
    '''
    Response from MaskedAuthMsgStream
    '''
    def __init__(self, addr: str, next_addr: str, msgs: List[AuthMessage], is_valid, is_trusted):
        self.addr = addr
        self.next_addr = next_addr
        self.msgs = msgs
        self.is_valid = is_valid
        self.is_trusted = is_trusted

    def to_json(self):
        # TODO test this
        # json.dumps(self, default=lambda o: o.__dict__,
        #            sort_keys=True, indent=4)
        copy_res_dict = self.__dict__.copy()
        copy_res_dict['msgs'] = [msg.__dict__ for msg in self.msgs]
        return json.dumps(copy_res_dict)
