# MAML_Ed25519 python library
------
Explanation and motivation: https://medium.com/.....

Inspired from MAML: https://github.com/rufsam/maml

Uses Ed25519 signature scheme from: https://github.com/warner/python-ed25519

### Install
pip install pyota ed25519 Crypto

### Usage

```python
import random
import string
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519

addr_test = Address(''.join(random.choices(string.ascii_uppercase + '9', k=81)))
mam_stream_1 = MAML_Ed25519(root_address=addr_test,channel_pwd='test_pass')
mam_stream_2 = MAML_Ed25519(root_address=addr_test,channel_pwd='test_pass')

# generate pubkey and make it trusted
prikey, pubkey = Ed25519Cipher.generate_keys()
mam_stream_1.add_trusted_pubkey('test', pubkey)
mam_stream_2.add_trusted_pubkey('test', pubkey)

# write with first MAML stream
mam_stream_1.write('data_to_be_sent', pubkey, prikey)

# read and validate with another
read_res = mam_stream_2.read()
```




