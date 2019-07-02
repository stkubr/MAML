[![Codacy Badge](https://api.codacy.com/project/badge/Grade/3c09d44316554f00b19f68a688b1f1cc)](https://app.codacy.com/app/stkubr/MAML?utm_source=github.com&utm_medium=referral&utm_content=stkubr/MAML&utm_campaign=Badge_Grade_Dashboard)
[![Build Status](https://travis-ci.com/stkubr/MAML.svg?branch=master)](https://travis-ci.com/stkubr/MAML)

# Currently rewriting in fully async mode, using iota_async from here https://github.com/stkubr/iota_async.lib.py

# MAML_Ed25519 Python library
------
Explanation and motivation: https://medium.com/@stkubr/iota-mam-ultra-lite-493d8d1fb71a

Inspired from MAML: https://github.com/rufsam/maml

Uses Ed25519 signature scheme from: https://github.com/warner/python-ed25519

### Install
pip install pyota ed25519 pycrypto

### Usage

```python
import random
import string
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519

addr_test = Address(''.join(random.choices(string.ascii_uppercase + '9', k=81)))
mam_stream_1 = MAML_Ed25519(root_address=addr_test,channel_password='test_pass')
mam_stream_2 = MAML_Ed25519(root_address=addr_test,channel_password='test_pass')

# generate pubkey and make it trusted
prikey, pubkey = Ed25519Cipher.generate_keys()
mam_stream_1.add_trusted_pubkey('test', pubkey)
mam_stream_2.add_trusted_pubkey('test', pubkey)

# write with first MAML stream
mam_stream_1.write('data_to_be_sent', pubkey, prikey)

# read and validate with another
read_res = mam_stream_2.read()

# split the channel
mam_stream_1.split_channel('test_pass_2')

# write new msg to new channel
write_res = mam_stream_1.write('data_to_be_sent_2', pubkey, prikey)

# switch the channel on second stream
mam_stream_2.split_channel('test_pass_2')

# read msg in second stream
read_res = mam_stream_2.read()

```
