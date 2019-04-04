import random
import string
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519

addr_test = Address(''.join(random.choices(string.ascii_uppercase + '9', k=81)))
mam_stream_1 = MAML_Ed25519(root_address=addr_test, channel_password='test_pass')
mam_stream_2 = MAML_Ed25519(root_address=addr_test, channel_password='test_pass')

# generate pubkey and make it trusted
prikey, pubkey = Ed25519Cipher.generate_keys()
mam_stream_1.add_trusted_pubkey('test_entity', pubkey)
mam_stream_2.add_trusted_pubkey('test_entity', pubkey)

# write with first MAML stream
write_res = mam_stream_1.write('data_to_be_sent', pubkey, prikey)

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
