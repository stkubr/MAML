from Crypto.Hash import SHA256
from iota import TryteString

def hash_tryte(msg: str):
    digest = SHA256.new()
    digest.update(msg.encode())
    hash = digest.hexdigest()
    tryte_hash = TryteString.from_unicode(hash)[0:81]
    return tryte_hash.__str__()