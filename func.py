import ecdsa
from hashlib import sha256

def tobig_endian(value):

	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)

def tolittle_endian(value):

	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)

def _load_key(self, public = False):
	if not public:
		types = ecdsa.SigningKey
		key = [pri for pri,pub in self.key] if isinstance(key, list) else self.key[0]
	else:
		types = ecdsa.VerifyingKey
		key = [pub for pri,pub in self.key] if isinstance(key, list) else self.key[1]

	sk = (types.from_string(key) 
			if not isinstance(key, list) 
			else [ecdsa.SigningKey.from_string(_key) for _key in key]
			 )
	return sk


def _load_tx_info(txid):
		pass

def dsha256(msg):
	return sha256(sha256(msg).digest()).digest()

_hex = lambda x: hex(x)[2:]
