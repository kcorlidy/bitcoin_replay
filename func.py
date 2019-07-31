import ecdsa
from hashlib import sha256

def tobig_endian(value):

	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)

def tolittle_endian(value, size = 8):

	if isinstance(value, int) and size > 0:
		size += 2
		value = format(value, "#0%sx"%size)[2:]

	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)

def _load_key(key, public = False):

	if not public:
		types = ecdsa.SigningKey
	else:
		types = ecdsa.VerifyingKey

	k = (types.from_string(key) 
			if not isinstance(key, list) 
			else [types.from_string(_key) for _key in key]
			 )
	return k


def _load_tx_info(txid):
		pass

def dsha256(msg, func = sha256):
	if isinstance(msg, str):
		msg = bytes.fromhex(msg)
		
	return func(func(msg).digest()).digest()


if __name__ == '__main__':
	assert tolittle_endian(47825296, 16) == "90c1d90200000000"
	assert tolittle_endian(0, 2) == "00"
	assert tolittle_endian(1, 2) == "01"

	assert tobig_endian("00") == "00"
	assert tobig_endian("01") == "01"
	assert tobig_endian("90c1d90200000000") == "0000000002D9C190".lower()