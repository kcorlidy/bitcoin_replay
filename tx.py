import ecdsa
import time
import calendar

from ecdsa.ecdsa import int_to_string, string_to_int
from functools import partial
from hashlib import sha256
from serialize import serialize_tx, deserialize_tx 
from . import tobig_endian, tobig_endian, _load_key, _load_tx_info, OPCODE_DICT



info = ["m/44'/0'/0'/0/0", # path
 '1HnA8fYPskppWonizo8v1owqjBDMviz5Zh', # addr
 '02707f1e1a0e1ea7ba8ce83710604304fa85f995b6b0d15ff752cf70602cf4757e', #pub
 '5f5b55e76d05be90bdd523483386b8d418412dbe04dd398155c486319fb260f8', #pri
 'KzR58Tj1WkLvMJmyZzt3P4KTLJpv2tn7xK32nfHGNq9Ffw8WLUEc'] # wif


SIGHASH = {
	"ALL": 0x01,
	"None": 0x02,
	"SINGLE": 0x03
}
		
class Transaction(Vin, Vout):
	"""

	"""
	def __init__(self, locktime = 0, version = b'01000000', **kwargs):
		super().__init__(**kwargs)
		self._version = version
		self._locktime = self.locktime(locktime)
		self._load_key = partial(_load_key, self)


	def create_rawtransaction(self):
		tx_raw = ""
		z = serialize_tx(self.tx_unspent, self.tx_raw)

		return z, tx_raw

	def sign_transaction(self, z):
		
		sk = self._load_key()
		return sk.sign(z, sigencode=ecdsa.util.sigencode_der)

	def extract_rs(self, sig):
		r_p = int(sig[6:8], 16) * 2 + 8
		r = sig[8:r_p]
		s_p = int(sig[2+r_p:4+r_p], 16) * 2 + 12
		s = sig[s_p:r_p+s_p]
		return int(r, 16), int(s, 16)

	def check_recovery(self, pub):
		padx = (b'\0'*32 + int_to_string(pub.pubkey.point.x()))[-32:]
		if pub.pubkey.point.y() & 1:
			ck = b'\3'+padx
		else:
			ck = b'\2'+padx
	
		scriptPubKey = hashlib.new("ripemd160", sha256(ck).digest()).hexdigest() 

		return scriptPubKey, hexlify(ck)

	def recovery_pubkey(self, r, s, z):
		pubkey = ecdsa.VerifyingKey.from_public_key_recovery(
			signature=signature, data=data, curve=curve, sigdecode=ecdsa.util.sigdecode_der)
		scriptPubKey_PubKeyhash = [ hexlify(pub) for pub in pubkey]
		return 

	def verify(self, z, sig):
		vk = self._load_key()
		return vk.verify(sig, z, sigdecode=ecdsa.util.sigdecode_der)

	def locktime(self, locktime):
		pass

	def txid(self, txhex):
		return hexlify(dsha256(txhex)[::-1])

	@property
	def print_json(self):
		pass

	@property
	def print_raw(self):
		pass


if __name__ == '__main__':
	ds = dsha256(bytes.fromhex("01000000000101d4c705db4bb9676e639c24262576dde43cac6d8933eed2d225afe732bf9450180000000017160014dd74b2d7191c7201ddaabf6792cfa18f34c9a695ffffffff01847f62000000000017a91455b074958c10742436c9ce0bfc533f440956305f8717a9149f9995e4dedfc5eab94774f425ad9395197e75ec870000000001000000"))
	print(hexlify(ds)) # a4cdc40b2f89603275753f24559fa4007cf4222b9bd95fd76465f541f47e681f
	# spk a9 14 9f9995e4dedfc5eab94774f425ad9395197e75ec 87