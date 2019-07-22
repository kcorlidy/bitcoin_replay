import ecdsa
import time
import calendar

from ecdsa.ecdsa import int_to_string, string_to_int
from functools import partial
from binascii import hexlify
from hashlib import sha256
from serialize import tx, witness_tx 
from opcodes import OPCODE_DICT
from func import tolittle_endian, _load_tx_info, _load_key, dsha256


info = ["m/44'/0'/0'/0/0", # path
 '1HnA8fYPskppWonizo8v1owqjBDMviz5Zh', # addr
 '02707f1e1a0e1ea7ba8ce83710604304fa85f995b6b0d15ff752cf70602cf4757e', #pub
 '5f5b55e76d05be90bdd523483386b8d418412dbe04dd398155c486319fb260f8', #pri
 'KzR58Tj1WkLvMJmyZzt3P4KTLJpv2tn7xK32nfHGNq9Ffw8WLUEc'] # wif


	
class Transaction(object):
	"""

	"""
	def __init__(self,  **kwargs):
		super().__init__(**kwargs)
		self._load_key = partial(_load_key, self)

	def sign_transaction(self, key, msg):
		
		sk = _load_key(key)
		return sk.sign(msg, sigencode=ecdsa.util.sigencode_der)

	def check_recovery(self, pub):

		padx = (b'\0'*32 + int_to_string(pub.pubkey.point.x()))[-32:]
		if pub.pubkey.point.y() & 1:
			ck = b'\3'+padx
		else:
			ck = b'\2'+padx
	
		scriptPubKey = hashlib.new("ripemd160", sha256(ck).digest()).hexdigest() 

		return scriptPubKey, hexlify(ck)

	def recovery_pubkey(self, signature, msg):

		pubkey = ecdsa.VerifyingKey.from_public_key_recovery(
			signature=signature, data=msg, curve=curve, sigdecode=ecdsa.util.sigdecode_der)
		scriptPubKey_PubKeyhash = [ hexlify(pub) for pub in pubkey]
		return 

	def verify(self, key, msg, sig):

		vk = _load_key(key, public = True)
		return vk.verify(sig, msg, sigdecode=ecdsa.util.sigdecode_der)


if __name__ == '__main__':
	ds = dsha256(bytes.fromhex("01000000000101d4c705db4bb9676e639c24262576dde43cac6d8933eed2d225afe732bf9450180000000017160014dd74b2d7191c7201ddaabf6792cfa18f34c9a695ffffffff01847f62000000000017a91455b074958c10742436c9ce0bfc533f440956305f8717a9149f9995e4dedfc5eab94774f425ad9395197e75ec870000000001000000"))
	print(hexlify(ds)) # a4cdc40b2f89603275753f24559fa4007cf4222b9bd95fd76465f541f47e681f
	# spk a9 14 9f9995e4dedfc5eab94774f425ad9395197e75ec 87