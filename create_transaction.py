from pyhdwallet import Base58
from hashlib import sha256
from binascii import hexlify

info = ["m/44'/0'/0'/0/0", # path
 '1HnA8fYPskppWonizo8v1owqjBDMviz5Zh', # addr
 '02707f1e1a0e1ea7ba8ce83710604304fa85f995b6b0d15ff752cf70602cf4757e', #pub
 '5f5b55e76d05be90bdd523483386b8d418412dbe04dd398155c486319fb260f8', #pri
 'KzR58Tj1WkLvMJmyZzt3P4KTLJpv2tn7xK32nfHGNq9Ffw8WLUEc'] # wif


class Vin(object):
	"""docstring for Vin"""
	def __init__(self, addr, sequence = b"FFFFFFFF"):
		self.addr = addr

	def from_txid(self):
		pass
		
	def scriptSig(self):
		pass

	def txinwitness(self, mon, siglist, pubkeylist):
		pass

	def output(self):
		pass

class Vout(object):
	"""docstring for Vout"""
	def __init__(self, addr_hex):
		self.addr = self.reverse(addr_hex) if addr_hex[0] not in ["1", "3", "b"] else addr_hex

	def reverse(self, addr_hex):
		pass

	def value(self):
		pass

	def n(self):
		pass

	def scriptPubKey(self):
		pass

	def output(self):
		pass

class transaction(object):
	"""docstring for transaction"""
	def __init__(self,):
		self.version = 1

	def size(self):
		pass

	def vsize(self):
		pass

	def locktime(self):
		pass

	def txid(self):
		pass
