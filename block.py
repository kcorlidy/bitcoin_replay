from hashlib import sha256
from binascii import hexlify
from create_transaction import transaction

class Block(object):
	"""docstring for Block"""
	def __init__(self, translist):
		super(Block, self).__init__()
		self.translist 		= translist
		self.vbrequired 	= 0
		self.vbavailable 	= {}
		self.capabilities	= ["proposal"]
		self.sigoplimit		= 80000
		self.sizelimit		= 4000000
		self.weightlimit	= 4000000
		self.rule			= ["csv","segwit"]

	def block_mintime(self):
		pass

	def block_hash(self):
		pass

	def version(self):
		pass

	def previousblockhash(self):
		pass

	def size_bits(self):
		pass

	def height(self):
		pass

class Block_transaction(object):
	"""docstring for Block_transaction"""
	def __init__(self):
		super(Block_transaction, self).__init__()

	def fee(self):
		pass

	def depends(self):
		pass

	def sigops(self):
		pass

	def weight(self):
		pass
		