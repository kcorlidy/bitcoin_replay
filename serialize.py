from func import tolittle_endian, tobig_endian
from opcodes import OPCODE_DICT
from sighash import SIGHASH
from binascii import hexlify

_hex = lambda x: hex()[2:]

class tx(object):
	"""
		version + inputs + outputs + locktime = tx
	"""
	def __init__(self, inputs, ouputs, locktime = 0, seq = 4294967295, version = 2):
		self.ver = tolittle_endian(version)
		self.inputs = {}
		self.ouputs = {}
		self.locktime = tolittle_endian(locktime)
		self.seq = tolittle_endian(seq)

	@classmethod
	def MoNscript(self, m, n, publickeylist):
		
		if isinstance(publickeylist, list) or isinstance(publickeylist, tuple)\
			and (isinstance(m, int) and isinstance(n) and m <= n and m >= 2):
			m += 80
			n += 80
			start = [bytes.fromhex(_hex(m))]

			for pk in publickeylist:
				pk = pk if isinstance(pk, bytes) else bytes.fromhex(pk)
				start += [bytes.fromhex(_hex(len(pk))), pk]

			start += [bytes.fromhex(_hex(n)),
						 bytes.fromhex(OPCODE_DICT.get("OP_CHECKMULTISIG"))]
		else:
			raise NotImplementedError("Can not handle your input")

		return hexlify(b"".join(start)).decode()


	@classmethod
	def redeemscript(self, script, addr_type = None):
		pass

	def createrawtransaction(self):
		pass

	def serialize(self):
		pass

	@classmethod
	def createScriptPubkey(self, value, script_type):
		pass

	def embed_scriptsig(self):
		pass

	def serialize_tx(tx_now, tx_bef):
		# load two transaction
		tx_now = tx_now if len(tx_now) != 64 else _load_tx_info(tx_now)
		tx_bef = tx_bef if len(tx_bef) != 64 else _load_tx_info(tx_bef)

		# clean the now one

		# add previous transaction vout info into cleaned transaction

		# double sha256
			
		return tx_now

	def deserialize_tx(tx_now, tx_bef):
		# load two transaction
		tx_now = tx_now if len(tx_now) != 64 else _load_tx_info(tx_now)
		tx_bef = tx_bef if len(tx_bef) != 64 else _load_tx_info(tx_bef)

		# clean the now one

		# add previous transaction vout info into cleaned transaction

		# double sha256
			
		return tx_now

class witness_tx(tx):
	"""
		version + maker + flag + inputs + outputs + witness + locktime = tx
	"""

	def __init__(self, inputs, ouputs, witness, maker = 0, flag = 1, **kw):
		super(normal_tx, self).__init__(inputs, ouputs, **kw)
		self.maker = tolittle_endian(maker, 2)
		self.flag = tolittle_endian(flag, 2)
		self.witness = {}

	def createrawtransaction(self):
		pass

	def serialize(self):
		pass

	def embed_witness(self):
		pass

	@classmethod
	def createScriptPubkey(self, value, script_type):
		result = super().createScriptPubkey(value, script_type)
		if result:
			return result

		return

	def serialize_tx(tx_now, tx_bef):
		# load two transaction
		tx_now = tx_now if len(tx_now) != 64 else _load_tx_info(tx_now)
		tx_bef = tx_bef if len(tx_bef) != 64 else _load_tx_info(tx_bef)

		# clean the now one

		# add previous transaction vout info into cleaned transaction

		# double sha256
			
		return tx_now

	def deserialize_tx(tx_now, tx_bef):
		# load two transaction
		tx_now = tx_now if len(tx_now) != 64 else _load_tx_info(tx_now)
		tx_bef = tx_bef if len(tx_bef) != 64 else _load_tx_info(tx_bef)

		# clean the now one

		# add previous transaction vout info into cleaned transaction

		# double sha256
			
		return tx_now