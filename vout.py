from pyhdwallet import Base58
from func import tolittle_endian
from opcodes import OPCODE_DICT
from binascii import hexlify

class Vout(object):
	"""

	"""
	def __init__(self, addr, coin, **kwargs):
		self.addr = addr # p2pkh p2sh etc.
		self.coin = self.coindec2coinhex(coin)
		self.count = 0

	def vout_number(self):
		# counter.
		count = self.count
		self.count += 1
		return count

	def scriptPubKey(self):

		script_type = self.addr[0]

		if script_type == "1":
			b58_dec = hexlify(Base58.check_decode(self.addr)).decode()
			code = [OPCODE_DICT.get(c) for c in ["OP_DUP", "OP_HASH160", "OP_EQUALVERIFY", "OP_CHECKSIG"]]
			return "{}{}{}".format(code[0] + code[1], len(b58_dec), b58_dec + code[2] + code[3])

		elif script_type == "3":
			b58_dec = hexlify(Base58.check_decode(self.addr)).decode()
			code = [OPCODE_DICT.get(c) for c in ["OP_HASH160", "OP_EQUAL"]]
			return "{}{}{}".format(code[0] + code[1], len(b58_dec), b58_dec + code[2] + code[3])

		elif script_type == "b":
			raise NotImplementedError("TODO: witness")
			if len(script_type) <= 34:
				# P2PKH
				pass
			else:
				# P2SH
				pass
		else:
			raise RuntimeError()

		return

	def coindec2coinhex(self, dec):
		_hex = hex(dec)[2:]
		return tolittle_endian(_hex)
