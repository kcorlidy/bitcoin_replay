from binascii import hexlify
from func import tolittle_endian
from opcodes import OPCODE_DICT
from sighash import SIGHASH

class Vin(object):
	"""
		:param key:
		:param tx: 			raw transaction, txid
		:param sequence:	default FFFFFFFF
		:param mon:			default None, means signle sig
		:param sighash:		default SIGHASH_ALL
		
	"""
	def __init__(self, key, tx_unspent, 
				sequence = b"FFFFFFFF", mon = None, sighash = SIGHASH.get("ALL"), **kwargs):
		self.key = key
		self.tx_unspent = tx_unspent
		self.seq = sequence
		self.mon = mon
		self.SIGHASH = sighash
		self.count = 0
		super().__init__(**kwargs)

	def hexvout(self, vout):
		return tolittle_endian(format(vout, "##010x")[2:])

	@classmethod
	def redeemscript(self, m, n, publickeylist):
		# P2WSH calls witnessScript, P2SH calls redeemScript
		# Be careful the order of publickeylist, which will change your address. Then redeem unsuccessfully
		if isinstance(publickeylist, list) or isinstance(publickeylist, tuple)\
			and (isinstance(m, int) and isinstance(n) and m <= n and m >= 1):
			m += 50
			n += 50
			start = [bytes.fromhex("{}".format(m))]
			for pk in publickeylist:
				start += [bytes.fromhex("21"), pk if isinstance(pk, bytes) else bytes.fromhex(pk)]
			start += [bytes.fromhex("{}".format(n)), bytes.fromhex("ae")]
		else:
			raise NotImplementedError("Can not handle your input")

		return hexlify(b"".join(start)).decode()


	def scriptSig(self, witness = False):
		if not witness:
			
			if mon and len(mon) == 2:
				# multisig
				m, n = mon

			else:
				# single sig
				pass

			return

		if witness == "P2WPKH nested in BIP16 P2SH":
			pass

		elif witness == "P2WSH nested in BIP16 P2SH":
			pass

		elif witness == "P2WPKH":
			pass

		elif witness == "P2WSH":
			pass

		else:
			raise RuntimeError("invalid witness type")

		return

	def txinwitness(self, siglist, redeemscript):
		self._txinwitness = siglist + [redeemscript]

