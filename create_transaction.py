from pyhdwallet import Base58
from hashlib import sha256
from binascii import hexlify
import ecdsa

info = ["m/44'/0'/0'/0/0", # path
 '1HnA8fYPskppWonizo8v1owqjBDMviz5Zh', # addr
 '02707f1e1a0e1ea7ba8ce83710604304fa85f995b6b0d15ff752cf70602cf4757e', #pub
 '5f5b55e76d05be90bdd523483386b8d418412dbe04dd398155c486319fb260f8', #pri
 'KzR58Tj1WkLvMJmyZzt3P4KTLJpv2tn7xK32nfHGNq9Ffw8WLUEc'] # wif


def tobig_endian(value):
	if len(value) != 10:
		raise RuntimeError("invalid value length")
	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)

def tolittle_endian(value):
	if len(value) != 10:
		raise RuntimeError("invalid value length")
	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)


class Vin(object):
	"""
		:param pubkey:
		:param pre_txid:
		:param sequence:
		:param mon:
		
	"""
	def __init__(self, pubkey, pre_txid, vout, sequence = b"FFFFFFFF", mon=(-1, -1)):
		self.pubkey = pubkey
		self.seq = sequence # or 0
		self.pre_txid = tolittle_endian(pre_txid)
		self.vout = self.hexvout(vout)
		self.count = 0

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

	def scriptSig(self, prikey, msg):
		pass

	def txinwitness(self, siglist, redeemscript):
		self._txinwitness = siglist + [redeemscript]

	def initialize(self):
		pass

class Vout(object):
	"""docstring for Vout"""
	def __init__(self, addr):
		self.addr = addr # p2pkh p2sh etc.
		self.count = 0

	def scriptcode(self):
		pass

	def vout_n(self):
		# counter.
		count = self.count
		self.count += 1
		return count

	def scriptPubKey(self, pubkey, script_type):

		script_type = script_type.lower()

		if script_type == "p2pkh":
			pass

		elif script_type == "p2sh":
			pass

		elif script_type == "p2wpkh":
			pass

		elif script_type == "p2wsh":
			pass

		elif script_type == "bech32_p2pkh":
			pass

		elif script_type == "bech32_p2sh":
			pass

		else:
			raise RuntimeError()

		return

	def coindec2coinhex(self, dec):
		_hex = hex(dec)[2:]
		return tolittle_endian(_hex)

	def initialize(self):
		pass


class transaction(object):
	"""docstring for transaction"""
	def __init__(self, vin_info, vout_info, locktime, version = b'01000000'):
		self._version = version
		self._vin = [Vin(**vins) for vins in vin_info]
		self._vout = [Vout(**vouts) for vouts in _vout_info]
		self._locktime = self.locktime(locktime)


	def locktime(self):
		pass

	def txid(self):
		pass

	def initialize(self):
		pass
