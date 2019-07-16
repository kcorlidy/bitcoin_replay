from pyhdwallet import Base58
from hashlib import sha256
from binascii import hexlify
import ecdsa
import time

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
		:param key:
		:param tx: 			raw transaction, txid
		:param sequence:	default FFFFFFFF
		:param mon:			default None, means signle sig
		:param sighash:		default SIGHASH_ALL
		
	"""
	def __init__(self, key, tx, 
				sequence = b"FFFFFFFF", mon = None, sighash = SIGHASH.get("ALL")):
		self.key = key
		self.tx = tx if len(tx) > 64 else self._load_previous_tx_info(tx)

		self.seq = sequence
		self.mon = mon
		self.SIGHASH = sighash

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

	def _load_previous_tx_info(self):
		pass

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

	def _sign(self, msg):
		dsha256 = sha256(sha256(msg).digest()).digest()
		sk = self._load_key()
		return sk.sign(dsha256, sigencode=ecdsa.util.sigencode_der)

	def extract_rs(self, sig):
		r_p = int(sig[6:8], 16) * 2 + 8
		r = sig[8:r_p]
		s_p = int(sig[2+r_p:4+r_p], 16) * 2 + 12
		s = sig[s_p:r_p+s_p]
		return int(r, 16), int(s, 16)

	def verify(self, msg, sig):
		msg = sha256(sha256(msg).digest()).digest() if len(msg) != 64 else msg
		vk = self._load_key()
		return vk.verify(sig, msg, sigdecode=ecdsa.util.sigdecode_der)

	def scriptSig(self):
		if mon and len(mon) == 2:
			# multisig
			m, n = mon

		else:
			# single sig
			pass

	def txinwitness(self, siglist, redeemscript):
		self._txinwitness = siglist + [redeemscript]

	def initialize(self):
		pass

class Vout(object):
	"""docstring for Vout"""
	def __init__(self, addr, coin):
		self.addr = addr # p2pkh p2sh etc.
		self.coin = self.coindec2coinhex(coin)
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

		if script_type in ["p2pkh", "p2wpkh"]:
			pass

		elif script_type in ["p2sh", "p2wsh"]:
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
	def __init__(self, vin_info, vout_info, locktime = 0, version = b'01000000'):
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

	@property
	def print_json(self):
		pass

	@property
	def print_raw(self):
		pass
