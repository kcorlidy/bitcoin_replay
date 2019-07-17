from pyhdwallet import Base58
from hashlib import sha256
from binascii import hexlify
import ecdsa
import time
import calendar
from opcodes import OPCODE_LIST
from functools import partial


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

	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)

def tolittle_endian(value):

	a = value[::2]
	b = value[::-2][::-1]
	rev = ["".join(i) for i in list(zip(a,b))][::-1]
	return "".join(rev)

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


def _load_tx_info(txid):
		pass


def calculate_zvalue(tx_now, tx_bef):
	# load two transaction
	tx_now = tx_now if len(tx_now) != 64 else _load_tx_info(tx_now)
	tx_bef = tx_bef if len(tx_bef) != 64 else _load_tx_info(tx_bef)

	# clean the now one

	# add previous transaction vout info into cleaned transaction

	# double sha256
		
	return tx_now

_hex = lambda x: hex(x)[2:]

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


	def _sign(self, msg):
		
		calculate_zvalue(tx_unspent)

		sk = self._load_key()
		return sk.sign(dsha256, sigencode=ecdsa.util.sigencode_der)


	def multisig(self, msg):
		pass

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

	def scriptPubKey(self, pubkey, script_type):

		script_type = self.addr[0]

		if script_type == "1":
			# P2PKH, P2WPKH, P2WPKHoP2SH
			pass

		elif script_type == "3":
			# P2SH, P2WSH, P2WSHoP2SH 
			pass

		elif script_type == "b":
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

		
class Transaction(Vin, Vout):
	"""

	"""
	def __init__(self, locktime = 0, version = b'01000000', **kwargs):
		super().__init__(**kwargs)
		self._version = version
		self._locktime = self.locktime(locktime)
		self._load_key = partial(_load_key, self)


	def create_rawtx(self):
		pass

	def extract_rs(self, sig):
		r_p = int(sig[6:8], 16) * 2 + 8
		r = sig[8:r_p]
		s_p = int(sig[2+r_p:4+r_p], 16) * 2 + 12
		s = sig[s_p:r_p+s_p]
		return int(r, 16), int(s, 16)

	def verify(self, msg, sig):
		vk = self._load_key()
		return vk.verify(sig, msg, sigdecode=ecdsa.util.sigdecode_der)

	def locktime(self, locktime):
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


if __name__ == '__main__':
	txid_ = tolittle_endian("01000000")
	print(txid_)
	tx = Transaction(key = 1, tx_unspent = 1, addr="133", coin=1)
	print(tx.__dict__)