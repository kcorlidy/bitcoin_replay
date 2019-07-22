from func import tolittle_endian, tobig_endian, dsha256
from opcodes import OPCODE_DICT
from sighash import SIGHASH
from binascii import hexlify
import hashlib

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
		
		if isinstance(publickeylist, list) or isinstance(publickeylist, tuple) \
			and (isinstance(m, int) and isinstance(n) and m <= n and m >= 2) \
			and len(publickeylist) == n:
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
	def redeemscript(self, script, addr_type):

		addr_type = addr_type.upper()

		if len(script) >= 34:
			head = script[0]
		else:
			raise RuntimeError("Are you should it is your address? Its length less than 34")

		if head in ["0", "5"]:
			# public key or MoNscript
		
			if addr_type == "P2SH":
				redeemscript = pkh = hashlib.new('ripemd160', sha256(bytes.fromhex(script)
					).digest()).digest()

			elif addr_type == "P2WSH":
				redeemscript = bytes.fromhex('0014') + sha256(b"\x21" + script + b"\xac").digest()

			elif addr_type == "P2WSH-P2SH":
				redeemscript = bytes.fromhex("0020") + sha256(script).digest()
				redeemscript = hashlib.new("ripemd160",  sha256(redeemscript).digest()).digest()

			return hexlify(redeemscript)

		elif head in ["1","m","2","3","b","t"]:
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


# scriptPubKey
def P2WPKHoP2SHAddress(pk, testnet = False):
	pk_hash = hashlib.new('ripemd160', sha256(pk).digest()).digest()
	push_20 = bytes.fromhex('0014')
	script_sig = push_20 + pk_hash
	return hexlify(script_sig)

def P2WSH(pk, testnet = False):
	pk_added_code = bytes.fromhex('0020') + sha256(pk).digest()
	return hexlify(pk_added_code)

def P2WSHoP2SHAddress(witnessScript, testnet = False):
	prefix = b"\xc4" if testnet else b"\x05"
	redeemScript = bytes.fromhex("0020") + sha256(witnessScript).digest()
	scriptPubKey = hashlib.new("ripemd160",  sha256(redeemScript).digest()).digest()
	return hexlify(redeemScript), hexlify(scriptPubKey)

def P2WPKH(pk, testnet = False):
	pk_added_code = bytes.fromhex('0014') + hashlib.new("ripemd", sha256(pk).digest()).digest()
	return hexlify(pk_added_code)


if __name__ == '__main__':

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Native_P2WPKH
	key = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
	assert P2WPKH(bytes.fromhex(key)) == b"00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1" # scriptPubKey 

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
	key = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
	assert P2WPKHoP2SHAddress(bytes.fromhex(key)) == b"001479091972186c449eb1ded22b78e40d009bdf0089" # redeemScript 

	key = "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
	assert P2WSH(bytes.fromhex(key)) == b"00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"

	key = "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
	redeemScript, scriptPubKey = P2WSHoP2SHAddress(bytes.fromhex(key))
	assert redeemScript == b"0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
	assert b"a914" + scriptPubKey + b"87" == b"a9149993a429037b5d912407a71c252019287b8d27a587"
