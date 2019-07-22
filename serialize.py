import hashlib

from Base58 import check_decode, check_encode
from segwit_addr import decode, encode
from func import tolittle_endian, tobig_endian, dsha256
from opcodes import OPCODE_DICT
from sighash import SIGHASH
from binascii import hexlify as _hexlify
from hashlib import sha256

_hex = lambda x: hex()[2:]
hexlify = lambda x: _hexlify(x).decode()

# ordinary scriptPubKey
def P2SH(script, otherplaces = False):
	strx = lambda x: "a914{}87".format(x)
	if script[0] in ["2","3"]:
		# same operation to P2WSH-P2SH/P2WPKH-P2SH
		return  strx(hexlify(check_decode(script)))

	if len(script) == 66 and not otherplaces:
		return  strx(hashlib.new('ripemd160', sha256(bytes.fromhex(script)).digest()).hexdigest())

def P2PKH(value):
	strx = lambda x: "76a914{}88ac".format(x)
	if value[0] in ["1", "m"]:
		return strx(hexlify(check_decode(value)))

	return strx(hashlib.new('ripemd160', sha256(bytes.fromhex(value)).digest()).hexdigest())

# witness scriptPubKey
def P2WPKHoP2SH(pk):

	check = P2SH(pk, True)
	if check:
		return check

	pk_hash = hashlib.new('ripemd160', sha256(bytes.fromhex(pk)).digest()).digest()
	push_20 = bytes.fromhex('0014')
	redeemscript = push_20 + pk_hash
	scriptPubKey =  hashlib.new('ripemd160', sha256(redeemscript).digest()).hexdigest()
	return hexlify(redeemscript), "a914" + scriptPubKey + "87"

def P2WSH(witnessScript):
	# witnessScript for P2WSH is special, be careful.
	dec = None
	
	if witnessScript.startswith("bc"):
		dec = decode("bc", witnessScript)

	elif witnessScript.startswith("tb"):
		dec = decode("tb", witnessScript)

	if dec:
		return hexlify(bytes.fromhex('0020') + bytes(dec[1]))

	pk_added_code = bytes.fromhex('0020') + sha256(bytes.fromhex(witnessScript)).digest()
	return hexlify(pk_added_code)

def P2WSHoP2SH(witnessScript):

	check = P2SH(witnessScript, True)
	if check:
		return check

	redeemScript = bytes.fromhex("0020") + sha256(bytes.fromhex(witnessScript)).digest()
	scriptPubKey = hashlib.new("ripemd160",  sha256(redeemScript).digest()).hexdigest()
	return hexlify(redeemScript), "a914" + scriptPubKey + "87"

def P2WPKH(value):
	dec = None

	if value.startswith("bc"):
		dec = decode("bc", value)

	elif value.startswith("tb"):
		dec = decode("tb", value)

	if dec:
		return hexlify(bytes.fromhex('0014') + bytes(dec[1]))

	pk_added_code = bytes.fromhex('0014') + hashlib.new("ripemd", sha256(bytes.fromhex(value)).digest()).digest()
	return hexlify(pk_added_code)

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
	def Script(self, script, addr_type = P2WPKH):

		addr_type = addr_type.upper()

		if len(script) >= 34:
			head = script[0]
		else:
			raise RuntimeError("Are you should it is your address? Its length less than 34")

		if head in ["1","3","b", # mainnet
					"m","2","t", # testnet
					"0","5" # public key or MoNscript
				   ]:
			return addr_type(script)

		else:
			raise RuntimeError("Only supported bitcoin mainnet(testnet) address")

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



if __name__ == '__main__':

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Native_P2WPKH
	key = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
	assert P2WPKH(key) == "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1" # scriptPubKey 

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
	key = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
	redeemscript, scriptPubKey = P2WPKHoP2SH(key)
	assert redeemscript == "001479091972186c449eb1ded22b78e40d009bdf0089"
	assert scriptPubKey == "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"

	key = "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
	assert P2WSH(key) == "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"

	key = "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
	redeemScript, scriptPubKey = P2WSHoP2SH(key)
	assert redeemScript == "0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
	assert scriptPubKey == "a9149993a429037b5d912407a71c252019287b8d27a587"

	key = "039e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46"
	assert P2PKH(key) == "76a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac"


	assert P2WPKHoP2SH("39wSTzCS9BiwF3Vci1tGXwyDXa1LReG9Jc") == "a9145a7b51041e3f0959db7783c097f278dd139ce43687"
	assert P2WSHoP2SH("3JXRVxhrk2o9f4w3cQchBLwUeegJBj6BEp")  == "a914b8a9a8ba8cf965b7df6b05afd948e53c351b2c0d87"
	# assert P2SH() They base on P2SH function, so pass
	assert P2PKH("1LBDY5Sugh4i2XS6StMKA1ZZiyN4a59Sdf") == "76a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac"
	
	
	assert P2WPKH("tb1qm3e067l5aadlmr07qg05rudd05m3vmw2606rzj") == "0014dc72fd7bf4ef5bfd8dfe021f41f1ad7d37166dca"
	'''
	assert P2WSH()
	'''