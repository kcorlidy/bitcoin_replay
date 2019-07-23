import hashlib
import warnings
import re

from Base58 import check_decode, check_encode
from segwit_addr import decode, encode
from func import tolittle_endian, tobig_endian, dsha256
from opcodes import OPCODE_DICT
from sighash import SIGHASH
from binascii import hexlify as _hexlify
from hashlib import sha256
from functools import partial
from collections import OrderedDict
from json import dumps, loads

_hex = lambda x: hex(int(x))[2:]
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
		self.inputs = inputs
		self.outputs = ouputs
		self.locktime = tolittle_endian(locktime)
		self.seq = tolittle_endian(seq)

	@classmethod
	def MoNscript(self, m, n, publickeylist):
		
		if isinstance(publickeylist, list) or isinstance(publickeylist, tuple) \
			and (isinstance(m, int) and isinstance(n) and m <= n and n >= 2 and m >= 1) \
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
			raise NotImplementedError("Can not handle your input. Condition: n >= 2, m >=1, m <= n, length(publickeylist) == n")

		return hexlify(b"".join(start)).decode()



	def check_inputs(self):
		"""
			address
			address_type(option) P2SH P2SH(P2WSH) P2SH(P2WPKH) P2PKH P2WSH P2WPKH
			redeemscript(option, multisig, redeemscript and mon must have one)
			mon(option, for multisig, tuple)
			:pubkey list:
			:prikey(option):
			locktime(option)
			sequence(option)
			prev_txid
			prev_vout
		"""
		for _input in self.inputs:
			locktime = _input.get("locktime")
			self.locktime = tolittle_endian(locktime) if locktime and locktime > 0 and isinstance(locktime, int) else self.locktime

			sequence = _input.get("sequence")
			self.seq = tolittle_endian(sequence) if sequence and sequence > 0 and isinstance(sequence, int) else self.seq
				
			prev_txid, prev_vout = _input.get("prev_txid"), _input.get("prev_vout")
			if prev_txid and prev_vout and isinstance(prev_vout, int) and len(prev_txid) == 64:
				_input["prev_txid"] = tolittle_endian(prev_txid)
				_input["prev_vout"] = tolittle_endian(prev_vout, 2)
			else:
				print(prev_txid, prev_vout)
				raise RuntimeError(":prev_txid string 32bytes: :prev_vout int:")

			pubkey = _input.get("pubkey")
			redeemscript = _input.get("redeemscript")
			mon = _input.get("mon")
			
			if not pubkey or not isinstance(pubkey, list):
				raise RuntimeError("pubkey is necessary. And it must be in a list")

			elif len(pubkey) > 1 and not redeemscript:

				if not isinstance(mon, tuple):	
					raise RuntimeError("redeemscript is necessary when using multisig")

				elif mon[0] <= mon[1] and mon[1] > 2:
					_input["redeemscript"] == self.MoNscript(mon[0], mon[1], pubkey)

			elif len(pubkey) == 1 and redeemscript:
				warnings.warn("redeemscript should not exit when using single signature", RuntimeError)
			
			elif len(pubkey) == 1 and mon:
				warnings.warn("mon should not exit when using single signature", RuntimeError)
			
			address = _input.get("address")
			if not address or not isinstance(address, str):
				raise RuntimeError("address is necessary. And it must be a string")

			elif not _input.get("address_type"):
				# analysis what kind of address it is.

				if re.findall(r"^[3,2]", address) and len(pubkey) > 1:
					# P2SH or P2SH(P2WSH)
					if not redeemscript:
						warnings.warn("P2SH or P2SH(P2WSH), not sure, but has set to P2SH(P2WSH)[default]")
					
					elif re.findall(r"^(0020)", redeemscript):
						_input["address_type"] = "P2SH(P2WSH)"

					else:
						_input["address_type"] = "P2SH"

				elif re.findall(r"^[3,2]", address) and len(pubkey) == 1:
					# P2SH(P2WPKH)
					_input["address_type"] = "P2SH(P2WPKH)"

				elif re.findall(r"^[1,m]", address):
					# P2PKH
					_input["address_type"] = "P2PKH"

				elif re.findall(r"^(bc|tb)", address) and len(pubkey) > 1:
					# P2WSH
					_input["address_type"] = "P2WSH"

				elif re.findall(r"^(bc|tb)", address) and len(pubkey) == 1:
					# P2WPKH
					_input["address_type"] = "P2WPKH"

		return True

	def check_outputs(self):
		"""
			:address str:
			:amount int:
		"""
		for _output in self.outputs:

			address = _output.get("address")
			amount = _output.get("amount")

			if amount < 0:
				raise RuntimeError("amount can not be negative")

			if not address:
				raise RuntimeError("Address can not be empty")

			elif re.findall(r"^[3,2]", address):
				_output["scriptpubkey"] = P2SH(address)

			elif re.findall(r"^[1,m]", address):
				_output["scriptpubkey"] = P2PKH(address)

			elif re.findall(r"^(bc|tb)", address) and len(address) == 42:
				_output["scriptpubkey"] = P2WPKH(address)

			elif re.findall(r"^(bc|tb)", address) and len(address) == 42:
				_output["scriptpubkey"] = P2WSH(address)

		return True

	def createrawtransaction(self):

		if not (self.check_inputs() and self.check_outputs()):
			# check input and output, if failed, over.
			return

	
		hex_input = ""

		vin_count = tolittle_endian(len(self.inputs), 2)
		hex_input += vin_count

		for num, input_ in enumerate(self.inputs):
			prev_txid = input_.get("prev_txid")
			prev_vout = input_.get("prev_vout")

			# script_length, signature, sighash_type, pubkey
			script_blank = "{%s}"%num
			sequence = self.seq

			hex_input += prev_txid +  prev_vout  + script_blank + sequence
		
		hex_output = ""

		vout_count = tolittle_endian(len(self.outputs), 2)
		hex_output += vin_count

		for output_ in self.outputs:
			amount = tolittle_endian(output_.get("amount"), 16)
			scriptpubkey = output_.get("scriptpubkey")

			hex_output += amount + _hex(len(scriptpubkey)/2) + scriptpubkey

		return self.ver + hex_input + hex_output + self.locktime

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

	@classmethod
	def json(self, txhex):
		if txhex[8:12] == "0001":
			raise RuntimeError("Don't support witness transaction for now.")

		version = txhex[:8]
		locktime = txhex[-8:]
		txhex = txhex[8:-8]

		vin_count = txhex[:2]
		txhex = txhex[2:]

		inputs = []
		for _ in range(int(vin_count)):
			__input = OrderedDict()
			__input["prev_txid"] = txhex[:64]
			__input["prev_vout"] = txhex[64:72]
			__input["script_length"] = txhex[72:74]
			l = 74 + int(__input["script_length"], 16) * 2
			__input["script"] = txhex[74:l]
			__input["sequence"] = txhex[l:l+8]
			inputs.append(__input)
			txhex = txhex[l+8:]

		vout_count = txhex[:2]
		txhex = txhex[2:]
		outputs = []
		for _ in range(int(vout_count)):
			__output = OrderedDict()
			__output["amount"] = txhex[:16]
			__output["script_length"] = txhex[16:18]
			l = 18 + int(__output["script_length"], 16) * 2
			__output["scriptpubkey"] = txhex[18:l]
			outputs.append(__output)
			txhex = txhex[l:]

		tx_json = OrderedDict(
			version = version,
			vin_count = vin_count,
			vin = inputs,
			vout_count = vout_count,
			vout = outputs,
			locktime = locktime

		)

		return dumps(tx_json,  indent = 4)


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


	def embed_witness(self):
		pass

	@classmethod
	def createScriptPubkey(self, value, addr_type):
		result = super().Script(value, addr_type)
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
	inputs = [{ "address":"tb1qm3e067l5aadlmr07qg05rudd05m3vmw2606rzj",
				"pubkey":["039e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46"],
				"prev_txid":"9e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46",
				"prev_vout":1}]
	outputs = [{"address":"tb1qm3e067l5aadlmr07qg05rudd05m3vmw2606rzj","amount":1}]
	tx_ = tx(inputs, outputs)
	tx_raw = tx_.createrawtransaction()
	
	
	# print(tx.json("02000000010cefbc7f0250945ba8888328486167ee83cde1a2e40ed27b780dde2e692219d3000000006a4730440220324b3acd694df487710c46096e7f49ed09c275ae536be2f8bb9dd0a0d9a60da10220194c898879d63b5c8e3930de7070831acd99e871614ddbc08958d57f17936ecf012103a9ef51cecb3c2066e394b5ac4671ef3cae9a45032dcfc6903e4df8a783037dd8feffffff0264f700000000000017a9146141931080ebc9461d52f3ce9ea54a7f35bec2278750ea3800000000001976a914d259038d23c4a8f9dd4eaaf92316d191f18d963788ac18f00800"))