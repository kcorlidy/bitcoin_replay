import hashlib
import warnings
import re

try:
	# normal
	from Base58 import check_decode, check_encode
	from segwit_addr import decode, encode
	from func import tolittle_endian, tobig_endian, dsha256
	from opcodes import OPCODE_DICT
	from sighash import SIGHASH
	from address import P2WSHoP2SHAddress
	

except:
	# for other module
	from .Base58 import check_decode, check_encode
	from .segwit_addr import decode, encode
	from .func import tolittle_endian, tobig_endian, dsha256
	from .opcodes import OPCODE_DICT
	from .sighash import SIGHASH
	from .address import P2WSHoP2SHAddress
	

from binascii import hexlify as _hexlify
from hashlib import sha256
from functools import partial
from collections import OrderedDict
from json import dumps, loads
from pprint import pprint


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

	if len(pk) < 66:
		check = P2SH(pk, True)
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

	if len(witnessScript) < 42:
		check = P2SH(witnessScript, True)
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



def tohex(order_dict):

	_hex = ""
	witness = ""

	for k, v in order_dict.items():
		if k == "locktime":
			break

		if k in ["vin", "vout"]:
			for x in v:
				for kv, vv in x.items():
					# witness is the second last
					if kv == "txwitness":
						witness += vv
					else:
						_hex += vv
		else:
			_hex += v

	_hex = _hex + witness + order_dict.get("locktime")
	return _hex


def txid(txhex):
	"""
		return txid, wtxid
	"""
	# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-id
	if txhex.find("0001") == 8:
		# witness
		wtxid = hexlify(dsha256(txhex))

		_dict = loads(witness_tx.decoderawtransaction(txhex), object_pairs_hook = OrderedDict)
		_dict["maker"] = ""
		_dict["flag"] = ""

		for v in _dict.get("vin"):
			if v.get("txwitness"):
				v["txwitness"] = ""

		txid = hexlify(dsha256(tohex(_dict)))

	else:
		txid = wtxid = hexlify(dsha256(txhex))
	
	return tolittle_endian(txid), tolittle_endian(wtxid)



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

		return hexlify(b"".join(start))



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
			if prev_txid != None and prev_vout != None and isinstance(prev_vout, int) and len(prev_txid) == 64:
				_input["prev_txid"] = tolittle_endian(prev_txid)
				_input["prev_vout"] = tolittle_endian(prev_vout, 8)
			else:
				print(prev_txid, prev_vout,len(prev_txid) == 64)
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
					_input["redeemscript"] = self.MoNscript(mon[0], mon[1], pubkey)

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

						check_redeemscript_again = _input.get("redeemscript")

						if check_redeemscript_again and P2WSHoP2SHAddress(bytes.fromhex(check_redeemscript_again)) == _input["address"]:
							_input["address_type"] = P2WSHoP2SH

						elif check_redeemscript_again:
							_input["address_type"] = P2SH

						else:
							_input["address_type"] = P2WSHoP2SH
							warnings.warn("P2SH or P2SH(P2WSH), not sure, but has set to P2SH(P2WSH)[default]")
						
					elif re.findall(r"^(0020)", redeemscript):
						_input["address_type"] = P2WSHoP2SH

					else:
						_input["address_type"] = P2SH

				elif re.findall(r"^[3,2]", address) and len(pubkey) == 1:
					# P2SH(P2WPKH)
					_input["address_type"] = P2WPKHoP2SH

				elif re.findall(r"^[1,m]", address):
					# P2PKH
					_input["address_type"] = P2PKH

				elif re.findall(r"^(bc|tb)", address) and len(pubkey) > 1:
					# P2WSH
					_input["address_type"] = P2WSH

				elif re.findall(r"^(bc|tb)", address) and len(pubkey) == 1:
					# P2WPKH
					_input["address_type"] = P2WPKH

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

			elif re.findall(r"^(bc|tb)", address) and len(address) > 42:
				_output["scriptpubkey"] = P2WSH(address)

		return True

	def createrawtransaction(self, withmark = True):
		
		# raise RuntimeError("can not handle multisig yet")
		
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
			script_blank = "{%s_%s}"%(input_.get("address"), prev_txid)
			sequence = self.seq

			hex_input += prev_txid +  prev_vout  + script_blank + sequence
		
		hex_output = ""

		vout_count = tolittle_endian(len(self.outputs), 2)
		hex_output += vout_count

		for output_ in self.outputs:
			amount = tolittle_endian(output_.get("amount"), 16)
			scriptpubkey = output_.get("scriptpubkey")

			hex_output += amount + _hex(len(scriptpubkey)/2) + scriptpubkey

		txhex = self.ver + hex_input + hex_output + self.locktime

		if withmark:
			return txhex
		
		return re.sub(r"{.*?}", "{}", txhex).format(*(["00"]*int(vin_count)))


	def scriptlength(self, value):
		value = int(len(value) / 2)
		if 0 < value <= int("fc", 16):
			return _hex(value)

		else:
			return "fd" + tolittle_endian(_hex(value + 1)) + "00" # 1bytes for OP_0(00)

	@classmethod
	def embed_scriptsig(self, info, tx):
		"""
			:info: [{"address":string, "prev_txid":string, "signature":[], "pubkey":[], "mon":[m,n], "redeemscript":string},]
		"""
		for ss in info:
			signature = ss.get("address")
			pubkey = ss.get("pubkey")
			redeemscript = ss.get("redeemscript")
			mon = ss.get("mon")
			if len(pubkey) > 1 or redeemscript:
				# multisig
				try:
					mon = self.MoNscript(mon[0], mon[1], pubkey) if not redeemscript else redeemscript
				except:
					raise RuntimeError('mon or redeemscript parameter is necessary for multisig, :info: [{"address":string, "prev_txid":string, "signature":[], "pubkey":[], "mon":[m,n], "redeemscript":string},]')
				sig = "".join(signature + [self.scriptlength(mon)] + [mon])
				sig = self.scriptlength(sig) + sig

			elif len(pubkey) == 1:
				sig = signature[0] + self.scriptlength(pubkey[0]) + pubkey
				sig = self.scriptlength(sig) + sig

			tx.format(**{"{}_{}".format(ss.get("address"), ss.get("prev_txid")):sig})

		return tx


	@classmethod
	def decoderawtransaction(self, txhex, rev = False):

		if txhex[8:12] == "0001":
			raise RuntimeError("Don't support witness transaction for now.")

		if rev:
			f = tolittle_endian
		else:
			f = lambda x: x

		version = txhex[:8]
		locktime = txhex[-8:]
		txhex = txhex[8:-8]

		vin_count = txhex[:2]
		txhex = txhex[2:]

		inputs = []
		for _ in range(int(vin_count, 16)):
			__input = OrderedDict()
			__input["prev_txid"] = f(txhex[:64])
			__input["prev_vout"] = f(txhex[64:72])
			txhex = txhex[72:]
			
			# fd + 2bytes length if length > fc. fdfd00 -> length = fd
			# sl -> script length
			if re.findall(r"^fd\w+", txhex):
				__input["script_length"] = txhex[:6]
				sl = int(tolittle_endian(__input["script_length"][2:]), 16) * 2

			else:
				__input["script_length"] = txhex[:2]
				sl = int(__input["script_length"], 16) * 2

			# the length of script_length
			sll = len(__input["script_length"])
			

			if sl >= 20000:
				print(__input["script_length"])
				raise RuntimeError("script length is too long")

			__input["script"] = txhex[sll:sll+sl]
			
			l = sll+sl
		
			__input["sequence"] = txhex[l:l+8]
			inputs.append(__input)
			txhex = txhex[l+8:]

		vout_count = txhex[:2]
		txhex = txhex[2:]
		outputs = []
		for _ in range(int(vout_count, 16)):
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

	def __init__(self, inputs, ouputs, witness = None, maker = 0, flag = 1, **kw):
		super(witness_tx, self).__init__(inputs, ouputs, **kw)
		self.maker = tolittle_endian(maker, 2)
		self.flag = tolittle_endian(flag, 2)
		self.witness = witness

	@classmethod
	def createscript(self, value):
		func_ = value.get("address_type")
		s = value.get("redeemscript") if value.get("redeemscript") else value.get("pubkey")[0]
		s = func_(s)
		return s if not isinstance(s, tuple) else s[0]

	def createrawtransaction(self, addscript = True, withmark = True):
		"""
			:addscript bool: For witness input, you can choose dont add input script(i.e. 0014dc72fd7bf4ef5bfd8dfe021f41f1ad7d37166dca)
		"""
		
		if not (self.check_inputs() and self.check_outputs()):
			# check input and output, if failed, over.
			return
	
		hex_input = ""
		witness_blank = ""
		vin_count = tolittle_endian(len(self.inputs), 2)
		hex_input += vin_count
		
		for _, input_ in enumerate(self.inputs):
			prev_txid = input_.get("prev_txid")
			prev_vout = input_.get("prev_vout")

			# script_length, signature, sighash_type, pubkey
			script = self.createscript(input_)

			if script and addscript:
				for _ in range(2):
					# double length for witness input script
					script = _hex(len(script)/2) + script
			else:
				script = "00"

			sequence = self.seq

			if input_.get("address_type") in [P2SH, P2PKH]:
				script_blank = "{%s_%s}"%(input_.get("address"),prev_txid)
				hex_input += prev_txid +  prev_vout  + script_blank + sequence
				witness_blank += "00"

			else:
				witness_blank += "{%s_%s}"%(input_.get("address"), prev_txid)
				hex_input += prev_txid +  prev_vout  + script + sequence
				
		
		hex_output = ""

		vout_count = tolittle_endian(len(self.outputs), 2)
		hex_output += vout_count

		for output_ in self.outputs:
			amount = tolittle_endian(output_.get("amount"), 16)
			scriptpubkey = output_.get("scriptpubkey")

			hex_output += amount + _hex(len(scriptpubkey)/2) + scriptpubkey

		
		txhex = self.ver + self.maker + self.flag + hex_input + hex_output + witness_blank + self.locktime
		
		if withmark:
			return txhex
		
		return re.sub(r"{.*?}", "{}", txhex).format(*(["00"]*int(vin_count)))


	def embed_witness(self, info, tx):
		"""
			:info: [{"address":string, "prev_txid":string, "signature":[], "pubkey":[], "mon":[m,n], "redeemscript":string},]
		"""

		# the difference between ordinary transaction and witness transaction is 
		# 	1. witness count
		#	2. length of whole script(not exist in witness)
		#	3. OP_0(necessary for multisig)
		for ss in info:
			witness_count = ""
			signature = ss.get("address")
			pubkey = ss.get("pubkey")
			redeemscript = ss.get("redeemscript")
			mon = ss.get("mon")

			if len(pubkey) > 1 or redeemscript:
				# multisig
				try:
					mon = self.MoNscript(mon[0], mon[1], pubkey) if not redeemscript else redeemscript
				except:
					raise RuntimeError('mon or redeemscript parameter is necessary for multisig, :info: [{"address":string, "prev_txid":string, "signature":[], "pubkey":[], "mon":[m,n], "redeemscript":string},]')
				
				witness_count = 1 + len(signature) + 1 # OP_0 + number of signature + script

				sig = "".join(signature + [self.scriptlength(mon)] + [mon])
				sig = _hex(witness_count) + OPCODE_DICT.get("OP_0") + sig

			elif len(pubkey) == 1:

				sig = signature[0] + self.scriptlength(pubkey[0]) + pubkey
				sig = "02" + sig

			tx.format(**{"{}_{}".format(ss.get("address"), ss.get("prev_txid")):sig})

		return tx


	@classmethod
	def decoderawtransaction(self, txhex, rev = False):

		if not txhex[8:12] == "0001":
			raise RuntimeError("This is not witness transaction")

		if rev:
			f = tolittle_endian
		else:
			f = lambda x: x

		version = txhex[:8]
		maker = txhex[8:10]
		flag = txhex[10:12]
		locktime = txhex[-8:]
		txhex = txhex[12:-8]

		vin_count = txhex[:2]
		txhex = txhex[2:]

		inputs = []
		for _ in range(int(vin_count, 16)):
			__input = OrderedDict()
			__input["prev_txid"] = f(txhex[:64])
			__input["prev_vout"] = f(txhex[64:72])
			txhex = txhex[72:]
			
			# fd + 2bytes length if length > fc. fdfd00 -> length = fd
			# sl -> script length
			if re.findall(r"^fd\w+", txhex):
				__input["script_length"] = txhex[:6]
				sl = int(tolittle_endian(__input["script_length"][2:]), 16) * 2

			else:
				__input["script_length"] = txhex[:2]
				sl = int(__input["script_length"], 16) * 2

			# the length of script_length
			sll = len(__input["script_length"])
			

			if sl >= 20000:
				print(__input["script_length"])
				raise RuntimeError("script length is too long")

			__input["script"] = txhex[sll:sll+sl]

			if 0 <= sl < 134:
				# just scriptpubkey or empty, only witness can do that
				__input["txwitness"] = 1
			
			l = sll+sl
		
			__input["sequence"] = txhex[l:l+8]
			inputs.append(__input)
			txhex = txhex[l+8:]

		vout_count = txhex[:2]
		txhex = txhex[2:]
		outputs = []
		for _ in range(int(vout_count, 16)):
			__output = OrderedDict()
			__output["amount"] = txhex[:16]
			__output["script_length"] = txhex[16:18]
			l = 18 + int(__output["script_length"], 16) * 2
			__output["scriptpubkey"] = txhex[18:l]
			outputs.append(__output)
			txhex = txhex[l:]


		txwitness = []
		for _ in range(int(vin_count, 16)):
			witness_list = []
			witness_count = txhex[:2]

			if not txhex:
				# vin count <= witness count
				break
			
			witness_count_int = int(witness_count, 16)
			
			if witness_count_int > 2:
				# multisig
				OP_0 = txhex[2:4] # necessary

				if int(OP_0, 16) == 0:

					txhex = txhex[4:]
					witness_list.append(OP_0)
					witness_count_int -= 1

				else:
					# no OP_0
					txhex = txhex[2:]

			elif witness_count_int == 0:
				# Placeholder, watch dfb40fbf72c8fa9b11c67ba24f12bc48ba2a26f08bd709a3a11ca9ae30323a3f.test_tx
				txhex = txhex[2:]
				continue

			elif witness_count_int == 2:
				# one sig
				txhex = txhex[2:]

			for _ in range(witness_count_int):
				length_int = int(txhex[:2], 16) * 2
				witness_list.append(txhex[2: length_int + 2])
				txhex = txhex[length_int + 2:]

			txwitness.append(witness_list)
		
		txwitness = txwitness[::-1]

		for inp in inputs:
			if inp.get("txwitness"):
				inp["txwitness"] = txwitness[-1]
				txwitness.pop()

		tx_json = OrderedDict(
			version = version,
			maker = maker,
			flag = flag,
			vin_count = vin_count,
			vin = inputs,
			vout_count = vout_count,
			vout = outputs,
			locktime = locktime

		)

		return dumps(tx_json,  indent = 4)



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
	
	# Data from 9988eaabbcf5976d13f91c28604f921239ed3fadf4592d1a0a0e288b419a78a4
	key = "5221035c8e83fa4ca1d74d10f122daaac69b006e5c02a1594b78907881190500b1f22a2102c1235301c06e94bdd44c248e6c824b58fafea3ceee4db2857402e322486046842103e46359fd20b25a7be466984f156084be0dead32e4e99cec2e0f7c9ad4863daaa53ae"
	assert P2WSH(key) == "0020d3124de88d90949cf90ed655bfd306f00d9473387eedc59d819d51bc6880f29d"
	assert P2WSH("bc1qm2pz5342a0n3ctv9hm6s568zeye8cw7j90j0nmjdwkrcy78qs2nsfyp945") == "0020da822a46aaebe71c2d85bef50a68e2c9327c3bd22be4f9ee4d75878278e082a7"
	
	
	# Data from , ordinary only
	inputs = [{ "address":"tb1qm3e067l5aadlmr07qg05rudd05m3vmw2606rzj",
				"pubkey":["039e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46"],
				"prev_txid":"9e84846f40570adc5cef6904e10d9f5a5dadb9f2afd07cc9aad188d769c50b46",
				"prev_vout":1}]
	outputs = [{"address":"tb1qm3e067l5aadlmr07qg05rudd05m3vmw2606rzj","amount":1}]
	tx_ = tx(inputs, outputs)
	tx_raw = tx_.createrawtransaction()
	
	# Data from ef7c7e3beafa9246f7454f457d75abf1f86606f8ceeb41877a5729dc659dfb74, witness only
	inputs = [{ "address":"3JXRVxhrk2o9f4w3cQchBLwUeegJBj6BEp",
				"pubkey":[	"029103d1dfbbee9ea5249ee0b03ca59e08291ce34a7467513edf8ea767b5aa2638",
							"03dce07bea5905a1c3e70f86c1f74f0e98e7cf3b6f5d02226a4c531c9e930c613b",
							"0268d8878afaf4b55118519d8520fe0db27f9596a812d4378f4bf4a96a53336946"],
				"prev_txid":"2b00918a833e5307ced62aa173b71f4120b0a691e71ae8bbc2e7e3408fb161fe",
				"prev_vout":3,
				"mon":(2,3)
				}] 
	outputs = [{"address":"3JXRVxhrk2o9f4w3cQchBLwUeegJBj6BEp","amount":146647479},
			   {"address":"1FAWNMVNxmDeuCRtTex79B5S3fsXXgv1Ja","amount":13197062}]
	tx_w = witness_tx(inputs, outputs)
	txw_raw = tx_w.createrawtransaction()
	
	
	# Data from dfb40fbf72c8fa9b11c67ba24f12bc48ba2a26f08bd709a3a11ca9ae30323a3f, witness&ordinary
	inputs = [{ "address":"1JpnBJzJWVam7hNJkfEPFeiXwLY6bKSbM7",
				"pubkey":["02317bd8bc51fecce3c5a2cf9fad735f2ca3bfc4045799994a43047930a12859e0"],
				"prev_txid":"7659a91704549b69e065238afc271acfc1f1f55bcfa1a31f0469a1e3262e1648",
				"prev_vout":0,
				},
				{ "address":"1JpnBJzJWVam7hNJkfEPFeiXwLY6bKSbM7",
				"pubkey":["02317bd8bc51fecce3c5a2cf9fad735f2ca3bfc4045799994a43047930a12859e0"],
				"prev_txid":"d5f2766f0dee62f0baaab07d4391b4ffddb282aad3958a1abc5497f7d5c1015c",
				"prev_vout":0,
				},
				{ "address":"3KBqs8ftE4dZf2geVjRcMYYzbNCLnVQycZ",
				"pubkey":["022c1b3031488e827d6f7a7ebab8fc1cf4fc1b987dce2fa8b601e0557672646a68"],
				"prev_txid":"f11b134f35a7cb975586fe196774ee74ecdd777d7d441fd1bc87c365abaef1b0",
				"prev_vout":1,
				},
				{ "address":"1JpnBJzJWVam7hNJkfEPFeiXwLY6bKSbM7",
				"pubkey":["02317bd8bc51fecce3c5a2cf9fad735f2ca3bfc4045799994a43047930a12859e0"],
				"prev_txid":"ddb8caa41353710ee04920c799e118bddd05c344f80ba4b91b222f807217b9f4",
				"prev_vout":0,
				},
				{ "address":"1JpnBJzJWVam7hNJkfEPFeiXwLY6bKSbM7",
				"pubkey":["02317bd8bc51fecce3c5a2cf9fad735f2ca3bfc4045799994a43047930a12859e0"],
				"prev_txid":"705c67143d459416c0616e7d04f1d5c00a4e85e14e6abbf30728409bf9e9a0ef",
				"prev_vout":0,
				},
				{ "address":"1JpnBJzJWVam7hNJkfEPFeiXwLY6bKSbM7",
				"pubkey":["02317bd8bc51fecce3c5a2cf9fad735f2ca3bfc4045799994a43047930a12859e0"],
				"prev_txid":"c67bb5545508b8ae4e086be247078b95e07269028caf43acfd00c976d9cbca50",
				"prev_vout":1,
				},
				{ "address":"1JpnBJzJWVam7hNJkfEPFeiXwLY6bKSbM7",
				"pubkey":["02317bd8bc51fecce3c5a2cf9fad735f2ca3bfc4045799994a43047930a12859e0"],
				"prev_txid":"447ff11ee08282bf0d522ca9443a0ebc394900ad50771a5890ea895887f39b9b",
				"prev_vout":0,
				},
				{ "address":"1JpnBJzJWVam7hNJkfEPFeiXwLY6bKSbM7",
				"pubkey":["02317bd8bc51fecce3c5a2cf9fad735f2ca3bfc4045799994a43047930a12859e0"],
				"prev_txid":"7045171ea26be06472a4e99d48e23766371198a19bdcd293920505c6c9db95a2",
				"prev_vout":0,
				}] 
	outputs = [{"address":"3GTzAhunoaoTLEAw96sdbF6Cov6SEEKj96","amount":17730000},
			   {"address":"38Se3yi7qJt36747ZtLJDFKcVN6G1nPrGw","amount":35642}]
	tx_w = witness_tx(inputs, outputs, locktime = 586805)
	txw_raw_wo = tx_w.createrawtransaction(withmark = False)
	
	_hex_ = "0100000000010bc5f6f209d947f0e4073f72b39a2d87a5f647567274f26eba2148a89feb35fa070000000000ffffffffd221e27a511238536a18a26f99739701300b4e31bbb2ea7538853730e193761200000000232200201260248fb98785dab7a5699958707ad20ea1ba1c04d866d02c6c3b64e8656e4affffffffc9b13a1a560e1621f296e0fa9a7d8c81786c07c1e17650e527aed1871d7fc32d0000000000ffffffff056f552f3966cbe46fc7915a1c47c5bc60c6a5e8bf5716e1f94ad24022d665370100000023220020868c3cdd51a2b6d73b3ef3a71b49fb4b0ef9234545706cfa78247503a70945f5ffffffff4f6684a04ba51a4df9a95b2b5c4f127b4c236036836e79c6c17e4529353377660400000023220020ed3443231e4c9b6ea97713dc06820f42a3f7b03d2a04d8f885ef6e17d1d0ec5fffffffff93593d54ac63d32f2bbb69ff800b8fd715e19cb9cebeacaa1d9a7be83293b46c0100000023220020378e6c2956eabc503de0ad7ca7cd0a0c06ba0ee92c96d0ed0639046ac1138705ffffffff81331ed8b31aa67ad87d4ae941369ac6099c22c530fe4c439f1bab5dae25c3700000000023220020dbd6c71abad6d637c06febb25c753ad039271e17f818f2459ee4997e980782b8ffffffff20f5e9064708f69c5472b08c98f53c0537915f3df3a29a9ec7e816e6d4f218820000000023220020cc22d4b41d7c494078d811f808ea40fdd840796cc7666284aa85875d83cebf9affffffff65a1c0f50866589116f219c2cb1f650d8220891577e0ca1638c025ce7873f4960000000023220020577738c1c5f3a5eeed2c0af27cdf6ce6209cb12d05ae94af19f710692dfe0e09ffffffffc18fa905954800c9da6a07e233b15f9989496e13558971c5acd544432be04da80000000000ffffffff866bf997beee5206481aa646e0a052ab300239089233346d2696fad4e538a0fb0100000023220020b314e8441b9f04ff72001c7f5fbc171304e610805a8e3819b9b135a9285e7290ffffffff0311e10b000000000022002022690c3e98bcfdcd1af1f5ccf4e92cbce2e2d21053fde95426181a70016b18676095a0000000000017a914d796005d38601417fcbb9ea9b959cf6ab1560362871949f0010000000017a9140321e212eab1f22511cb351bac296862c6a3b7a387030047304402206c694e5919ac3a6d0e1816cc1d3c56665bb81b9b57c76008da6a44b05fa312cf022023d8a964a3a9239019716e3700471445e9b4596b72d9cd30d5b5609f2c9e514a0125512103b50599018de1e7714faffbd5da190766cc73f6b48142aeca093b8e195e5635ae51ae03004730440220070c948bf083f40b527d19cc71c361cb658ca7c15f248d40ec843a67160c6a17022004cca8b06e98d85a85889e5ba885a89f831776d7b229b68ab15ebd7468d79dd40125512103c4be3beaf1d14f296ebfcf791798e8b47f3ef850cd0c8029bb5d3805222e678351ae030047304402206443ebaed7df753519e14a51d22224d281d836ebe021656759d5e0da2d1c92d5022024112eb57a803c648b7be1e684266f428b8471f48463ff3b0a3a7496d25ae0190125512103941468534f06e1615ad2d83de6a3a9db30fded0ce47c7c4597f25761f6de3a0a51ae0300483045022100d40bed6c627703e1bc64f7bade8ca3804f4c642d26e6ed855b18d6e6b23b7baa02205b221a7426d4d6e533cff94d8b89cb0c38fc198e6b3a26c303042330d5cb16b801255121038f64faacd67c9d2c6fa9baa85a9ec6460d48f5c27c1a6c674e142bb3758b41eb51ae0300483045022100b6cc6dbd7e4ca5a9cb7b9e0ba5ff9a3be908bdb27f25dc71a77595294be6abe90220764c334d1be8b0630a1f840553eab3d68962304bcb002d4d93453ec9b8563fb901255121031cb38871e2c7d2000bec439d0ff92bd5e1bfb75709b956f735cc154493c2e5fd51ae0300473044022076c5792db455472a097987e57b284c8f2db43390808d3968774eb2b4cb62a50e02203ceeef4de7689842419cef121203a5b78972cd5589e1af68bdab248cc58defab012551210266a92ed1fb3b2b1214cff2937fecfe6e50f0e88801059757cef19eda48ab0c7751ae030047304402201ca149a8a47c8efc2e13cfc20f23777d5d0d7e5bd9a8611d016b865ddf8866e002205f812fae81720f0735d974f24c9a186accf176ca270b7d8edc411bcb51f38d0601255121033cace199a79669c1459af28e1ca4482ef7e4dd2e9805ac4f4fd233806990808e51ae03004730440220489fd1a2d1a5e6e0a6b608c3af5c57af7913716537e9002ad0b95f83fc2a9b0f02204db86802764a3ecc57dd99bfad0085a785a7d1ec0d81ad28c13fbf60ca607b100125512103fb383b14e15d90b8b9f1575aa4320215b77c2fad8c091b9d175f05f5efd5416b51ae03004830450221009601387683e5b958aedda65dc13dc0440ebc892bdcd1baa7acfd8494930d3c6e02206549d57d1a80e4fd687fedb91f999115f22a37d2e3ee73835f591f51bcafeaf90125512102cba9bcbea6980c4ff12b35722e54f308f890b788341dc98382e877372936090851ae030047304402203cb8f3291ded60fab0f6b4b20c3f1cdb9024dc74d45a0439a673b9df53a430dc022037ce7f3f79aa8f508585136aea55f4ab17622860b73e0ea2ee0e6886925bff830125512103941468534f06e1615ad2d83de6a3a9db30fded0ce47c7c4597f25761f6de3a0a51ae0300473044022075f147cea7946653c7f1ebfbf269d86ed20858766f39675c3423652fef186ae7022066aa5bacbff280dd39fc5c278be1458fe8e7252eb5d4545d5d78d7995d04e0a0012551210370c1dc0d16703fec46cc808c6d77a6718d8e945ecef2f9605992d31ee136d21851ae00000000"
	assert txid(_hex_)[0] == "15436f1c7fdd7f3dc0d203483a8a86b8f4974e6b60a0d0112db5791f6939041a"
	