import ecdsa

from func import dsha256, _load_key, tolittle_endian
from opcodes import OPCODE_DICT
from serialize import tx, witness_tx, hexlify, P2WPKHoP2SH, P2PKH
from json import loads
from pprint import pprint
from collections import OrderedDict
from ecdsa.ecdsa import int_to_string, string_to_int
from sighash import SIGHASH

decoderawtransaction = tx.decoderawtransaction
decoderawtransaction_witness = witness_tx.decoderawtransaction

class inspector(object):
	'''
		Double SHA256 of the serialization of:
			 1. nVersion of the transaction (4-byte little endian)
			 2. hashPrevouts (32-byte hash)
			 3. hashSequence (32-byte hash)
			 4. outpoint (32-byte hash + 4-byte little endian) 
			 5. scriptCode of the input (serialized as scripts inside CTxOuts)
			 6. value of the output spent by this input (8-byte little endian)
			 7. nSequence of the input (4-byte little endian)
			 8. hashOutputs (32-byte hash)
			 9. nLocktime of the transaction (4-byte little endian)
			10. sighash type of the signature (4-byte little endian)
	'''
	def __init__(self, txhex):
		self.txhex = txhex
		self.msg = None

	def deserialize(self, sighashtype = "ALL"):
		
		txhex = self.txhex

		try:
			json = decoderawtransaction(txhex)

		except Exception as e:
			json = decoderawtransaction_witness(txhex)

		json = loads(json, object_pairs_hook = OrderedDict)

		#pprint(json)

		if json.get("maker") and json.get("flag"):
			del json["maker"]
			del json["flag"]

			for p, vin in enumerate(json.get("vin")):
				blank = "{%s}"%p
				vin["script_length"] = "{script_%s}"%p
				vin["script"] = ""

				if vin.get("txwitness"):
					vin["txwitness"] = "{witness_%s}"%p

		#pprint(json)

		ourhex = self.tohex(json) + tolittle_endian(SIGHASH.get(sighashtype), 8)
		vin_count = int(json.get("vin_count"), 16)
		script_n = "script_{}"
		witness_n = "witness_{}"

		SigZ = []
		# start serializing
		for n in range(vin_count):
			msg = ourhex.format(**{
				script_n.format(n):"00",
				witness_n.format(n):""
				})
			SigZ.append(msg)

		return SigZ, [hexlify(dsha256(bytes.fromhex(s))) for s in SigZ]

	@classmethod
	def deserialize_P2SH_P2WPKH(self, txhex, sighashtype = "ALL"):

		raise NotImplementedError("amount is puzzle, and i did not sure what type of address you are using")

		if not txhex:
			txhex = self.txhex

		try:
			json = decoderawtransaction(txhex)

		except Exception as e:
			json = decoderawtransaction_witness(txhex)

		json = loads(json, object_pairs_hook = OrderedDict)

		#pprint(json)
		nVersion = json.get("version")

		vin = json.get("vin")


		Preimages = []

		for v in vin:

			outpoint = v.get("prev_txid") + v.get("prev_vout")
			nSequence =  v.get("sequence")
			hashPrevouts = hexlify(dsha256(outpoint))
			hashSequence = hexlify(dsha256(nSequence))

			scriptCode = P2PKH(v.get("txwitness")[1]) # used P2PKH
			scriptCode = hex(int(len(scriptCode)/2))[2:] + scriptCode

			amount = "00ca9a3b00000000"

			output = "".join([vout.get("amount") + vout.get("script_length") + vout.get("scriptpubkey") for vout in json.get("vout")])
			hashOutputs = hexlify(dsha256(output))
			
			nLockTime = json.get("locktime")
			nHashType = tolittle_endian(SIGHASH.get(sighashtype), 8)

			Preimages.append(nVersion + hashPrevouts +
							 hashSequence + outpoint +
							 scriptCode + amount + nSequence +
							 hashOutputs + nLockTime +
							 nHashType)

		return [hexlify(dsha256(p)) for p in Preimages]

	def tohex(self, order_dict):

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

	@classmethod
	def check_recovery(self, pub):

		padx = (b'\0'*32 + int_to_string(pub.pubkey.point.x()))[-32:]
		if pub.pubkey.point.y() & 1:
			ck = b'\3'+padx
		else:
			ck = b'\2'+padx

		return hexlify(ck)

	@classmethod
	def recovery(self, signature, msg = None):

		if isinstance(msg, str) and msg:
			msg = bytes.fromhex(msg)

		if isinstance(signature, str) and msg:
			signature = bytes.fromhex(signature)

		pubkey = ecdsa.VerifyingKey.from_public_key_recovery(
			signature=signature, data=msg, curve=ecdsa.curves.SECP256k1, sigdecode=ecdsa.util.sigdecode_der)
		
		PubKeyHash = [self.check_recovery(pub) for pub in pubkey]
		
		return PubKeyHash

	@classmethod
	def verify(self, signature, pubkeyhash, msg = None):

		if not msg and self.msg:
			msg = self.msg

		elif not msg and not self.msg:
			raise AttributeError("msg can not be None")

		re_process = self.recovery(signature = signature, msg = msg)
		
		return any([pkh == pubkeyhash for pkh in re_process])

	def check_deserialize(self, signature, pubkeyhash):
		pass
		
if __name__ == '__main__':

	txhex = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
	
	# remove sighast type
	signature = "304502204c8fb3c82fad396945c3e3a6f81edda4062636b3c1c1fc192861c2d9409e5a98022100e2ef26fc8e54a51f4fef29d7f05b5b2a5a0ac9f3550810c6c5479e68d6e1f5ca"
	pubkeyhash = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
	
	ffff = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6" # inspector.deserialize_P2SH_P2WPKH(txhex)[0]
	
	state = inspector.verify(signature, pubkeyhash, ffff)

	print(state)