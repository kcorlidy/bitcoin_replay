import ecdsa
import re

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
	def check_scripttype(self, script):
		pass

	@classmethod
	def deserialize_have_P2WPKH(self, txhex, amounts, sighashtype = "ALL"):

		# raise NotImplementedError("amount is puzzle, and i did not sure what type of address you are using")

		if not txhex:
			txhex = self.txhex

		try:
			json = decoderawtransaction(txhex)

		except Exception as e:
			json = decoderawtransaction_witness(txhex)

		json = loads(json, object_pairs_hook = OrderedDict)
		
		# pprint(json) # should add one more key `script type`
		
		nVersion = json.get("version")

		vin = json.get("vin")


		Preimages = []
		count = 0

		for pos,v in enumerate(vin):
			the_txwitness = v.get("txwitness")

			if the_txwitness and len(the_txwitness) == 2:
				# P2WPKH / P2SH(P2WPKH)
				outpoint = v.get("prev_txid") + v.get("prev_vout")
				nSequence =  v.get("sequence")
				hashPrevouts = hexlify(dsha256("".join([vx.get("prev_txid") + vx.get("prev_vout") for vx in vin])))
				hashSequence = hexlify(dsha256("".join([vx.get("sequence") for vx in vin])))

				scriptCode = P2PKH(the_txwitness[-1]) # used P2PKH
				scriptCode = hex(int(len(scriptCode)/2))[2:] + scriptCode

				amount = amounts[count]
				count += 1

				output = "".join([vout.get("amount") + vout.get("script_length") + vout.get("scriptpubkey") for vout in json.get("vout")])
				hashOutputs = hexlify(dsha256(output))
				
				nLockTime = json.get("locktime")
				nHashType = tolittle_endian(SIGHASH.get(sighashtype), 8)

				if sighashtype == "SINGLE":
					hashSequence = "0"*64

				Preimages.append(nVersion + hashPrevouts +
								 hashSequence + outpoint +
								 scriptCode + amount + nSequence +
								 hashOutputs + nLockTime +
								 nHashType)
		# print(Preimages)
		return [hexlify(dsha256(p)) for p in Preimages]

	@classmethod
	def deserialize_have_P2WSH(self, txhex, amounts, sighashtype = "ALL"):
		
		if not txhex:
			txhex = self.txhex

		try:
			json = decoderawtransaction(txhex)

		except Exception as e:
			json = decoderawtransaction_witness(txhex)

		json = loads(json, object_pairs_hook = OrderedDict)
		
		# pprint(json) # should add one more key `script type`
		
		nVersion = json.get("version")

		vin = json.get("vin")


		Preimages = []
		count = 0
		
		for pos,v in enumerate(vin):

			the_txwitness = v.get("txwitness")

			if the_txwitness and len(the_txwitness) >= 2:
				# P2WSH / P2SH(P2WSH)
				outpoint = v.get("prev_txid") + v.get("prev_vout")
				nSequence =  v.get("sequence")
				hashPrevouts = hexlify(dsha256("".join([vx.get("prev_txid") + vx.get("prev_vout") for vx in vin])))
				hashSequence = hexlify(dsha256("".join([vx.get("sequence") for vx in vin])))

				scriptCode = self.getlastpubkey(the_txwitness[-1]) # get last part
				scriptCode = hex(int(len(scriptCode)/2))[2:] + scriptCode
				
				amount = amounts[count]
				count += 1

				output = "".join([vout.get("amount") + vout.get("script_length") + vout.get("scriptpubkey") for _, vout in enumerate(json.get("vout")) if _ == pos]) # _ == pos means second inputs to second ouput/ 1-input to 1-output
				hashOutputs = hexlify(dsha256(output)) if output else "0"*64 
				
				nLockTime = json.get("locktime")
				nHashType = tolittle_endian(SIGHASH.get(sighashtype), 8)

				if sighashtype == "SINGLE":
					hashSequence = "0"*64

				elif sighashtype == "SINGLE|ANYONECANPAY":
					hashSequence = hashPrevouts = "0"*64

				Preimages.append(nVersion + hashPrevouts +
								 hashSequence + outpoint +
								 scriptCode + amount + nSequence +
								 hashOutputs + nLockTime +
								 nHashType)
		

		return [hexlify(dsha256(p)) for p in Preimages]

	@classmethod
	def getlastpubkey(self, script):

		if script.startswith("00"):
			return script

		regex = r"(?<=ab)((68){0,1}(2102|2103)\w{64}\w{0,4}$)"
		sit =  re.findall(regex, script)
		
		if not sit:
			sit = re.findall(r"^[5]\w+((2102|2103)\w{64})\w{2,4}$", script)

		return [i for i in sit[-1] if len(i) >= 66][0]

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

		pubkey = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
			signature=signature, digest=msg, curve=ecdsa.curves.SECP256k1, sigdecode=ecdsa.util.sigdecode_der)
		
		PubKeyHash = [self.check_recovery(pub) for pub in pubkey]
		
		return PubKeyHash

	@classmethod
	def verify(self, signature, pubkeyhash, msg = None):

		if not msg and self.msg:
			msg = self.msg

		elif not msg and not self.msg:
			raise AttributeError("msg can not be None")

		recover_process = self.recovery(signature = signature, msg = msg)
		
		return any([pkh == pubkeyhash for pkh in recover_process])

		
if __name__ == '__main__':

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
	txhex = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
	# Remember! remove sighast type
	signature = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb"
	pubkeyhash = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
	ffff = inspector.deserialize_have_P2WPKH(txhex, amounts=["00ca9a3b00000000"]) 
	assert ffff == ["64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"]
	state = inspector.verify(signature=signature, pubkeyhash=pubkeyhash, msg=ffff[0])
	print("tx1:",state)

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
	txhex2 = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
	signature2 = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
	pubkeyhash2 = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
	ffff2 = inspector.deserialize_have_P2WPKH(txhex2, amounts=["0046c32300000000"])
	assert ffff2 == ["c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"]
	state2 = inspector.verify(signature=signature2, pubkeyhash=pubkeyhash2, msg=ffff2[0])
	print("tx2:",state2)
	
	# My transaction 4dc48bc2dff60410c77bf3674cdc22954db99e4b2841c0ef8cfd5ff4a0df34fa testnet
	txhex3 = "0200000000010341e241eb1e14125ac93a43bd1561a839de3aad1fce8b49ab7a44e31b903a5e100100000000fdffffff6b626907ad9ebe7dab31e18337aa42408757312fa239a98fa0afc68fe8dcce9e0000000000fdffffffb87c4c430ad2d1d3575e55824bfbbb394016760d6a0b987d10759ccbeef5ab4a0000000000fdffffff01f2a2210600000000160014dc72fd7bf4ef5bfd8dfe021f41f1ad7d37166dca0247304402200ed9eb7189da61da05c9ed35ffdb589e5b98a9135b9d74db1edfb8e00177e2b90220229bd12925be2aff620b6ae2f72d832eb27468c0dac6165ffab590eacdad273d012102b497bfc891cc3b85df8b1ab4cbe4d6dce76d037c3d3a13712073960d54d6dcf7024730440220716345f34607a9a8b4acd434f8318937ad7164bd92dbe602fae458afe7b83a9102201217c1357df8fc3be1bf28283ef3fd16f5269daef9a00f45368b0770090b3e45012102b497bfc891cc3b85df8b1ab4cbe4d6dce76d037c3d3a13712073960d54d6dcf70247304402205300b916b6ce48a945098585e61197783ef98ddb61af385d432c2ea0ad1fedef0220279e3afc47e77f8503880efaeebc3a72f6f65dd0989933c38a256144b2ec6637012102b0573d73a59544b9f5e6f50f992738970a5521d74b94c4dd2d7ecf393fb1da7a2ffa1700"
	signature3 = "304402200ed9eb7189da61da05c9ed35ffdb589e5b98a9135b9d74db1edfb8e00177e2b90220229bd12925be2aff620b6ae2f72d832eb27468c0dac6165ffab590eacdad273d"
	pubkeyhash3 = "02b497bfc891cc3b85df8b1ab4cbe4d6dce76d037c3d3a13712073960d54d6dcf7"
	
	signature4 = "30440220716345f34607a9a8b4acd434f8318937ad7164bd92dbe602fae458afe7b83a9102201217c1357df8fc3be1bf28283ef3fd16f5269daef9a00f45368b0770090b3e45"
	pubkeyhash4 = "02b497bfc891cc3b85df8b1ab4cbe4d6dce76d037c3d3a13712073960d54d6dcf7"
	
	signature5 = "304402205300b916b6ce48a945098585e61197783ef98ddb61af385d432c2ea0ad1fedef0220279e3afc47e77f8503880efaeebc3a72f6f65dd0989933c38a256144b2ec6637"
	pubkeyhash5 = "02b0573d73a59544b9f5e6f50f992738970a5521d74b94c4dd2d7ecf393fb1da7a"
	
	ffff3 = inspector.deserialize_have_P2WPKH(txhex3, amounts=[tolittle_endian(i, 16) for i in [4178886, 96115369, 2573688]])
	ffff3, ffff4, ffff5 = ffff3
	
	state3 = inspector.verify(signature=signature3, pubkeyhash=pubkeyhash3, msg=ffff3)
	state4 = inspector.verify(signature=signature4, pubkeyhash=pubkeyhash4, msg=ffff4)
	state5 = inspector.verify(signature=signature5, pubkeyhash=pubkeyhash5, msg=ffff5)
	print("tx3:",state3)
	print("tx4:",state3)
	print("tx5:",state3)


	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
	Preimages = "01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000023210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000"
	txhex6 = "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000"
	ffff6 = inspector.deserialize_have_P2WSH(txhex6, amounts=["0011102401000000"], sighashtype="SINGLE") 
	assert ffff6 == ["fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"]

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh - the second one
	Preimages = "0100000000010280e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffffe9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff0280969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac80969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000"
	txhex7 = "01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000"
	ffff7 = inspector.deserialize_have_P2WSH(txhex7, amounts=["ffffff0000000000","ffffff0000000000"], sighashtype="SINGLE|ANYONECANPAY")
	assert ffff7 == ['e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a', 'cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54']