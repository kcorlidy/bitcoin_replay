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
from warnings import warn

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

	@classmethod
	def check_scripttype(self, vin):
		'''
			Be careful, this function can only guess what kind of address it might be.
			The most accurate method is to check previous output content
			# 0 -> unkown
			# 1 -> P2PKH, 2 -> P2SH
			# 3 -> P2SH(P2WPKH), 4 -> P2SH(P2WSH)
			# 5 -> P2WPKH, 6 -> P2WSH
			# 7 -> P2PK
		'''

		if not vin:
			raise RuntimeError

		script = vin.get("script")
		lscript = len(script)
		txwitness_count = len(vin.get("txwitness")) if vin.get("txwitness") else 0

		if lscript >= 140:
			# P2SH or P2PKH or P2PK, can not recognize OP_CODESEPARATOR
			if re.findall(r"([5][1-9a-f]|60)(21(02|03)\w{64})+([5][1-9a-f]|60)(ae)", script):
				# m of n
				return 2

			elif lscript > 246:
				return 6

			return 1

		elif 0 < lscript < 100:
			# witness
			if 0 < script.find("0020") <= 4:
				return 6

			elif 0 < script.find("0014") <= 4:
				return 5

			if txwitness_count > 2:
				return 4

			elif txwitness_count == 2:

				if re.findall(r"^0[2-3]\w{64}" ,vin.get("txwitness")[1]):
					return 5

				return 6

			return 5

		elif lscript == 0:
			# view previous tx output can know what it is.
			if txwitness_count > 2:
				return 6

			elif txwitness_count == 2:

				if re.findall(r"^0[2-3]\w{64}" ,vin.get("txwitness")[1]):
					return 5

				return 6
				
		return 0

	@classmethod
	def deserialize(self, txhex, amounts, sighashtype = "ALL"):

		json = self.decodetransaction(txhex)
		
		nVersion = json.get("version")

		vin = json.get("vin")

		Preimages = []
		count = 0

		for pos,v in enumerate(vin):

			st = self.check_scripttype(v)
			
			the_txwitness = v.get("txwitness")

			if the_txwitness and len(the_txwitness) == 2 and st in [3, 5]:
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


			if the_txwitness and len(the_txwitness) >= 2 and st in [4, 6]:
				# P2WSH / P2SH(P2WSH)
				outpoint = v.get("prev_txid") + v.get("prev_vout")
				nSequence =  v.get("sequence")
				hashPrevouts = hexlify(dsha256("".join([vx.get("prev_txid") + vx.get("prev_vout") for vx in vin])))
				hashSequence = hexlify(dsha256("".join([vx.get("sequence") for vx in vin])))

				if sighashtype.find("SINGLE") >= 0:

					scriptCode = self.getlastpart(the_txwitness[-1]) # get last part

					if not scriptCode:
						scriptCode = the_txwitness[-1]

				elif sighashtype.find("ALL") >= 0 or sighashtype.find("None") >= 0:
					scriptCode = the_txwitness[-1]

				scriptCode = hex(int(len(scriptCode)/2))[2:] + scriptCode
				
				amount = amounts[count]
				count += 1

				if sighashtype.find("SINGLE") >= 0:
					output = "".join([vout.get("amount") + vout.get("script_length") + vout.get("scriptpubkey") for _, vout in enumerate(json.get("vout")) if _ == pos]) # _ == pos means second inputs to second ouput/ 1-input to 1-output

				elif sighashtype.find("ALL") >= 0:
					output = "".join([vout.get("amount") + vout.get("script_length") + vout.get("scriptpubkey") for _, vout in enumerate(json.get("vout"))])
				
				elif sighashtype.find("None") >= 0:
					output = ""

				hashOutputs = hexlify(dsha256(output)) if output else "0"*64 
				
				nLockTime = json.get("locktime")
				nHashType = tolittle_endian(SIGHASH.get(sighashtype), 8)

				if sighashtype == "SINGLE" or sighashtype == "None":
					hashSequence = "0"*64

				elif sighashtype.find("ANYONECANPAY") > 0:
					hashSequence = hashPrevouts = "0"*64

				Preimages.append(nVersion + hashPrevouts +
								 hashSequence + outpoint +
								 scriptCode + amount + nSequence +
								 hashOutputs + nLockTime +
								 nHashType)
		
		return [hexlify(dsha256(p)) for p in Preimages]

	@classmethod
	def decodetransaction(self, txhex):

		if not txhex:
			txhex = self.txhex

		try:
			json = decoderawtransaction(txhex)

		except Exception as e:
			json = decoderawtransaction_witness(txhex)

		return loads(json, object_pairs_hook = OrderedDict)

	@classmethod
	def getlastpart(self, script):
		# special case
		# OP_CODESEPARATOR and out-of-range SIGHASH_SINGLE are processed
		# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
		if script.startswith("00") or len(script) == 66:
			return script

		regex = r"(?<=ab)((68){0,1}(2102|2103)\w{64}\w{0,4}$)"
		sit =  re.findall(regex, script)
		
		if sit:
			return [i for i in sit[-1] if len(i) >= 66][0]

		return None

	def deserialize_have_P2PKH(self, txhex, amounts, sighashtype = "ALL"):
		pass

	def deserialize_have_P2SH(self, txhex, amounts, sighashtype = "ALL"):
		pass

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

	@classmethod
	def autoverify(self, txhex):
		warn("Can verify witness part only")
		
if __name__ == '__main__':
	
	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
	txhex = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
	# Remember! remove sighast type
	signature = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb"
	pubkeyhash = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
	ffff = inspector.deserialize(txhex, amounts=["00ca9a3b00000000"]) 
	assert ffff == ["64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"]
	state = inspector.verify(signature=signature, pubkeyhash=pubkeyhash, msg=ffff[0])
	print("tx1:",state)

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
	txhex2 = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
	signature2 = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
	pubkeyhash2 = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
	ffff2 = inspector.deserialize(txhex2, amounts=["0046c32300000000"])
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
	
	ffff3 = inspector.deserialize(txhex3, amounts=[tolittle_endian(i, 16) for i in [4178886, 96115369, 2573688]])
	ffff3, ffff4, ffff5 = ffff3
	
	state3 = inspector.verify(signature=signature3, pubkeyhash=pubkeyhash3, msg=ffff3)
	state4 = inspector.verify(signature=signature4, pubkeyhash=pubkeyhash4, msg=ffff4)
	state5 = inspector.verify(signature=signature5, pubkeyhash=pubkeyhash5, msg=ffff5)
	print("tx3:",state3)
	print("tx4:",state4)
	print("tx5:",state5)

	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
	Preimages = "01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000023210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000"
	txhex6 = "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000"
	signature6 = "304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e5"
	pubkeyhash6 ="0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465"
	ffff6 = inspector.deserialize(txhex6, amounts=["0011102401000000"], sighashtype="SINGLE") 
	assert ffff6 == ["fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"]
	state6 = inspector.verify(signature=signature6, pubkeyhash=pubkeyhash6, msg=ffff6[0])
	print("tx6:",state6)
	
	
	# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh - the second one
	Preimages = "0100000000010280e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffffe9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff0280969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac80969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000"
	txhex7 = "01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000"
	signature7 = "3045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe6"
	pubkeyhash7 = "0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98"

	signature8 = "30440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff"
	pubkeyhash8 = "0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98"

	ffff7 = inspector.deserialize(txhex7, amounts=["ffffff0000000000","ffffff0000000000"], sighashtype="SINGLE|ANYONECANPAY")
	assert ffff7 == ['e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a', 'cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54']
	state7 = inspector.verify(signature=signature7, pubkeyhash=pubkeyhash7, msg=ffff7[0])
	state8 = inspector.verify(signature=signature8, pubkeyhash=pubkeyhash8, msg=ffff7[1])
	print("tx7:",state7)
	print("tx8:",state8)
	
	
	# txid aa3c07663a5b5368f75519c68aeb13e24a931498f11dfd75839432fc2b12005d mainnet, purpose is to test mixed type transactions
	txhex9 = "0100000000010292611e383cd7a4b97973ff8ae904432e56c2dbddfde5c526cff7122381bead030100000000ffffffff93732ebb1ee84c0570c6d8c915d22953378289b348b9daf2c82c3e6c7c6df68f210000006b483045022100d6bbc284289c127b1918a94cf5001cc05f7461467f83014cf49529dd867ca7e7022061d5afe78e6b90f60f7c69d59c1e9cf545ff405db6e11030838200e0f9abd5d5012103607a2e1e25cd163df8d0769fb582c8bcf57a04ca575e7a5d93de4545ecaeb4bcffffffff02d8d30d0000000000160014b3e2448ca6436ecb3b7ef0ffafbcce14e62ee54d1ff10800000000001976a91436f20c7b64230e23a0da7cd65de9eb54d8bba8ad88ac0247304402202177e9529d13feb94bda3f5cbdfb1daf75b6662a33b6d25adcad89bfd3e1ff4b02205dc01d4866758ebc7d55a7382f40aca8aae4d753e582e90cd2b147817ecf8984012103827eb290d49b6f541e95c9495fff0a7e0350e10b30a1922d1ccd1a10b498bd470000000000"
	signature9 = "304402202177e9529d13feb94bda3f5cbdfb1daf75b6662a33b6d25adcad89bfd3e1ff4b02205dc01d4866758ebc7d55a7382f40aca8aae4d753e582e90cd2b147817ecf8984"
	pubkeyhash9 = "03827eb290d49b6f541e95c9495fff0a7e0350e10b30a1922d1ccd1a10b498bd47"
	ffff9 = inspector.deserialize(txhex9, amounts=[tolittle_endian(576100, 16)])
	state9 = inspector.verify(signature=signature9, pubkeyhash=pubkeyhash9, msg=ffff9[0])
	print("tx9:",state9)
	# there is a extra test. txid a922593ec22ba0307b8f5c276d570e1534c27876017b3cde9248d5f24d795c6d mainnet, all of them are P2WPKH

	
	# txid 15436f1c7fdd7f3dc0d203483a8a86b8f4974e6b60a0d0112db5791f6939041a mainnet, P2SH(P2WSH) & P2WSH
	txhex10 = "0100000000010bc5f6f209d947f0e4073f72b39a2d87a5f647567274f26eba2148a89feb35fa070000000000ffffffffd221e27a511238536a18a26f99739701300b4e31bbb2ea7538853730e193761200000000232200201260248fb98785dab7a5699958707ad20ea1ba1c04d866d02c6c3b64e8656e4affffffffc9b13a1a560e1621f296e0fa9a7d8c81786c07c1e17650e527aed1871d7fc32d0000000000ffffffff056f552f3966cbe46fc7915a1c47c5bc60c6a5e8bf5716e1f94ad24022d665370100000023220020868c3cdd51a2b6d73b3ef3a71b49fb4b0ef9234545706cfa78247503a70945f5ffffffff4f6684a04ba51a4df9a95b2b5c4f127b4c236036836e79c6c17e4529353377660400000023220020ed3443231e4c9b6ea97713dc06820f42a3f7b03d2a04d8f885ef6e17d1d0ec5fffffffff93593d54ac63d32f2bbb69ff800b8fd715e19cb9cebeacaa1d9a7be83293b46c0100000023220020378e6c2956eabc503de0ad7ca7cd0a0c06ba0ee92c96d0ed0639046ac1138705ffffffff81331ed8b31aa67ad87d4ae941369ac6099c22c530fe4c439f1bab5dae25c3700000000023220020dbd6c71abad6d637c06febb25c753ad039271e17f818f2459ee4997e980782b8ffffffff20f5e9064708f69c5472b08c98f53c0537915f3df3a29a9ec7e816e6d4f218820000000023220020cc22d4b41d7c494078d811f808ea40fdd840796cc7666284aa85875d83cebf9affffffff65a1c0f50866589116f219c2cb1f650d8220891577e0ca1638c025ce7873f4960000000023220020577738c1c5f3a5eeed2c0af27cdf6ce6209cb12d05ae94af19f710692dfe0e09ffffffffc18fa905954800c9da6a07e233b15f9989496e13558971c5acd544432be04da80000000000ffffffff866bf997beee5206481aa646e0a052ab300239089233346d2696fad4e538a0fb0100000023220020b314e8441b9f04ff72001c7f5fbc171304e610805a8e3819b9b135a9285e7290ffffffff0311e10b000000000022002022690c3e98bcfdcd1af1f5ccf4e92cbce2e2d21053fde95426181a70016b18676095a0000000000017a914d796005d38601417fcbb9ea9b959cf6ab1560362871949f0010000000017a9140321e212eab1f22511cb351bac296862c6a3b7a387030047304402206c694e5919ac3a6d0e1816cc1d3c56665bb81b9b57c76008da6a44b05fa312cf022023d8a964a3a9239019716e3700471445e9b4596b72d9cd30d5b5609f2c9e514a0125512103b50599018de1e7714faffbd5da190766cc73f6b48142aeca093b8e195e5635ae51ae03004730440220070c948bf083f40b527d19cc71c361cb658ca7c15f248d40ec843a67160c6a17022004cca8b06e98d85a85889e5ba885a89f831776d7b229b68ab15ebd7468d79dd40125512103c4be3beaf1d14f296ebfcf791798e8b47f3ef850cd0c8029bb5d3805222e678351ae030047304402206443ebaed7df753519e14a51d22224d281d836ebe021656759d5e0da2d1c92d5022024112eb57a803c648b7be1e684266f428b8471f48463ff3b0a3a7496d25ae0190125512103941468534f06e1615ad2d83de6a3a9db30fded0ce47c7c4597f25761f6de3a0a51ae0300483045022100d40bed6c627703e1bc64f7bade8ca3804f4c642d26e6ed855b18d6e6b23b7baa02205b221a7426d4d6e533cff94d8b89cb0c38fc198e6b3a26c303042330d5cb16b801255121038f64faacd67c9d2c6fa9baa85a9ec6460d48f5c27c1a6c674e142bb3758b41eb51ae0300483045022100b6cc6dbd7e4ca5a9cb7b9e0ba5ff9a3be908bdb27f25dc71a77595294be6abe90220764c334d1be8b0630a1f840553eab3d68962304bcb002d4d93453ec9b8563fb901255121031cb38871e2c7d2000bec439d0ff92bd5e1bfb75709b956f735cc154493c2e5fd51ae0300473044022076c5792db455472a097987e57b284c8f2db43390808d3968774eb2b4cb62a50e02203ceeef4de7689842419cef121203a5b78972cd5589e1af68bdab248cc58defab012551210266a92ed1fb3b2b1214cff2937fecfe6e50f0e88801059757cef19eda48ab0c7751ae030047304402201ca149a8a47c8efc2e13cfc20f23777d5d0d7e5bd9a8611d016b865ddf8866e002205f812fae81720f0735d974f24c9a186accf176ca270b7d8edc411bcb51f38d0601255121033cace199a79669c1459af28e1ca4482ef7e4dd2e9805ac4f4fd233806990808e51ae03004730440220489fd1a2d1a5e6e0a6b608c3af5c57af7913716537e9002ad0b95f83fc2a9b0f02204db86802764a3ecc57dd99bfad0085a785a7d1ec0d81ad28c13fbf60ca607b100125512103fb383b14e15d90b8b9f1575aa4320215b77c2fad8c091b9d175f05f5efd5416b51ae03004830450221009601387683e5b958aedda65dc13dc0440ebc892bdcd1baa7acfd8494930d3c6e02206549d57d1a80e4fd687fedb91f999115f22a37d2e3ee73835f591f51bcafeaf90125512102cba9bcbea6980c4ff12b35722e54f308f890b788341dc98382e877372936090851ae030047304402203cb8f3291ded60fab0f6b4b20c3f1cdb9024dc74d45a0439a673b9df53a430dc022037ce7f3f79aa8f508585136aea55f4ab17622860b73e0ea2ee0e6886925bff830125512103941468534f06e1615ad2d83de6a3a9db30fded0ce47c7c4597f25761f6de3a0a51ae0300473044022075f147cea7946653c7f1ebfbf269d86ed20858766f39675c3423652fef186ae7022066aa5bacbff280dd39fc5c278be1458fe8e7252eb5d4545d5d78d7995d04e0a0012551210370c1dc0d16703fec46cc808c6d77a6718d8e945ecef2f9605992d31ee136d21851ae00000000"
	
	signature10 = ['304402206c694e5919ac3a6d0e1816cc1d3c56665bb81b9b57c76008da6a44b05fa312cf022023d8a964a3a9239019716e3700471445e9b4596b72d9cd30d5b5609f2c9e514a',
					 '30440220070c948bf083f40b527d19cc71c361cb658ca7c15f248d40ec843a67160c6a17022004cca8b06e98d85a85889e5ba885a89f831776d7b229b68ab15ebd7468d79dd4',
					 '304402206443ebaed7df753519e14a51d22224d281d836ebe021656759d5e0da2d1c92d5022024112eb57a803c648b7be1e684266f428b8471f48463ff3b0a3a7496d25ae019',
					 '3045022100d40bed6c627703e1bc64f7bade8ca3804f4c642d26e6ed855b18d6e6b23b7baa02205b221a7426d4d6e533cff94d8b89cb0c38fc198e6b3a26c303042330d5cb16b8',
					 '3045022100b6cc6dbd7e4ca5a9cb7b9e0ba5ff9a3be908bdb27f25dc71a77595294be6abe90220764c334d1be8b0630a1f840553eab3d68962304bcb002d4d93453ec9b8563fb9',
					 '3044022076c5792db455472a097987e57b284c8f2db43390808d3968774eb2b4cb62a50e02203ceeef4de7689842419cef121203a5b78972cd5589e1af68bdab248cc58defab',
					 '304402201ca149a8a47c8efc2e13cfc20f23777d5d0d7e5bd9a8611d016b865ddf8866e002205f812fae81720f0735d974f24c9a186accf176ca270b7d8edc411bcb51f38d06',
					 '30440220489fd1a2d1a5e6e0a6b608c3af5c57af7913716537e9002ad0b95f83fc2a9b0f02204db86802764a3ecc57dd99bfad0085a785a7d1ec0d81ad28c13fbf60ca607b10',
					 '30450221009601387683e5b958aedda65dc13dc0440ebc892bdcd1baa7acfd8494930d3c6e02206549d57d1a80e4fd687fedb91f999115f22a37d2e3ee73835f591f51bcafeaf9',
					 '304402203cb8f3291ded60fab0f6b4b20c3f1cdb9024dc74d45a0439a673b9df53a430dc022037ce7f3f79aa8f508585136aea55f4ab17622860b73e0ea2ee0e6886925bff83',
					 '3044022075f147cea7946653c7f1ebfbf269d86ed20858766f39675c3423652fef186ae7022066aa5bacbff280dd39fc5c278be1458fe8e7252eb5d4545d5d78d7995d04e0a0']
	
	pubkeyhash10 = ['512103b50599018de1e7714faffbd5da190766cc73f6b48142aeca093b8e195e5635ae51ae',
					 '512103c4be3beaf1d14f296ebfcf791798e8b47f3ef850cd0c8029bb5d3805222e678351ae',
					 '512103941468534f06e1615ad2d83de6a3a9db30fded0ce47c7c4597f25761f6de3a0a51ae',
					 '5121038f64faacd67c9d2c6fa9baa85a9ec6460d48f5c27c1a6c674e142bb3758b41eb51ae',
					 '5121031cb38871e2c7d2000bec439d0ff92bd5e1bfb75709b956f735cc154493c2e5fd51ae',
					 '51210266a92ed1fb3b2b1214cff2937fecfe6e50f0e88801059757cef19eda48ab0c7751ae',
					 '5121033cace199a79669c1459af28e1ca4482ef7e4dd2e9805ac4f4fd233806990808e51ae',
					 '512103fb383b14e15d90b8b9f1575aa4320215b77c2fad8c091b9d175f05f5efd5416b51ae',
					 '512102cba9bcbea6980c4ff12b35722e54f308f890b788341dc98382e877372936090851ae',
					 '512103941468534f06e1615ad2d83de6a3a9db30fded0ce47c7c4597f25761f6de3a0a51ae',
					 '51210370c1dc0d16703fec46cc808c6d77a6718d8e945ecef2f9605992d31ee136d21851ae']

	# remember, if this is real multisig you have to extract each public key
	pubkeyhash10 = [p[4:-4] for p in pubkeyhash10]

	ffff10 = inspector.deserialize(txhex10, amounts=[tolittle_endian(i, 16) for i in [2999788, 3024000, 3689652, 5024078, 3623169, 4210577, 3937500, 3700221, 5030366, 3945446, 4680000]])
	state10 = [ inspector.verify(signature=signaturex, pubkeyhash=pubkeyhashx, msg=ffffx) for signaturex, pubkeyhashx, ffffx in zip(signature10, pubkeyhash10, ffff10)]
	print("tx10:",state10)
	