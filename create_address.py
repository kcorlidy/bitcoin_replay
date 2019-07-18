from hashlib import sha256
from binascii import hexlify
import hashlib
from pyhdwallet import segwit_addr, Base58
from pyhdwallet.hdwallets import bips
import warnings

'''
entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
mnemonic = "plate inject impose rigid plug tornado march art vast filter issue village"
bip44 = bips(path="m/44'/0'/0'/0",entropy=entropy) # mnemonic = mnemonic
store44 = bip44.generator(7).Derived_Addresses

bip49 = bips(path="m/49'/0'/0'/0",entropy=entropy)
store49 = bip49.generator(7).Derived_Addresses # P2WPKHoP2SHAddress

bip84 = bips(path="m/84'/0'/0'/0",entropy=entropy)
store84 = bip84.generator(7).Derived_Addresses # p2wpkh

print(store44, store49, store84)
'''



def MoNscript(m, n, publickeylist):
	# P2WSH calls witnessScript, P2SH calls redeemScript
	# Be careful the order of publickeylist, which will change your address. Then redeem unsuccessfully
	if isinstance(publickeylist, list) or isinstance(publickeylist, tuple)\
		and (isinstance(m, int) and isinstance(n) and m <= n and m >= 1):
		m += 50
		n += 50
		start = [bytes.fromhex("{}".format(m))]
		for pk in publickeylist:
			pk = pk if isinstance(pk, bytes) else bytes.fromhex(pk)
			start += [bytes.fromhex(hex(len(pk))[2:]), pk]
		start += [bytes.fromhex("{}".format(n)), bytes.fromhex("ae")]
	else:
		raise NotImplementedError("Can not handle your input")

	return hexlify(b"".join(start)).decode()

def P2SH(redeemScript ,testnet = False):
	prefix = b"\xc4" if testnet else b"\x05"
	hash_again = hashlib.new('ripemd160', sha256(redeemScript).digest()).digest()
	return Base58.check_encode(prefix + hash_again) 

def P2WSH(pk, testnet = False):
	warnings.warn("I just got the same result as Bip141 example, but i did not sure it suit for MoN")
	pk_added_code = bytes.fromhex('0014') + sha256(b"\x21" + pk + b"\xac").digest()
	hrp = "bc" if not testnet else "tb"
	l = list(bytearray(pk_added_code))
	l0 = l[0] - 0x50 if l[0] else 0
	address = segwit_addr.encode(hrp, l0, l[2:])
	return address 

def P2WPKH(pk, testnet = False):
	pk_added_code = bytes.fromhex('0014') + hashlib.new("ripemd", sha256(pk).digest()).digest()
	l = list(bytearray(pk_added_code))
	l0 = l[0] - 0x50 if l[0] else 0
	hrp = "bc" if not testnet else "tb"
	result = segwit_addr.encode(hrp, l0, l[2:])
	return result 

def P2WSHoP2SHAddress(witnessScript, testnet = False):
	prefix = b"\xc4" if testnet else b"\x05"
	redeemScript = bytes.fromhex("0020") + sha256(witnessScript).digest()
	hash_again = hashlib.new("ripemd160",  sha256(redeemScript).digest()).digest()
	return Base58.check_encode(prefix + hash_again) 

if __name__ == '__main__':

	pk = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	pk = bytes.fromhex(pk)
	p2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
	p2wpkh = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	assert P2WPKH(pk) == p2wpkh
	assert P2WSH(pk) == p2wsh

	P2WSHoP2SHAddress_witnessScript = "5221021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe2103bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38210280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c6553ae"
	P2WSHoP2SHAddress_witnessScript = bytes.fromhex(P2WSHoP2SHAddress_witnessScript)
	P2WSHoP2SHAddress_ = "3CYkk3x1XUvdXCdHtRFdjMjp17PuJ8eR8z"
	print(P2WSHoP2SHAddress(witnessScript = P2WSHoP2SHAddress_witnessScript))

	# need a standard data 51..51ae might be changed now, i think
	redeemScript_single = "5141042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf51ae"
	redeemScript_single = bytes.fromhex(redeemScript_single)
	single_P2SH_address = "3P14159f73E4gFr7JterCCQh9QjiTjiZrG"
	#
	redeemScript_mon = "522102194e1b5671daff4edc82ce01589e7179a874f63d6e5157fa0def116acd2c3a522103a043861e123bc67ddcfcd887b167e7ff9d00702d1466524157cf3b28c7aca71b2102a49a62a9470a31ee51824f0ee859b0534a4f555c0e2d7a9d9915d6986bfc200453ae"
	redeemScript_mon = bytes.fromhex(redeemScript_mon)
	mon_P2SH_address = "3JUJgXbB1WpDEJprE8wP8vEXtba36dAYbk"
	assert P2SH(redeemScript = redeemScript_single) == single_P2SH_address
	assert P2SH(redeemScript = redeemScript_mon) == mon_P2SH_address

	publickeylist = ["021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe", "03bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38", "0280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c65"]
	assert MoNscript(2,3,publickeylist) == "5221021e6617e06bb90f621c3800e8c37ab081a445ae5527f6c5f68a022e7133f9b5fe2103bea1a8ce6369435bb74ff1584a136a7efeebfe4bc320b4d59113c92acd869f38210280631b27700baf7d472483fadfe1c4a7340a458f28bf6bae5d3234312d684c6553ae"

	print(P2SH(bytes.fromhex("a82073d83ecabab6ba96a47f03d0e21ffbdfeaab5d337b7e93a0cc2e85019190fb3f87"), testnet=True))