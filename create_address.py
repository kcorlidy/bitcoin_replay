from pyhdwallet.hdwallets import bips

entropy = "a62e81c7dcfa6dcae1f066f1aacddafa"
mnemonic = "plate inject impose rigid plug tornado march art vast filter issue village"
bip44 = bips(path="m/44'/0'/0'/0",entropy=entropy) # mnemonic = mnemonic
store44 = bip44.generator(7).Derived_Addresses

bip49 = bips(path="m/49'/0'/0'/0",entropy=entropy)
store49 = bip49.generator(7).Derived_Addresses

bip84 = bips(path="m/84'/0'/0'/0",entropy=entropy)
store84 = bip84.generator(7).Derived_Addresses

print(store44, store49, store84)