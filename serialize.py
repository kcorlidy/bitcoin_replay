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