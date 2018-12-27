# Password authentication sample

import getpass
import hashlib


def get_derived_key(password):
	"""Return a derived key for a given password."""
	# encode password into bytes for hashing
	password_bytes = password.encode('UTF-8')
	# random 16 bytes as salt
	# suggested iterations is 100,000
	derived_key = hashlib.pbkdf2_hmac(
		hash_name='sha256', password=password_bytes, salt=get_salt(),
		iterations=100000)
	return derived_key

def verify_password(password, derived_key):
	"""
	Computes the derived key of a password and compares it with the given
	derived key.
	"""
	return get_derived_key(password) == derived_key

def get_salt():
	"""Return a random byte string of length 16 bytes."""
	# TO-DO: Implement this.
	return b'salt'
