import os
from Crypto.Cipher import DES3
from Crypto import Random

def encrypt_file(in_filename, out_filename, chunk_size, key, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)

    with open(in_filename, 'r') as in_file:
        with open(out_filename, 'wb') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                out_file.write(des3.encrypt(chunk))

def decrypt_file(in_filename, out_filename, chunk_size, key, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)

    with open(in_filename, 'rb') as in_file:
        with open(out_filename, 'wb') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                out_file.write(des3.decrypt(chunk))
				
				


if __name__ == '__main__':
	iv = Random.get_random_bytes(8)
	key = b'Hello world all!'
	
	with open('plaintext.txt', 'r') as f:
		print ('to_enc.txt: %s' % f.read())
	encrypt_file('plaintext.txt', 'ciphertext.txt', 8192, key, iv)
	#with open('to_enc.enc', 'r') as f:
	#	print ('to_enc.enc: %s' % f.read())
	decrypt_file('ciphertext.txt', 'decrypted.txt', 8192, key, iv)
	#with open('to_enc.dec', 'r') as f:
	#	print ('to_enc.dec: %s' % f.read())				
