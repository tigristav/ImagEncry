
import sys
import argparse
import numpy as np
import base64
import binascii
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key



def generateKeys(password):
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, 
		encryption_algorithm=serialization.BestAvailableEncryption(str.encode(password)))
	
	with open("key.pem", "wb") as key_file:
		key_file.write(pem)

	print("Key generated Successfully")	


def showMyPublicKey():
	try:
		pwd = input("Password:")
		with open("key.pem", "rb") as key_file:
			private_key = serialization.load_pem_private_key(key_file.read(), password=str.encode(pwd))
	except FileNotFoundError:
		print("Private key file was not found, have you generated a private key?")
	else:
		public_key = private_key.public_key()
		pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
		for x in pem.splitlines():
			print(x.decode())
		if input("Write public key to file?(Y/N) ") == ('y' or 'Y' or 'yes' or 'Yes' or 'YES'):
			try:
				with open("publickey.txt", "w") as key_file:
					for x in pem.splitlines()[1:len(pem.splitlines())-1]:
						key_file.write(x.decode())
			except:
				print("Failed to write public key to file.")			
		

def encodeMessage(message):
	pub_key_input = input("Public Key: ")
	if pub_key_input == "":
		try:
			pwd = input("Password:")
			with open("key.pem", "rb") as key_file:
				private_key = serialization.load_pem_private_key(key_file.read(), password=str.encode(pwd))
		except FileNotFoundError:
			print("Private key file was not found, have you generated a private key?")
		except ValueError:
			print("Private key decryption failed. Most likely scenario is an incorrect password")	
		else:
			public_key = private_key.public_key()
			encrypted_message = public_key.encrypt(str.encode(message), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
			return encrypted_message
	else:
		pub_key_input = str.encode(pub_key_input)
		encrypted_message = public_key.encrypt(str.encode(message), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
		return encrypted_message


def embedMessage(message, path):
	message = base64.b64encode(message)
	print(f"Message length: {len(message)}")
	try:
		img = Image.open(path)
		formatImg = img.format
		img = img.convert("RGBA")
		pixels = np.array(img)
		width, height = img.size

		num_message = [ord(x) for x in str(message)]

		if (width*height)/2 < len(message):
			print("The chosen image cannot contain the message")
			return

		pixels[:] = [x&0xFE for x in pixels]

		column_index = 0
		row_index = 0
		
		counter = 0;
		for x in num_message:
			testval = 0
			for n in range(0,8):
				bit = (x & (1 << (7-n))) >> (7-n) # former bit = (x & (1 << n)) >> n
				
				if bit == 1:
					if n > 3:
						pixels[column_index, row_index, n%4] ^= bit
					else:
						pixels[column_index, row_index, n] ^= bit

				if (n+1) % 4 == 0:
					row_index += 1
				if row_index >= height:
					row_index = 0
					column_index += 1
				
				counter += 1
	
		modImg = Image.fromarray(pixels)
		if img.format == 'JPEG':
			modImg.save("modbild.jpg", quality=70)
		else:
			modImg.save(f"modbild.{formatImg}")	
	except Exception as e:
		print(f"failed with {e}")


def scanImage(path, length):
	img = Image.open(path)
#	img = img.convert("RGBA")
	pixels = np.array(img)
	width, height = img.size

	result = []

	row_index = 0
	column_index = 0

	for x in range(0,int(length)):
		value = 0

		for n in range(0,8):
			if n > 3:
				bit = pixels[column_index, row_index, n%4] & 1
			else:
				bit = pixels[column_index, row_index, n] & 1
	
			if value == 0:
				value = (value | bit)
			else:
				value = value << 1
				value = (value | bit)

			if (n+1) % 4 == 0:
				row_index += 1
			if row_index >= height:
				row_index = 0
				column_index += 1
		result.append(value)

	result = [chr(int(x)) for x in result]
	result = ''.join([str(x) for x in result])
	result = bytes(result, encoding='utf8')
	padding = (len(result)-3)%4
	result += b'='*(4-padding)
	result = result[2:-1]
	result = base64.b64decode(result)	
	return result


def decryptMessage(embeddedMessage):
	pwd = input("Password: ")
	with open("key.pem", "rb") as key_file:
				private_key = serialization.load_pem_private_key(key_file.read(), password=str.encode(pwd))
	
	decrypted_message = private_key.decrypt(embeddedMessage, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	print(decrypted_message)


def printHelp():
	print("-------------------------------------------")
	print("Syntax: filename.py -[command] [arguments]")
	print("-------------------------------------------")
	print("Available Commands: \ne\nd\ngenerate_keys\nmy_public_key")
	print("-------------------------------------------")


def argParser(args):
	return ARGS.get(args)

ARGS = {
	**dict.fromkeys(["h", "help"], printHelp),
	**dict.fromkeys(["encrypt"], [encodeMessage, embedMessage]),
	**dict.fromkeys(["decrypt"], [scanImage, decryptMessage]),
	**dict.fromkeys(["generate_keys"], generateKeys),
	**dict.fromkeys(["my_public_key"], showMyPublicKey)
}


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Steganography script with built-in RSA encryption for message.", prefix_chars="-")
	subparser = parser.add_subparsers(dest="command")
	encrypt_parser = subparser.add_parser("encrypt")
	encrypt_parser.add_argument("-m", type=str, required=True, help="Message")
	encrypt_parser.add_argument("-p", type=str, required=True, help="Path")

	decrypt_parser = subparser.add_parser("decrypt")
	decrypt_parser.add_argument("-p", type=str, required=True, help="Path")
	decrypt_parser.add_argument("-l", type=int, required=True, help="Length of message")

	keygen_parser = subparser.add_parser("generate_keys")	
	showpublic_parser = subparser.add_parser("my_public_key")

	args = parser.parse_args()
	if args.command == 'encrypt':
		argParser(args.command)[1](argParser(args.command)[0](args.m), args.p)
	elif args.command == 'decrypt':
		argParser(args.command)[1](argParser(args.command)[0](args.p, args.l))
	else:
		argParser(args.command)()
	
