from Crypto.PublicKey import RSA

key = RSA.generate(2048)
f = open('mykey.pem','wb')
f.write(key.export_key('PEM'))
f.close()

public_key = key.publickey().export_key()
file_out = open("publickey.pem", "wb")
file_out.write(public_key)
file_out.close()