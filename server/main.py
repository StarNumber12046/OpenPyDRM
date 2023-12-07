import flask
import os
import random
import string
import dill
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

aes_key = get_random_bytes(32)
cipher = AES.new(aes_key, AES.MODE_CBC)

f = open('mykey.pem','r')
key = RSA.import_key(f.read())

fp = open('publickey.pem', 'rb')
public_key = RSA.import_key(fp.read())


keys = {"1234": "225373651154460"} 
tokens = {}
rsa_keys = {}
app = flask.Flask("")

def hello(name: str):
    print("Hello, {}".format(name))

def encode_asset(asset):
    return dill.dumps(asset)

assets = {"hello": encode_asset(hello)}

@app.route("/login")
def login():
    if keys[flask.request.headers.get("key", "")] == flask.request.headers.get("HWID", ""):
        token = "".join(random.sample(string.ascii_letters+string.digits, 16))
        tokens[flask.request.headers.get("HWID", "")] = token
        return token
    
    return flask.Response(status=401, response="Unauthorized")

@app.route("/asset/<string:asset_name>/")
def get_asset(asset_name):
    
    if flask.request.headers.get("Authorization", "") != tokens.get(flask.request.headers.get("HWID", ""), "notfound"):
        return flask.Response(status=401, response="Unauthorized")
    if asset_name in assets:
        padded_data = pad(assets[asset_name], AES.block_size)
        encrypted_asset = base64.b64encode(cipher.encrypt(padded_data))
        return encrypted_asset
    return flask.Response(status=404, response="Asset not found")

@app.route("/key", methods=["POST"])
def send_rsa_public_key():
    if flask.request.headers.get("Authorization", "") != tokens.get(flask.request.headers.get("HWID", ""), "notfound"):
        return flask.Response(status=401, response="Unauthorized")
    rsa_keys[flask.request.headers.get("Authorization", "")]  = flask.request.get_data()
    return "OK"

@app.route("/aes_key")
def send_aes_key():
    if flask.request.headers.get("Authorization", "") != tokens.get(flask.request.headers.get("HWID", ""), "notfound"):
        return flask.Response(status=401, response="Unauthorized")
    if flask.request.headers.get("Authorization", "") not in rsa_keys.keys():
        return flask.Response(status=400, response="Missing RSA encryption key")
    key = RSA.import_key(base64.b64decode(rsa_keys[flask.request.headers.get("Authorization", "")]))
    rsa_cipher = PKCS1_OAEP.new(key)
    
    return base64.b64encode(rsa_cipher.encrypt(aes_key)).decode("utf-8")

@app.route("/iv")
def send_iv():
    return base64.b64encode(cipher.iv).decode("utf-8")


app.run("127.0.0.1", 8080)