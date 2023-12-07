from Crypto.PublicKey import RSA
import requests
import dill
import uuid
import base64
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad


class PyDrm:
    def __init__(self, key: str, URL: str) -> None:
        self.key = key
        self.URL = URL
        self.HWID = uuid.getnode()
        self.auth_token = None
        self.encryption_key = None
        self.encrypted_key = None
        self.private_key = None
        self.public_key = None
        self.iv = None
        pass
    
    def gethwid(self) -> int:
        """
        Return the hardware ID of the current machine.
        :return: An integer representing the hardware ID.
        """
        return self.HWID
    
    def getkey(self) -> str:
        """
        Get the key associated with this object.
        
        Returns:
            str: The key associated with this object.
        """
        return self.key
    
    def getbaseurl(self) -> str:
        """
        Returns the base URL.

        :return: The base URL as a string.
        """
        return self.URL
    
    def login(self):
        """
        Sends a login request to the DRM server and returns the authorization token and updates it in the class accordingly if the status code is 200.

        Returns:
            - str: The auth token to be used in future requests if the status code is 200.

        Raises:
            - ValueError: If the status code is not 200.
        """
        login_url = self.URL + "/login"
        response = requests.get(login_url, headers={
            "key": self.key,
            "HWID": str(self.gethwid())
        })
        
        if response.status_code == 200:
            self.auth_token = response.text
            return response.text
        
        else:
            raise ValueError("Failed to login to the DRM server")
       

    
    def get_iv(self):
        """
        Retrieves the initialization vector (IV) from the server.

        Returns:
            bytes: The IV as a byte string.
        """
        response = requests.get(self.URL + "/iv", headers={
            "Authorization": self.auth_token,
            "HWID": str(self.HWID)
        })
        self.iv = base64.b64decode(response.text.encode("utf-8"))
        return base64.b64decode(response.text)
    
    def retrieve_aes_key(self, encrypted_key: bytes, decryption_key: str) -> bytes:
        key_obj = RSA.import_key(decryption_key)
        cipher_public = PKCS1_OAEP.new(key_obj)
        decrypted_key = cipher_public.decrypt(encrypted_key)
        return decrypted_key
    
    def decrypt_asset(self, asset: bytes, key: str, iv: bytes) -> any:
        """
        Decrypts an asset using the given key.

        Args:
            - asset (str): The asset to decrypt.
            - key (str): The key to use for decryption.

        Returns:
            - any: The decrypted asset.
        """
        aes_cipher  = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = aes_cipher.decrypt(asset)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data
        
    def get_aes_encrypted_key(self):
        """
        Sends a request to the DRM server to get the RSA encrypted AES key associated with this object.

        Returns:
            - str: The key associated with this object.
        """
        response = requests.get(self.URL + "/aes_key", headers={
            "Authorization": self.auth_token,
            "HWID": str(self.HWID)
        })
        
        if response.status_code != 200:
            raise ValueError("Failed to get key from the DRM server")
        key = base64.b64decode(response.text)
        self.encrypted_key = key
        return key
    
    def send_public(self, key: bytes):
        """
        Sends a request to the DRM server to get the RSA encrypted AES key associated with this object.

        Returns:
            - str: The key associated with this object.
        """
        response = requests.post(self.URL + "/key", headers={
            "Authorization": self.auth_token,
            "HWID": str(self.HWID)
        }, data=base64.b64encode(key))
        
        if response.status_code != 200:
            raise ValueError("Failed to send key to the DRM server")
    
    def generate_rsa_key(self):
        """
        Generates a new key and returns it as a string.
        """
        key = RSA.generate(1024)
        self.private_key = key
        self.public_key = key.public_key()
        
        return key.public_key().export_key()
    
    def get_asset(self, asset_name:str, version:str="latest") -> any:
        """
        Sends a request to the DRM server to get the asset with the given name and version.

        Args:
            - asset_name (str): The name of the asset to get.
            - version (str): The version of the asset to get. Defaults to "latest".

        Returns:
            - str: The contents of the asset.
        """
        
        response = requests.get(self.URL + "/asset/" + asset_name + "/", headers={
            "Authorization": self.auth_token,
            "HWID": str(self.HWID)
        })
        
        if response.status_code == 404:
            raise ValueError("Asset not found")
        
        
        if response.status_code != 200:
            raise ValueError("Failed to login to the DRM server")
        
        self.send_public(self.generate_rsa_key())
        self.get_iv()
        encrypted_aes_key = self.get_aes_encrypted_key()
        aes_key = self.retrieve_aes_key(encrypted_aes_key, self.private_key.export_key().decode("utf-8")) 
        base64_decoded_asset = base64.b64decode(response.text.encode())
        asset = self.decrypt_asset(base64_decoded_asset, aes_key, self.iv)
        asset = dill.loads(asset) 
        
        return asset
        