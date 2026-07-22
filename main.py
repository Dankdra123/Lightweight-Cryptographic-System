from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


##### PUBLIC KEY INFASTRUCTURE#################################

##create CA with its own RSA pair, signs user certs
def create_ca():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    cert = {"subject": "CA", "public_key": public, "valid": True}
    return private, public, cert


###verify certificate by checking sig matches CA pub key and not been revoked

def issue_cert(ca_private, name, public_key):
    cert = {"subject": name, "public_key": public_key, "valid": True}
    cert_bytes = name.encode()
    cert["signature"] = ca_private.sign(cert_bytes, padding.PKCS1v15(), hashes.SHA256())
    return cert


def verify_cert(cert, ca_public):
    try:
        ca_public.verify(cert["signature"], cert["subject"].encode(),
                         padding.PKCS1v15(), hashes.SHA256())
        return cert["valid"]
    except:
        return False


#CRYPTOGRAPHY####################################


###encrypt the session key AES using RSAOAEP allowsa secure transfer
def rsa_wrap_key(public, key):
    return public.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )


####decrypt / unwrap plaintext message 

def rsa_unwrap_key(private, wrapped):
    return private.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )


def aes_encrypt(key, plaintext):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

#decrypt the cyphertext 
def aes_decrypt(key, nonce, ciphertext):
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)

##cintegrity verification
def sha256(data):
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize().hex()


#########################DEMONSTRATION SECTION####################################################

def demo():
    print("CA CREATION")
    ca_priv, ca_pub, ca_cert = create_ca()

    #generate keypair
    print("\nUSER KEYS AND CERTIFICATES")
    USER_A_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    USER_B_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        #issue certs
    USER_A_cert = issue_cert(ca_priv, "USER_A", USER_A_priv.public_key())
    USER_B_cert = issue_cert(ca_priv, "USER_B", USER_B_priv.public_key())

    #validate previous certs
    print("USER_A cert valid?", verify_cert(USER_A_cert, ca_pub))
    print("USER_B cert valid?", verify_cert(USER_B_cert, ca_pub))

    print("\n=== HYBRID ENCRYPTION (USER_A → USER_B) ===")
    plaintext = b"THIS IS A SECURE MESSAGE" #<-message to encrypt
    aes_key = os.urandom(32) #<-session key
    nonce, cipher = aes_encrypt(aes_key, plaintext)#<-encrypt the message
    wrapped = rsa_wrap_key(USER_B_priv.public_key(), aes_key)#<-wrap the key with userb public key
    hash_val = sha256(plaintext) #compute the hashfor integrity

    print("Message hash:", hash_val)

    print("\nUSER_B DECRYPTS")
    unwrap = rsa_unwrap_key(USER_B_priv, wrapped)#unwrap the AES key
    decrypted = aes_decrypt(unwrap, nonce, cipher)#and decrypt the cypertext
    print("Decrypted:", decrypted)
    print("Hash correct?", sha256(decrypted) == hash_val)

    print("\nREVOCATION DEMO") #simulate revocation, SHOULD fail here
    USER_A_cert["valid"] = False
    print("USER_A cert valid after revocation?", verify_cert(USER_A_cert, ca_pub))


if __name__ == "__main__":
    demo()
