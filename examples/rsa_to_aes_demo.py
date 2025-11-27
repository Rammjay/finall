from ucap.core.capabilities import Capabilities
from ucap.core.session_manager import Session
from ucap.plugins.rsa_oaep.rsa_module import RSA_OAEP
from ucap.plugins.aes_gcm.aes_module import AES_GCM

plugins = {
    "RSA_OAEP": RSA_OAEP(),
    "AES_GCM": AES_GCM(),
}

deviceA = Capabilities(crypto_list=["RSA_OAEP"], features=["ENCRYPT", "DECRYPT"])
deviceB = Capabilities(crypto_list=["AES_GCM"], features=["ENCRYPT", "DECRYPT"])

session = Session(deviceA, deviceB, plugins)

plaintext = b"THIS IS A UCAP TEST MESSAGE"

encrypted = session.send_A_to_B(plaintext)

print("Original:", plaintext)
print("Encrypted Output:", encrypted)
print("Len:", len(encrypted))
