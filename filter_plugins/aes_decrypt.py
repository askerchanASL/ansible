from ansible.errors import AnsibleFilterError
from Crypto.Cipher import AES
import base64

def custom_decrypt(encrypted_text, key):
    try:
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_text)
        key_bytes = key.encode('utf-8')

        # AES requires key length of 16, 24, or 32 bytes
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted_bytes)

        # Remove padding
        return decrypted.decode('utf-8').rstrip('\x00')
    except Exception as e:
        raise AnsibleFilterError(f"Decryption failed: {e}")

class FilterModule(object):
    def filters(self):
        return {
            'custom_decrypt': custom_decrypt
        }