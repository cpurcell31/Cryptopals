from Crypto.Random import get_random_bytes
from itertools import zip_longest
from binascii import unhexlify, hexlify
from binascii import Error as bError
from time import sleep
import web

from Set4.challenge31 import hmac_sha1

key = get_random_bytes(16)

urls = (
    '/', 'index',
    '/test?', 'test'
)

hashes = {'foo': hmac_sha1(key, b'YELLOW SUBMARINE')}


# A very simple web application for challenge31

def insecure_compare(hmac_hash, signature):
    hmac = hexlify(hmac_hash)
    print(hmac)
    sig = signature.encode()
    if len(sig) > len(hmac):
        return False
    for hash_byte, sig_byte in zip_longest(hmac, sig):
        if hash_byte != sig_byte:
            return False
        sleep(0.05)
    return True


class index:

    @staticmethod
    def GET():
        return "Hello World"


class test:

    @staticmethod
    def GET():
        i = web.input(file=None, signature=None)
        file = i.file
        signature = i.signature
        if insecure_compare(hashes[file], signature):
            return "File Found!"
        else:
            return web.InternalError("Invalid Signature")


if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()







