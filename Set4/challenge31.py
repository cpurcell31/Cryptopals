from Set4.challenge28 import sha1
import requests


# Challenge 31
def hmac_sha1(key, msg):
    block_size = 64
    block_key = key

    if len(key) > block_size:
        block_key = sha1(key)
    elif len(key) < block_size:
        block_key = key + b'\x00' * (block_size - len(key))

    outer_key_pad = b''.join([(key_byte ^ matrix_byte).to_bytes(1, 'big')
                              for key_byte, matrix_byte in zip(block_key, b'\x5c'*block_size)])
    inner_key_pad = b''.join([(key_byte ^ matrix_byte).to_bytes(1, 'big')
                              for key_byte, matrix_byte in zip(block_key, b'\x36'*block_size)])

    return sha1(outer_key_pad + sha1(inner_key_pad + msg))


def hmac_timing_attack():
    url = 'http://localhost:8080/test'
    params = {'file': 'foo', 'signature': None}
    hmac = b''
    session = requests.session()

    # THIS TAKES A VERY LONG TIME
    for j in range(40):
        times = list()
        for i in range(256):
            params['signature'] = hmac + i.to_bytes(1, 'big')
            r = session.get(url, params=params)
            elapsed = r.elapsed.total_seconds()
            if times:
                # If current byte gives time significantly above the mean we can break
                mean = sum(t for t in times) / len(times)
                if elapsed > mean + .03:
                    hmac += i.to_bytes(1, 'big')
                    print(hmac)
                    break
            times.append(elapsed)
    print(hmac)
