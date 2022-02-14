from Set2.challenge9 import pkcs_padding
from Set1.challenge7 import ecb_decrypt, ecb_encrypt
from Crypto.Random import get_random_bytes
from random import randint


# Challenge 13

class Profile:
    def __init__(self):
        self.key = get_random_bytes(16)

    @staticmethod
    def k_v_parser(input_str):
        k_v_list = input_str.split('&')
        obj_dict = dict()
        for item in k_v_list:
            obj_list = item.split('=')
            obj_dict[obj_list[0]] = obj_list[1].strip()
        return obj_dict

    @staticmethod
    def profile_for(input_email):
        stripped_email = input_email.replace('&', '').replace('=', '')
        user_dict = dict()
        user_dict["email"] = stripped_email
        user_dict["uid"] = str(randint(10, 99))
        user_dict["role"] = "user"
        return ("email=" + user_dict["email"] + "&uid=" + user_dict["uid"] + "&role=" + user_dict["role"]).encode()

    def encrypt_profile(self, profile_encoding):
        return ecb_encrypt(pkcs_padding(profile_encoding, 16), self.key)

    def decrypt_profile(self, cipher_str):
        return self.k_v_parser(ecb_decrypt(cipher_str, self.key).decode())


def make_profile_admin(target_email):
    pro = Profile()
    profile_str = pro.profile_for(target_email)
    cipher_str = pro.encrypt_profile(profile_str)

    # Adjust cipher_str to our needs by rotating the blocks
    num_blocks = len(cipher_str) // 16
    blocks = [cipher_str[i*16:(i+1)*16] for i in range(num_blocks)]
    profile_str = blocks[0]+blocks[1]+blocks[3]+blocks[2]
    return pro.decrypt_profile(profile_str)