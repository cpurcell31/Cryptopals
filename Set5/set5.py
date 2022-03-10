from Set5.challenge33 import diffie_hellman_generate
from Set5.challenge34 import diffie_mitm
from Set5.challenge35 import negotiated_groups_mitm
from Set5.challenge36 import controller
from Set5.challenge37 import srp_zero_key_attack, srp_n_key_attack
from Set5.challenge38 import simplified_srp_controller, mitm_simplified_srp
from Set5.challenge39 import rsa_keygen, rsa_encrypt, rsa_decrypt


def set5_solutions():
    #print(diffie_hellman_generate())
    #print(diffie_mitm())
    #negotiated_groups_mitm()
    controller()
    srp_zero_key_attack()
    srp_n_key_attack()
    #simplified_srp_controller()
    mitm_simplified_srp()
    n, e, d = rsa_keygen()
    byte_str = b'Happy Birthday!'
    c = rsa_encrypt(n, e, byte_str)
    print(c)
    byte_str = rsa_decrypt(n, d, c)
    print(byte_str)


