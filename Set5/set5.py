from Set5.challenge33 import diffie_hellman_generate
from Set5.challenge34 import diffie_mitm
from Set5.challenge35 import negotiated_groups_mitm
from Set5.challenge36 import controller
from Set5.challenge37 import srp_zero_key_attack, srp_n_key_attack


def set5_solutions():
    #print(diffie_hellman_generate())
    #print(diffie_mitm())
    #negotiated_groups_mitm()
    controller()
    srp_zero_key_attack()
    srp_n_key_attack()


