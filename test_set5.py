from Set5.challenge34 import diffie_mitm


def test_challenge34():
    msg_a, msg_b = diffie_mitm()
    assert msg_a == msg_b
