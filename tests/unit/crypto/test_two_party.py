import pytest

from umbral.config import default_params
from umbral.curvebn import CurveBN
from umbral.point import Point
from nucypher.crypto.two_party import TwoPartyElement


def test_secret_splitting_and_reassembly():
    the_secret = CurveBN.gen_rand()
    known_share = CurveBN.gen_rand()
    known_index = CurveBN.gen_rand()

    # Get the resulting non-deterministic share
    non_deterministic_scalar = TwoPartyElement.split_curvebn(the_secret, known_share, known_index)
    
    # Check that the share isn't the secret
    assert non_deterministic_scalar.share != the_secret

    # Check that the share isn't the deterministic share
    assert non_deterministic_scalar.share != known_share
    assert non_deterministic_scalar.index != known_index

    # Check that we can reassemble with the correct scalars
    deterministic_scalar = TwoPartyElement(known_share, known_index)
    assert the_secret == non_deterministic_scalar.reassemble_with(deterministic_scalar)
    assert the_secret == deterministic_scalar.reassemble_with(non_deterministic_scalar)

    # Reassembly with the wrong scalar fails
    invalid_scalar = TwoPartyElement(CurveBN.gen_rand(), CurveBN.gen_rand())
    assert the_secret != invalid_scalar.reassemble_with(deterministic_scalar)
    assert the_secret != deterministic_scalar.reassemble_with(invalid_scalar)


def test_two_party_split_with_deterministic_shared_secret():
    the_secret = CurveBN.gen_rand()
    priv_key = CurveBN.gen_rand()
    share_point, index_point = Point.gen_rand(), Point.gen_rand()

    deterministic_scalar = TwoPartyElement.from_shared_secret(priv_key, share_point, index_point, default_params())
    non_deterministic_scalar = TwoPartyElement.split_curvebn(the_secret, deterministic_scalar.share,
                                                            deterministic_scalar.index)
    assert the_secret == non_deterministic_scalar.reassemble_with(deterministic_scalar)


def test_two_party_split_computation():
    the_secret = CurveBN.gen_rand()
    known_share = CurveBN.gen_rand()
    known_index = CurveBN.gen_rand()

    # Split the secret
    non_deterministic_scalar = TwoPartyElement.split_curvebn(the_secret, known_share, known_index)
    deterministic_scalar = TwoPartyElement(known_share, known_index)

    # Perform a two party computation of `S * r` for random `r`:
    rand_scalar = CurveBN.gen_rand()
    s_by_r_prime_share = non_deterministic_scalar.share * rand_scalar
    s_by_r_prime_prime_share = deterministic_scalar.share * rand_scalar

    # Re-assemble the computed value
    non_deterministic_scalar.share = s_by_r_prime_share
    deterministic_scalar.share = s_by_r_prime_prime_share
    assert (the_secret * rand_scalar) == deterministic_scalar.reassemble_with(non_deterministic_scalar)

    # Assembly with non-computed values doesn't compute correctly
    assert (the_secret * rand_scalar) != deterministic_scalar.reassemble_with(TwoPartyElement(known_share, known_index))
