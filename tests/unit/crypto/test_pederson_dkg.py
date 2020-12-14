import pytest
from nucypher.crypto.dkg import *


def test_pederson_dkg():
    poly_comm, comm_proof, shares = gen_pederson_shares(3, 5, b'test ceremony id')
    
    # Check that the output is correct for the given parameters
    assert len(shares) == 5
    assert len(poly_comm) == 3

    # Check that the commitments are valid
    assert verify_pederson_commitment(poly_comm, comm_proof, b'test ceremony id')

    # Check that invalid commitments abort
    with pytest.raises(Exception):
        assert not verify_pederson_commitment(poly_comm, comm_proof, b'bad ceremony id')

    # Check that the shares are valid
    for share in shares:
        assert verify_pederson_share(share, poly_comm)

    # Check that invalid shares abort
    _, _, bad_shares = gen_pederson_shares(3, 5, b'wrong ceremony')
    with pytest.raises(Exception):
        assert not verify_pederson_share(bad_shares[0], poly_comm)
