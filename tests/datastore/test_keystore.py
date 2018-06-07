import pytest

from datetime import datetime
from nucypher.datastore import datastore, keypairs


def test_key_sqlite_datastore(test_datastore, bob):

    # Test add pubkey
    test_datastore.add_key(bob.stamp, is_signing=True)

    # Test get pubkey
    query_key = test_datastore.get_key(bob.stamp.fingerprint())
    assert bytes(bob.stamp) == bytes(query_key)

    # Test del pubkey
    test_datastore.del_key(bob.stamp.fingerprint())
    with pytest.raises(datastore.NotFound):
        del_key = test_datastore.get_key(bob.stamp.fingerprint())


def test_policy_arrangement_sqlite_datastore(test_datastore):
    alice_keypair_sig = keypairs.SigningKeypair(generate_keys_if_needed=True)
    alice_keypair_enc = keypairs.EncryptingKeypair(generate_keys_if_needed=True)
    bob_keypair_sig = keypairs.SigningKeypair(generate_keys_if_needed=True)

    hrac = b'test'

    # Test add PolicyArrangement
    new_arrangement = test_datastore.add_policy_arrangement(
            datetime.utcnow(), b'test', hrac, alice_pubkey_sig=alice_keypair_sig.pubkey,
            alice_signature=b'test'
    )

    # Test get PolicyArrangement
    query_arrangement = test_datastore.get_policy_arrangement(hrac)
    assert new_arrangement == query_arrangement

    # Test del PolicyArrangement
    test_datastore.del_policy_arrangement(hrac)
    with pytest.raises(datastore.NotFound):
        del_key = test_datastore.get_policy_arrangement(hrac)


def test_workorder_sqlite_datastore(test_datastore):
    bob_keypair_sig1 = keypairs.SigningKeypair(generate_keys_if_needed=True)
    bob_keypair_sig2 = keypairs.SigningKeypair(generate_keys_if_needed=True)

    hrac = b'test'

    # Test add workorder
    new_workorder1 = test_datastore.add_workorder(bob_keypair_sig1.pubkey, b'test0', hrac)
    new_workorder2 = test_datastore.add_workorder(bob_keypair_sig2.pubkey, b'test1', hrac)

    # Test get workorder
    query_workorders = test_datastore.get_workorders(hrac)
    assert {new_workorder1, new_workorder2}.issubset(query_workorders)

    # Test del workorder
    deleted = test_datastore.del_workorders(hrac)
    assert deleted > 0
    assert test_datastore.get_workorders(hrac).count() == 0
