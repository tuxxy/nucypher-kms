import os

import collections
import pytest
from eth_utils import is_checksum_address

from nucypher.blockchain.eth.constants import MIN_ALLOWED_LOCKED, MIN_LOCKED_PERIODS

TestPolicyMetadata = collections.namedtuple('TestPolicyMetadata', 'policy_id author addresses')


@pytest.fixture(scope='function')
@pytest.mark.usefixtures('blockchain_ursulas')
def policy_meta(testerchain, three_agents):
    token_agent, miner_agent, policy_agent = three_agents
    origin, someone, *everybody_else = testerchain.interface.w3.eth.accounts
    agent = policy_agent

    _policy_id = os.urandom(16)
    node_addresses = list(miner_agent.sample(quantity=3, duration=1))
    _txhash = agent.create_policy(policy_id=_policy_id,
                                  author_address=someone,
                                  value=MIN_ALLOWED_LOCKED,
                                  periods=10,
                                  reward=20,
                                  node_addresses=node_addresses)

    return TestPolicyMetadata(_policy_id, someone, node_addresses)


@pytest.mark.slow()
@pytest.mark.usefixtures('blockchain_ursulas')
def test_create_policy(testerchain, three_agents):
    token_agent, miner_agent, policy_agent = three_agents
    origin, someone, *everybody_else = testerchain.interface.w3.eth.accounts
    agent = policy_agent

    policy_id = os.urandom(16)
    node_addresses = list(miner_agent.sample(quantity=3, duration=1))
    txhash = agent.create_policy(policy_id=policy_id,
                                 author_address=someone,
                                 value=MIN_ALLOWED_LOCKED,
                                 periods=10,
                                 reward=20,
                                 node_addresses=node_addresses)

    receipt = testerchain.wait_for_receipt(txhash)
    assert receipt['status'] == 1, "Transaction Rejected"
    assert receipt['logs'][0]['address'] == agent.contract_address


@pytest.mark.slow()
@pytest.mark.usefixtures('blockchain_ursulas')
def test_fetch_policy_arrangements(three_agents, policy_meta):
    token_agent, miner_agent, policy_agent = three_agents
    agent = policy_agent

    arrangements = list(agent.fetch_policy_arrangements(policy_id=policy_meta.policy_id))
    assert arrangements
    assert len(arrangements) == len(policy_meta.addresses)
    assert is_checksum_address(arrangements[0][0])
    assert list(record[0] for record in arrangements) == policy_meta.addresses


@pytest.mark.slow()
@pytest.mark.usefixtures('blockchain_ursulas')
def test_revoke_arrangement(three_agents, policy_meta):
    token_agent, miner_agent, policy_agent = three_agents
    agent = policy_agent

    txhash = agent.revoke_arrangement(policy_id=policy_meta.policy_id,
                                      author_address=policy_meta.author,
                                      node_address=policy_meta.addresses[0])
    testerchain = agent.blockchain
    receipt = testerchain.wait_for_receipt(txhash)
    assert receipt['status'] == 1, "Transaction Rejected"
    assert receipt['logs'][0]['address'] == agent.contract_address


@pytest.mark.slow()
@pytest.mark.usefixtures('blockchain_ursulas')
def test_revoke_policy(three_agents, policy_meta):
    token_agent, miner_agent, policy_agent = three_agents
    agent = policy_agent

    txhash = agent.revoke_policy(policy_id=policy_meta.policy_id, author_address=policy_meta.author)
    testerchain = agent.blockchain
    receipt = testerchain.wait_for_receipt(txhash)
    assert receipt['status'] == 1, "Transaction Rejected"
    assert receipt['logs'][0]['address'] == agent.contract_address


@pytest.mark.usefixtures('blockchain_ursulas')
def test_calculate_refund(testerchain, three_agents, policy_meta):
    token_agent, miner_agent, policy_agent = three_agents
    agent = policy_agent

    ursula = policy_meta.addresses[-1]
    testerchain.time_travel(hours=9)
    _txhash = miner_agent.confirm_activity(node_address=ursula)
    txhash = agent.calculate_refund(policy_id=policy_meta.policy_id, author_address=policy_meta.author)
    testerchain = agent.blockchain
    receipt = testerchain.wait_for_receipt(txhash)
    assert receipt['status'] == 1, "Transaction Rejected"


@pytest.mark.usefixtures('blockchain_ursulas')
def test_collect_refund(testerchain, three_agents, policy_meta):
    token_agent, miner_agent, policy_agent = three_agents
    agent = policy_agent

    testerchain.time_travel(hours=9)
    txhash = agent.collect_refund(policy_id=policy_meta.policy_id, author_address=policy_meta.author)
    testerchain = agent.blockchain
    receipt = testerchain.wait_for_receipt(txhash)
    assert receipt['status'] == 1, "Transaction Rejected"
    assert receipt['logs'][0]['address'] == agent.contract_address


@pytest.mark.slow()
@pytest.mark.usefixtures('blockchain_ursulas')
def test_collect_policy_reward(testerchain, three_agents, policy_meta):
    token_agent, miner_agent, policy_agent = three_agents
    agent = policy_agent

    ursula = policy_meta.addresses[-1]
    old_eth_balance = token_agent.blockchain.interface.w3.eth.getBalance(ursula)

    for _ in range(MIN_LOCKED_PERIODS):
        _txhash = miner_agent.confirm_activity(node_address=ursula)
        testerchain.time_travel(periods=1)

    txhash = agent.collect_policy_reward(collector_address=ursula)
    receipt = testerchain.wait_for_receipt(txhash)
    assert receipt['status'] == 1, "Transaction Rejected"
    assert receipt['logs'][0]['address'] == agent.contract_address
    new_eth_balance = token_agent.blockchain.interface.w3.eth.getBalance(ursula)
    assert new_eth_balance > old_eth_balance
