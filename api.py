import json
import rsa
from urllib.parse import urlparse
from ast import literal_eval

import requests
from flask import Flask, jsonify, request
from threading import Thread
import signal
from time import sleep

import blockchain

# Instantiate the Node
app = Flask(__name__)

# Genesis block
genesis_block = blockchain.init_genesis_block()

# Instantiate the Blockchain
blockchain = blockchain.Blockchain(genesis_block)

# {
#     'phase': 0              # pre-prepare = 0, prepare = 1, commit = 2
#     'block': proposal       # in phase 0-1
#     'vote': True or False   # in phase 2
# }
@app.route('/consensus', methods=['POST'])
def consensus():
    values = request.get_json()
    cdata = bytes(values.get('data'))
    sign = bytes(values.get('sign'))
    node_id = values.get('id')
    data = rsa.decrypt(cdata, blockchain.prikey)

    if not rsa.verify(data, sign, blockchain.nodes[node_id][1]):
        print("VERIFY ERROR")
        response = {'message': "Verify Error"}
        return jsonify(response), 400

    data = literal_eval(data.decode('utf8'))
    phase = data.get('phase')

    response = None

    # to prevent replaying previous steps
    if phase < blockchain.status[0]:
        print("PREVIOUS STEPS")
        response = {'message': "Previous Steps"}
        return jsonify(response), 202

    if phase == 0:      # pre-prepare
        if node_id != blockchain.leader[0]:
            print("NOT LEADER ERROR")
            response = {'message': "Leader Error"}
            return jsonify(response), 400
        # TODO : check either index is right (prevent replay attack)
        # get block
        block = data.get('block')
        # block validation
        valid = True    # TODO : validation function
        if valid:
            # update blockchain's view block to block
            blockchain.current_block = block
            # status reset
            blockchain.status = [1, block, {str(block): {blockchain.leader[0], blockchain.node_identifier}}, (0, 0)]
            # TODO : exec prepare phase
            blockchain.prepare()
            # response
            response = {'id': blockchain.node_identifier, 'result': True}   # block is valid
        else:
            # response
            response = {'id': blockchain.node_identifier, 'result': False}  # block is invalid
    elif phase == 1:    # prepare
        # get block
        block = data.get('block')
        # TODO : check either index is right (prevent replay attack)
        # TODO : check either id is unique and block is same
        if blockchain.status[2].get(str(block), None) is None:  # if new block
            blockchain.status[2][str(block)] = {node_id}
        else:                                                   # exist block
            blockchain.status[2][str(block)].add(node_id)
        # TODO : when count is over 2/3 nodes, exec commit phase
        if (len(blockchain.nodes) + 1) * 2 < len(blockchain.status[2][str(blockchain.current_block)]) * 3:
            blockchain.status[0] = 2
            # blockchain.commit(True)
    elif phase == 2:    # commit
        # TODO : check either index is right (prevent replay attack)
        # TODO : check either id is unique
        result = data.get('result')
        # TODO :when count is over 2/3 nodes, send result to mid server
    else:               # error
        pass

    return jsonify(response), 201


# @app.route('/mine', methods=['GET'])
# def mine():
#     # We run the proof of work algorithm to get the next proof...
#     last_block = blockchain.last_block
#     last_proof = last_block['proof']
#     proof = blockchain.proof_of_work(last_proof)

#     # We must receive a reward for finding the proof.
#     # The sender is "0" to signify that this node has mined a new coin.
#     blockchain.new_transaction(
#         sender="0",
#         recipient=node_identifier,
#         amount=1,
#     )

#     # Forge the new Block by adding it to the chain
#     previous_hash = blockchain.hash(last_block)
#     block = blockchain.new_block(proof, previous_hash)

#     response = {
#         'message': "New Block Forged",
#         'index': block['index'],
#         'transactions': block['transactions'],
#         'proof': block['proof'],
#         'previous_hash': block['previous_hash'],
#     }
#     return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


# @app.route('/transactions/new', methods=['POST'])
# def new_transaction():
#     values = request.get_json()

#     # Check that the required fields are in the POST'ed data
#     required = ['sender', 'recipient', 'amount']
#     if not all(k in values for k in required):
#         return 'Missing values', 400

#     # Create a new Transaction
#     index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

#     response = {'message': f'Transaction will be added to Block {index}'}
#     return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/id', methods=['GET'])
def get_id():
    response = {'id': f'{blockchain.node_identifier}'}
    return jsonify(response), 200


@app.route('/pubkey', methods=['GET'])
def get_pubkey():
    str_pubkey = str(blockchain.pubkey)
    parse_pubkey = str_pubkey.split('(')[1][:-1].split(' ')
    parse_num = {}
    parse_num['e'] = int(parse_pubkey[1])
    parse_num['n'] = int(parse_pubkey[0][:-1])

    response = {'pubkey': parse_num}
    return jsonify(response), 200


@app.route('/connected_nodes', methods=['GET'])
def get_connected_nodes():
    response = {'nodes': list(blockchain.nodes.keys())}
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    leader_idx = values.get('leader_idx')
    blockchain.leader_idx = leader_idx

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        node_id = node.get('id')
        node_addr = node.get('address')
        node_pubkey = rsa.PublicKey(**node.get('pubkey'))
        is_leader = node.get('leader')

        if is_leader is True:
            blockchain.leader = (node_id, node_addr)

        if node_id != blockchain.node_identifier:
            blockchain.register_node(node_id, node_addr, node_pubkey)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes.keys()),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def nodes_resolve():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


@app.route('/nodes/leader', methods=['GET'])
def get_leader():
    response = {'nodes': blockchain.leader}
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def do_it_now():
    response = blockchain.pre_prepare()
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
