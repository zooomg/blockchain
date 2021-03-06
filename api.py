import json
import rsa
from urllib.parse import urlparse
from ast import literal_eval

import requests
from flask import Flask, jsonify, request
import threading
import signal
from time import sleep, time
from argparse import ArgumentParser

import blockchain

parser = ArgumentParser()
parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
args = parser.parse_args()
port = args.port

# Instantiate the Node
app = Flask(__name__)

# Instantiate the Blockchain
blockchain = blockchain.Blockchain(str(port))

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
        response = {'message': "Previous Steps {phase}"}
        return jsonify(response), 202

    if phase == 0:      # pre-prepare
        if node_id != blockchain.leader[0]:
            print("NOT LEADER ERROR")
            response = {'message': "Leader Error"}
            return jsonify(response), 400
        # get block
        block = data.get('block')
        # check either index is right (prevent replay attack)
        block_idx = block.get('index')
        if not blockchain.valid_idx(block_idx):
            print("INVALID INDEX ERROR")
            response = {'message': "WRONG INDEX OF BLOCK"}
            return jsonify(response), 400
        # check the time (prevent DDoS attack)
        block_time = block.get('timestamp')
        if not blockchain.valid_timestamp(block_time):
            print("WRONG TIMESTAMP ERROR")
            response = {'message': "WRONG TIMESTAMP OF BLOCK"}
            return jsonify(response), 400
        # update blockchain's view block to block
        blockchain.current_block = block
        # status reset
        blockchain.status[0] = 1
        # exec prepare phase
        threading.Thread(target=blockchain.prepare).start()
        # response
        response = {'id': blockchain.node_identifier, 'result': True}   # block is valid
        return jsonify(response), 201
    elif phase == 1:    # prepare
        # get block
        block = data.get('block')
        # check either index is right (prevent replay attack)
        block_idx = block.get('index')
        if not blockchain.valid_idx(block_idx):
            response = {'message': "WRONG INDEX OF BLOCK"}
            return jsonify(response), 400
        # check either id is unique(to use set) and block is same
        if blockchain.status[2].get(str(block), None) is None:  # if new block
            blockchain.status[2][str(block)] = {node_id}
        else:                                                   # exist block
            blockchain.status[2][str(block)].add(node_id)

        response = {'id': blockchain.node_identifier, 'result': True}

        # 2/3 blocks before pre-prepare
        if blockchain.current_block is None:
            response = {'id': blockchain.node_identifier, 'result': False}
            return jsonify(response), 201

        # when count is over 2/3 nodes, exec commit phase
        if len(blockchain.nodes) * 2 < len(blockchain.status[2][str(blockchain.current_block)]) * 3:
            blockchain.status[0] = 2
            threading.Thread(target=blockchain.commit).start()
    elif phase == 2:    # commit
        # check either index is right (prevent replay attack)
        block_idx = data.get('index')
        if not blockchain.valid_idx(block_idx):
            response = {'message': "WRONG INDEX OF BLOCK"}
            return jsonify(response), 400
        # check either id is unique(to use set)
        result = literal_eval(data.get('result'))
        if result == True:
            blockchain.status[3][0].add(node_id)
        else:
            blockchain.status[3][1].add(node_id)

        # when True count is over 2/3 nodes, send result to mid server
        if len(blockchain.nodes) * 2 < len(blockchain.status[3][0]) * 3:
            # add current block to chain
            blockchain.add_block()
            # TODO : send result to mid server
            # reset the settings
            blockchain.status = [0, None, {}, (set(), set())]
            blockchain.transactions_buffer = [x for x in blockchain.transactions_buffer if x not in blockchain.current_transactions]
            blockchain.current_block = None
            blockchain.current_transactions = []
            pass

        # when False count is over 1/3 nodes, send result to mid server
        if len(blockchain.nodes) < len(blockchain.status[3][1]) * 3:
            # TODO : send result to mid server
            # TODO : reset the settings
            for tx in blockchain.current_transactions:
                rand_id = tx.get('rand_id')
                blockchain.utxo[rand_id] = False

            blockchain.transactions_buffer += blockchain.current_transactions
            blockchain.current_transactions = []
            # TODO : leader change
            pass
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

@app.route('/append_genesis', methods=['POST'])
def append_genesis():
    values = request.get_json()
    # TODO : auth pubkey 확인
    blockchain.append_genesis(values)
    response = {'message': f'ang gimotti'}
    return jsonify(response), 201


@app.route('/utxo/new', methods=['POST'])
def new_utxo():
    values = request.get_json()
    if blockchain.add_utxo(values):
        response = {'message': f'UTxO will be added to list'}
        return jsonify(response), 201
    else:
        response = {'message': f'Invalid UTxO'}
        return jsonify(response), 400


@app.route('/utxo/list', methods=['GET'])
def get_utxo():
    print(blockchain.utxo)
    print(list(blockchain.utxo.keys()))
    response = {'utxo': list(blockchain.utxo.keys())}
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # TODO : After jwt
    # Create a new Transaction
    if blockchain.new_transaction(values):
        response = {'message': f'transaction will be added to buffer'}
        return jsonify(response), 201
    else:
        response = {'message': f'Invalid transaction'}
        return jsonify(response), 400

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/transactions/list', methods=['GET'])
def get_transactions():
    response = {'utxo': blockchain.transactions_buffer}
    return jsonify(response), 200

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

    # TODO : decrypt to auth's pubkey

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
            blockchain.consensus_start()

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

@app.route('/leader/tx_resolve', methods=['POST'])
def tx_resolve():
    values = request.get_json()
    print("test", values)

    cdata = bytes(values.get('data'))
    sign = bytes(values.get('sign'))
    node_id = values.get('id')
    data = rsa.decrypt(cdata, blockchain.prikey)

    if not rsa.verify(data, sign, blockchain.nodes[node_id][1]):
        print("VERIFY ERROR")
        response = {'message': "Verify Error"}
        return jsonify(response), 400

    data = literal_eval(data.decode('utf8'))
    txs = data.get('txs')

    if str(txs) in blockchain.resolve_cnt:
        blockchain.resolve_cnt[str(txs)] += 1
    else:
        blockchain.resolve_cnt[str(txs)] = 1

    if len(blockchain.nodes) < blockchain.resolve_cnt[str(txs)]*2:
        blockchain.transactions_buffer += txs
        blockchain.resolve_cnt = {}

    response = {
        'message': 'Tx resolve'
    }
    return jsonify(response), 201

@app.route('/nodes/leader/list', methods=['GET'])
def get_leader():
    response = {'nodes': blockchain.leader}
    return jsonify(response), 200

# 제거해야함
@app.route('/drop', methods=['GET'])
def drop_tx():
    tx = blockchain.transactions_buffer.pop()
    response = {'tx': tx}
    return jsonify(response), 200

@app.route('/nodes/leader/heartbeat', methods=['POST'])
def heartbeat():
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
    heartbeat_idx = data.get('heartbeat')

    if heartbeat_idx != blockchain.heartbeat + 1:
        print("HEARTBEAT INDEX ERROR")
        response = {'message': "Heartbeat Error"}
        return jsonify(response), 400

    # Reset timer
    blockchain.timer_chk = True
    
    if len(blockchain.transactions_buffer) > 0:
        blockchain.retrans += 1
        if blockchain.retrans == 3:
            blockchain.tx_resolve()
    else:
        blockchain.retrans = 0

    response = {
        'message': 'Get heartbeat'
    }
    return jsonify(response), 201


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, threaded=True)