import json
import rsa
from uuid import uuid4
from urllib.parse import urlparse
import requests
import random

nodes_addr = ["http://172.17.64.185:5000",
              "http://172.17.64.185:5001",
              "http://172.17.67.233:5000",
              "http://172.17.67.233:5001"]

# nodes_addr = ["http://127.0.0.1:5002",
#               "http://127.0.0.1:5000",
#               "http://127.0.0.1:5001"]

utxo_list = []
candidate_list = ['X', 'Y', 'Z']

pubkey, prikey = None, None

def init_key():
    global pubkey, prikey
    init_pubkey = {
        'e': 65537,
        'n': 17809337809702581702806712750053855729116615216583132187723237673838818997862296690261064757625415664990204748919188173181942765055081418828098039146431896266688540311566257421970474465165733940444107217057017214471218490459283519787553499209929334460323792755288443804920738718853804105499649811677109466929811357788771159957275809186164999242515624152177284219205274328856370640031144310994904160761505104630562313240588506017841870945278152662353349372756482500998680942480381750645179533581431845207703425055137502840627577875951162237565176494850997789361250424373942732156204282322009099409257140674930124768817
    }
    init_prikey = {
        'd': 8635233953017668473840561988776742504297399663356000297988637312687125612937275156421957898638369677989437055501549393155051272489667245160756082670188845502030330126198040223048900118705029638608608801690965958531087934622040258301251011556737788747512232210580296302683466046187914202059455957660070246672013707388028725388283474004439701732335559824827967096861669963189829941824516585965629044294111218357690041254335783942315396238136651664781307753945648078172134840883017681542040703410825306606009593032468927252803640570940767630212653502898544255203854156369414487479905724655891913524288647307673826367473,
        'p': 2889101189397481652920451123911715208805849172481004521631853092585858552794856554998630416553844276418166118795587307485932830737143880474114305660248662414590130328263330565982356269914968625350652178564036234855974316154950786493141881770142188545555571912788868828846901530836311780414199599335642657089169004438882513988317,
        'q': 6164317772966856954653010695983062419378205063584548072027557803303461108594358257763754659865802110819357359210132216647236847610628786224204552133958620614390099158275551219713792836086389527238593103708552375294789696469974419390423102997859504910315679091310636654313988940739068166501
    }
    pubkey = rsa.PublicKey(**init_pubkey)
    init_prikey.update(init_pubkey)
    prikey = rsa.PrivateKey(**init_prikey)

nodes = []

def get_info():
    for node in nodes_addr:
        url = node + '/id'
        response = requests.get(url=url)
        node_id, node_pubkey = None, None

        if response.status_code == 200:
            node_id = response.json()['id']

        url = node + '/pubkey'
        response = requests.get(url=url)

        if response.status_code == 200:
            node_pubkey = response.json()['pubkey']

        nodes.append({'id': node_id, 'address': node, 'pubkey': node_pubkey})

def send_tx():
    headers = {'Content-Type': 'application/json'}
    for utxo in utxo_list:
        for node in nodes:
            url = node + '/transactions/new'
            data = {'rand_id': utxo, 'candidate': candidate[random.randint(0, 2)]}
            node_pubkey = rsa.PublicKey(**node.get('pubkey'))
            cdata = rsa.encrypt(str(data).encode('utf8'), node_pubkey)
            sign = rsa.sign(cdata, prikey, 'SHA-1')
            fdata = {'data': list(cdata), 'sign': list(sign)}
            jdata = json.dumps(fdata)

            response = requests.post(url, headers=headers, data=jdata)

            if response.status_code == 201:
                msg = response.json()['message']

def init_uxto():
    utxo = str(uuid4()).replace('-', '')
    utxo_list.append(utxo)
    data = {'utxo': utxo}

    headers = {'Content-Type': 'application/json'}
    for node in nodes:
        url = node.get('address') + '/utxo/new'
        print(url)
        node_pubkey = rsa.PublicKey(**node.get('pubkey'))
        cdata = rsa.encrypt(str(data).encode('utf8'), node_pubkey)
        sign = rsa.sign(cdata, prikey, 'SHA-1')
        fdata = {'data': list(cdata), 'sign': list(sign)}
        jdata = json.dumps(fdata)
        
        response = requests.post(url, headers=headers, data=jdata)

        if response.status_code == 201:
            msg = response.json()['message']
            print(msg)

init_key()
print(pubkey)
get_info()

init_uxto()
init_uxto()
init_uxto()
init_uxto()
init_uxto()

send_tx()