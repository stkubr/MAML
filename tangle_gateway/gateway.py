from flask import Flask, jsonify
from flask import render_template_string
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import hash_tryte, AuthMessage, AuthCommunicator
from tangle_connector import TangleConnector

tangle_con = TangleConnector()
auth_comm = AuthCommunicator()

app = Flask(__name__)

@app.route('/web+iota:/<pubkey>')
def get_certficate(pubkey):
    auth_txs = auth_comm.get_self_auth_txs_from_endpoint(pubkey)
    if auth_txs:
        latest_auth_tx = sorted(auth_txs, key=lambda x: x.timestamp, reverse=True)[0]
        payload = latest_auth_tx.auth_msg.payload
    else:
        payload = f"No transactions from endpoint: {pubkey}"
    return render_template_string(payload)

@app.route('/submit_page')
def submit_page():
    prikey, pubkey = Ed25519Cipher.generate_keys()
    pubkey_str = pubkey.to_ascii(encoding='base64').decode()
    address = hash_tryte(pubkey_str)
    html = '''
    <!DOCTYPE html>
    <html>
    
    <head>
    <title>Web+IOTA test page</title>
    </head>
    
    <body>
    
    <h1>Welcome to IOTA-based decentralized internet!</h1>
    
    </body>
    </html>
    '''
    msg = AuthMessage().finalize(html, pubkey, prikey)
    tangle_con.send_msg_to_addr(Address(address),
                                msg.to_json(),
                                tag='IOTA9GATEWAY')
    return jsonify(msg.to_json()), 200


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(port = port)