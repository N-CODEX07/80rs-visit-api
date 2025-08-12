import httpx
import json
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, request, jsonify

app = Flask(__name__)

# Encryption configuration
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

############ ENCRYPT-UID ##############
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    
    x = x / 128 
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                data = json.load(f)
                # Handle the special format with multiple "token" keys
                if isinstance(data, dict):
                    return [v for k, v in data.items() if k == "token"]
                return []
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return [v for k, v in data.items() if k == "token"]
                return []
        else:
            with open("token_bd.json", "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return [v for k, v in data.items() if k == "token"]
                return []
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return []

def get_url(server_name):
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        return "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

async def send_request(player_id, jwt_token, region):
    try:
        encrypted_id = Encrypt_ID(player_id)
        encrypted_api = encrypt_api(f"08{encrypted_id}1007")
        target = bytes.fromhex(encrypted_api)
        
        url = get_url(region)
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "ob50",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br",
        }

        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.post(url, headers=headers, data=target)
            return {
                "status": response.status_code,
                "success": response.status_code == 200
            }
    except Exception as e:
        return {
            "error": str(e),
            "success": False
        }

@app.route('/attack', methods=['GET'])
async def attack_handler():
    player_id = request.args.get('uid')
    region = request.args.get('region', 'IND')
    
    if not player_id:
        return jsonify({"status": "error", "message": "uid parameter is required"}), 400

    try:
        # Validate player_id is numeric
        int(player_id)
    except ValueError:
        return jsonify({"status": "error", "message": "uid must be a numeric value"}), 400

    # Load tokens for the specified region
    tokens = load_tokens(region)
    if not tokens:
        return jsonify({"status": "error", "message": f"No valid tokens found for region {region}"}), 400

    # Limit to 100 tokens
    token_list = tokens[:100]
    
    # Send requests concurrently
    tasks = [send_request(player_id, jwt_token, region) for jwt_token in token_list]
    results = await asyncio.gather(*tasks)
    
    # Calculate success rate
    success_count = sum(1 for r in results if r.get('success'))
    
    return jsonify({
        "status": "completed",
        "region": region,
        "target": player_id,
        "tokens_used": len(token_list),
        "success_count": success_count,
        "failure_count": len(token_list) - success_count,
        "success_rate": f"{(success_count/len(token_list)*100):.2f}%"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8399, debug=False)
