from flask import Flask, request, jsonify
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    now = datetime.now()
    now = str(now)[:len(str(now)) - 7]
    data = bytes.fromhex('1a13323032352d30332d30362030363a32343a3135220966726565206669726528013a07312e3132302e324232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520d41542654204d6f62696c6974795a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e309a012b476f6f676c657c31623833656335362d363635662d343064392d613436372d303637396438623762306231a2010d37342e3230382e3139372e3230aa0102656eb201206332303962666537343263306532613363613339656631313366336663613430ba010134c2010848616e6468656c64ca01104173757320415355535f493030354441ea014063643030633331363466373361393935373964306238363032643932653137636437353863383262306265353239303839376564346638663161353665333937f00101ca020d41542654204d6f62696c697479d2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003a28c02e803bdef01f003af13f80392078004e9fa018804a28c029004e9fa019804a28c02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d4a775553566677524542514277456c7045704d3455673d3d2f6c69622f61726de00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d4a775553566677524542514277456c7045704d3455673d3d2f626173652e61706bf00406f804018a050233329a050a32303139313138313035a80503b205094f70656e474c455332b805ff01c00504ca0522450147130554590145045d1009044c5945395b0455040d6c5c515760020e6f010f30e005e6b201ea05093372645f7061727479f2055c4b717348547a4232754c4c5351667a71317453626639565049307555466b683673596b556d7735516a78526230396a35663644366e6177466f367249666a302b57736f725a32655a5737556138444b556f546375626862435651513df805e7e4068806019006019a060134a2060134')
    data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
    data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
    d = encrypt_api(data.hex())
    Final_Payload = bytes.fromhex(d)
    
   
    headers = {
        "Host": "loginbp.ggblueshark.com",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "*/*",
        "Authorization": "Bearer",
        "ReleaseVersion": "OB52",
        "X-GA": "v1 1",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(Final_Payload)),
        "User-Agent": "Free%20Fire/2019118692 CFNetwork/3826.500.111.2.2 Darwin/24.4.0",
        "Connection": "keep-alive"
    }
    
    URL = "https://loginbp.ggblueshark.com/MajorLogin"
    RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
    
    if RESPONSE.status_code == 200:
        if len(RESPONSE.text) < 10:
            return False
        BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        return BASE64_TOKEN
    else:
        print(f"MajorLogin failed with status: {RESPONSE.status_code}")
        print(f"Response: {RESPONSE.text}")
        return False

@app.route('/get', methods=['GET'])
def check_token():
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "",
            "client_id": "100067",
        }
        response = requests.post(url, headers=headers, data=data)
        try:
            data = response.json()
            print("RESPONSE JSON:", data)
        except Exception as e:
            print("FAILED TO PARSE JSON:", response.text)
            return jsonify({"status": "error", "message": "Invalid response from Garena"})

        if "access_token" not in data or "open_id" not in data:
            return jsonify({"status": "error", "message": f"Missing keys in response: {data}"})

        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "cd00c3164f73a99579d0b8602d92e17cd758c82b0be5290897ed4f8f1a56e397"
        OLD_OPEN_ID = "c209bfe742c0e2a3ca39ef113f3fca40"
        token = TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        if token:
            return jsonify({"status": "success", "token": token})
        else:
            return jsonify({"status": "failure", "message": "Failed to generate token"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8792)
