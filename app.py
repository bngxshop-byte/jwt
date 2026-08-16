from flask import Flask, request, jsonify
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import sys
import os

# تأكد من وجود xTnito في المسار
try:
    from xTnito import *
except ImportError as e:
    print(f"Error importing xTnito: {e}")
    # لو مش موجود ارجع رسالة خطأ
    def xGeT(uid, password):
        return f"Error: xTnito not found"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


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

        token = xGeT(uid , password)
        if token:
            return jsonify({"status": "success", "token": token})
        else:
            return jsonify({"status": "failure", "message": "Failed to generate token"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# لو حبيت تشغل محلياً
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8792)
