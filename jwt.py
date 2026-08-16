import requests
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import blackboxprotobuf
from flask import Flask, request, jsonify
from google_play_scraper import app as ah

urllib3.disable_warnings()

app = Flask(__name__)

UA = "GarenaMSDK/4.0.32 (iPhone9,3;ios - 15.8.2;en-US;US;app v1.123.1 2019120273)"
def up():
    global login_url, ob, verr
    data = ah("com.dts.freefireth", lang="fr", country="CA")
    version = data["version"]
    x = requests.get(
        f"https://version.ggwhitehawk.com/live/ver.php"
        f"?version={version}&lang=en&device=android&channel=android"
        f"&appsttore=googleplay&region=en&whitelist_version=1.3.0"
        f"&whitelist_sp_version=1.0.0&device_name=google%20G011A"
        f"&device_CPU=ARMv7%20VFPv3%20NEON%20VMH"
        f"&device_GPU=Adreno%20(TM)%20640&device_mem=1993"
    ).json()
    login_url = x.get("server_url")
    ob = x.get("latest_release_version") 
    verr = x.get("remote_version")
    host = login_url.split('https://')[1].split('/')[0]
    return login_url, ob, verr , host
login_url, ob, verr , host = up()

def EncodeVarint(value):
    result = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
        if not value:
            break
    return bytes(result)

def BuildProto(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = BuildProto(value)
            packet.extend(EncodeVarint((field << 3) | 2))
            packet.extend(EncodeVarint(len(nested)))
            packet.extend(nested)
        elif isinstance(value, int):
            packet.extend(EncodeVarint(field << 3))
            packet.extend(EncodeVarint(value))
        elif isinstance(value, str):
            data = value.encode()
            packet.extend(EncodeVarint((field << 3) | 2))
            packet.extend(EncodeVarint(len(data)))
            packet.extend(data)
        elif isinstance(value, bytes):
            packet.extend(EncodeVarint((field << 3) | 2))
            packet.extend(EncodeVarint(len(value)))
            packet.extend(value)
    return bytes(packet)

def ParseProto(data):
    return blackboxprotobuf.decode_message(data)[0]

def GetToken(uid, pwd):
    url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    payload = {
        "source": 1,
        "password": pwd,
        "uid": int(uid),
        "response_type": "token",
        "client_type": 1,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Accept-Language": "en-US,en;q=0.9"
    }
    r = requests.post(url, data=json.dumps(payload), headers=headers)
    return r.json()

def EncodePyl(data):
    KEY = b'Yg&tc%DEuh6%Zc^8'
    IV = b'6oyZDr22E3ychjM%'
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(data, AES.block_size))

def BuildLogin(open_id, access):
    payload = {
        3: str(datetime.now())[:-7],
        4: "free fire",
        5: 2,
        7: verr,
        8: "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)",
        9: "Handheld",
        10: "Verizon",
        11: "WIFI",
        12: 1920,
        13: 1080,
        14: "280",
        15: "ARM64 FP ASIMD AES VMH | 2865 | 4",
        16: 3003,
        17: "Adreno (TM) 640",
        18: "OpenGL ES 3.1 v1.46",
        19: "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57",
        20: "223.191.51.89",
        21: "ar",
        22: open_id,
        23: "3",
        24: "Handheld",
        25: "iPhone10,1",
        29: access,
        30: 1,
        41: "Verizon",
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 36235,
        61: 31335,
        62: 2519,
        63: 703,
        64: 25010,
        65: 26628,
        66: 32992,
        67: 36235,
        70: 1,
        73: 1,
        74: "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64",
        76: 1,
        77: "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk",
        78: 2,
        79: 2,
        81: "64",
        83: "2019118695",
        85: 3,
        86: "OpenGLES2",
        87: 16383,
        88: 4,
        90: "Tunis",
        91: "11",
        92: 13564,
        93: "android",
        94: "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY=",
        95: 110009,
        97: 1,
        98: 1,
        99: "4",
        100: "4",
        102: b'\x10\x01D@W\r\x04\x01\x18S[AYYD\t\x16lYY\\x06\x04(RPw[V\x08;\x0eS8'
    }
    return BuildProto(payload)

def MajorLogin(proto_data):
    headers = {
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": host,
        "ReleaseVersion": ob,
        "User-Agent": UA,
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }
    damn = EncodePyl(proto_data)
    r = requests.post(f"https://{host}/MajorLogin", headers=headers, data=damn, verify=False)
    return r

@app.route("/get")
def get():
    uid = request.args.get("uid")
    pw = request.args.get("pw")
    Token = GetToken(uid, pw)
    access = Token["data"]["access_token"]
    open_id = Token["data"]["open_id"]
    payload = BuildLogin(open_id, access)
    r = MajorLogin(payload)
    parsed = ParseProto(r.content)
    result = parsed.get("8")
    if isinstance(result, bytes):
        result = result.decode("utf-8", errors="replace")
    return jsonify({"token": result})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)