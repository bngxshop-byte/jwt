import requests
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import blackboxprotobuf
from flask import Flask, request, jsonify
from google_play_scraper import app as ah
import os
import sys

# تعطيل تحذيرات SSL
urllib3.disable_warnings()

app = Flask(__name__)

# ثوابت
UA = "GarenaMSDK/4.0.32 (iPhone9,3;ios - 15.8.2;en-US;US;app v1.123.1 2019120273)"
KEY = b'Yg&tc%DEuh6%Zc^8'
IV = b'6oyZDr22E3ychjM%'

# المتغيرات العامة
login_url = ""
ob = ""
verr = ""
host = ""

def up():
    """تحديث بيانات الاتصال من Google Play"""
    global login_url, ob, verr, host
    try:
        data = ah("com.dts.freefireth", lang="fr", country="CA")
        version = data["version"]
        
        response = requests.get(
            f"https://version.ggwhitehawk.com/live/ver.php"
            f"?version={version}&lang=en&device=android&channel=android"
            f"&appsttore=googleplay&region=en&whitelist_version=1.3.0"
            f"&whitelist_sp_version=1.0.0&device_name=google%20G011A"
            f"&device_CPU=ARMv7%20VFPv3%20NEON%20VMH"
            f"&device_GPU=Adreno%20(TM)%20640&device_mem=1993",
            timeout=10
        ).json()
        
        login_url = response.get("server_url", "")
        ob = response.get("latest_release_version", "")
        verr = response.get("remote_version", "")
        host = login_url.split('https://')[1].split('/')[0] if login_url else ""
        
        return login_url, ob, verr, host
    except Exception as e:
        print(f"خطأ في تحديث البيانات: {e}")
        # استخدام قيم افتراضية في حالة الفشل
        login_url = "https://example.com"
        ob = "1.123.1"
        verr = "1.123.1"
        host = "example.com"
        return login_url, ob, verr, host

# تحديث البيانات عند بدء التشغيل
login_url, ob, verr, host = up()

def EncodeVarint(value):
    """تشفير Varint للبروتوبوف"""
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
    """بناء رسالة بروتوبوف"""
    packet = bytearray()
    for field, value in fields.items():
        try:
            if isinstance(value, dict):
                nested = BuildProto(value)
                packet.extend(EncodeVarint((field << 3) | 2))
                packet.extend(EncodeVarint(len(nested)))
                packet.extend(nested)
            elif isinstance(value, int):
                packet.extend(EncodeVarint(field << 3))
                packet.extend(EncodeVarint(value))
            elif isinstance(value, str):
                data = value.encode('utf-8')
                packet.extend(EncodeVarint((field << 3) | 2))
                packet.extend(EncodeVarint(len(data)))
                packet.extend(data)
            elif isinstance(value, bytes):
                packet.extend(EncodeVarint((field << 3) | 2))
                packet.extend(EncodeVarint(len(value)))
                packet.extend(value)
            else:
                # معالجة الأنواع غير المعروفة
                data = str(value).encode('utf-8')
                packet.extend(EncodeVarint((field << 3) | 2))
                packet.extend(EncodeVarint(len(data)))
                packet.extend(data)
        except Exception as e:
            print(f"خطأ في بناء الحقل {field}: {e}")
            continue
    return bytes(packet)

def ParseProto(data):
    """فك تشفير رسالة بروتوبوف"""
    try:
        return blackboxprotobuf.decode_message(data)[0]
    except Exception as e:
        print(f"خطأ في فك البروتوبوف: {e}")
        return {}

def GetToken(uid, pwd):
    """الحصول على توكن المصادقة"""
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
    try:
        r = requests.post(url, data=json.dumps(payload), headers=headers, timeout=10)
        return r.json()
    except Exception as e:
        print(f"خطأ في الحصول على التوكن: {e}")
        return {"error": str(e)}

def EncodePyl(data):
    """تشفير البيانات باستخدام AES-CBC"""
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return encrypted
    except Exception as e:
        print(f"خطأ في التشفير: {e}")
        return b""

def BuildLogin(open_id, access):
    """بناء رسالة تسجيل الدخول"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    payload = {
        3: timestamp,
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
    """إرسال طلب تسجيل الدخول الرئيسي"""
    if not host:
        return None
        
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
    
    try:
        damn = EncodePyl(proto_data)
        r = requests.post(
            f"https://{host}/MajorLogin",
            headers=headers,
            data=damn,
            verify=False,
            timeout=15
        )
        return r
    except Exception as e:
        print(f"خطأ في تسجيل الدخول الرئيسي: {e}")
        return None

@app.route('/')
def index():
    """الصفحة الرئيسية"""
    return jsonify({
        "status": "running",
        "endpoint": "/get?uid=USER_ID&pw=PASSWORD",
        "message": "Free Fire Login API"
    })

@app.route("/get")
def get():
    """نقطة النهاية الرئيسية للحصول على التوكن"""
    uid = request.args.get("uid")
    pw = request.args.get("pw")
    
    # التحقق من صحة المدخلات
    if not uid or not pw:
        return jsonify({"error": "يجب تقديم uid و pw"}), 400
    
    try:
        # الحصول على توكن المصادقة
        Token = GetToken(uid, pw)
        
        if "error" in Token:
            return jsonify({"error": Token["error"]}), 500
            
        if "data" not in Token:
            return jsonify({"error": "فشل في الحصول على بيانات التوكن"}), 500
            
        access = Token["data"].get("access_token")
        open_id = Token["data"].get("open_id")
        
        if not access or not open_id:
            return jsonify({"error": "بيانات التوكن غير مكتملة"}), 500
        
        # بناء رسالة تسجيل الدخول
        payload = BuildLogin(open_id, access)
        
        # إرسال طلب تسجيل الدخول
        r = MajorLogin(payload)
        
        if r is None:
            return jsonify({"error": "فشل في الاتصال بخادم تسجيل الدخول"}), 500
            
        if r.status_code != 200:
            return jsonify({"error": f"خطأ في الخادم: {r.status_code}"}), r.status_code
        
        # فك تشفير الرد
        parsed = ParseProto(r.content)
        result = parsed.get("8")
        
        if isinstance(result, bytes):
            result = result.decode("utf-8", errors="replace")
        elif result is None:
            return jsonify({"error": "لم يتم العثور على التوكن في الرد"}), 500
            
        return jsonify({"token": result})
        
    except ValueError as e:
        return jsonify({"error": f"خطأ في تحويل البيانات: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"خطأ غير متوقع: {str(e)}"}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "المسار غير موجود"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "خطأ داخلي في الخادم"}), 500

if __name__ == "__main__":
    # تشغيل الخادم
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    
    print(f"🚀 تشغيل الخادم على المنفذ {port}")
    print("📋 استخدام: /get?uid=USER_ID&pw=PASSWORD")
    
    app.run(host="0.0.0.0", port=port, debug=debug)
