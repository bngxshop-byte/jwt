from flask import Flask, request, jsonify
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import sys
import os

# تأكد من وجود xTnito في المسار
import requests , json , binascii , time , urllib3 , base64 , datetime , re ,socket , threading , random , os
from protobuf_decoder.protobuf_decoder import Parser
from threading import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Key , Iv = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56]) , bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])




vip_index = 0

def EnC_AEs(HeX):
    cipher = AES.new(Key , AES.MODE_CBC , Iv)
    return cipher.encrypt(pad(bytes.fromhex(HeX), AES.block_size)).hex()
    
def DEc_AEs(HeX):
    cipher = AES.new(Key , AES.MODE_CBC , Iv)
    return unpad(cipher.decrypt(bytes.fromhex(HeX)), AES.block_size).hex()
    
def EnC_PacKeT(HeX , K , V): 
    return AES.new(K , AES.MODE_CBC , V).encrypt(pad(bytes.fromhex(HeX) ,16)).hex()
    
def DEc_PacKeT(HeX , K , V):
    return unpad(AES.new(K , AES.MODE_CBC , V).decrypt(bytes.fromhex(HeX)) , 16).hex()  

def EnC_Uid(H , Tp):
    e , H = [] , int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0)) ; H >>= 7
    return bytes(e).hex() if Tp == 'Uid' else None

def EnC_Vr(N):
    if N < 0: ''
    H = []
    while True:
        BesTo = N & 0x7F ; N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)
    
def DEc_Uid(H):
    n = s = 0
    for b in bytes.fromhex(H):
        n |= (b & 0x7F) << s
        if not b & 0x80: break
        s += 7
    return n
    
def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))           
    return packet    
    
def DecodE_HeX(H):
    R = hex(H) 
    F = str(R)[2:]
    if len(F) == 1: F = "0" + F ; return F
    else: return F

def Fix_PackEt(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = Fix_PackEt(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def DeCode_PackEt(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = Fix_PackEt(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
                      
def xMsGFixinG(n):
    return '🗿'.join(str(n)[i:i + 3] for i in range(0 , len(str(n)) , 3))

def ArA_CoLor():
    Tp = ["32CD32" , "00BFFF" , "00FA9A" , "90EE90" , "FF4500" , "FF6347" , "FF69B4" , "FF8C00" , "FF6347" , "FFD700" , "FFDAB9" , "F0F0F0" , "F0E68C" , "D3D3D3" , "A9A9A9" , "D2691E" , "CD853F" , "BC8F8F" , "6A5ACD" , "483D8B" , "4682B4", "9370DB" , "C71585" , "FF8C00" , "FFA07A"]
    return random.choice(Tp)
    
def xBunnEr():
    bN = [902000306 , 902000305 , 902000003 , 902000016 , 902000017 , 902000019 , 902000020 , 902000021 , 902000023 , 902000070 , 902000087 , 902000108 , 902000011 , 902049020 , 902049018 , 902049017 , 902049016 , 902049015 , 902049003 , 902033016 , 902033017 , 902033018 , 902048018 , 902000306 , 902000305]
    return random.choice(bN)

def xSEndMsg(Msg , Tp , Tp2 , id , K , V):
    feilds = {1: id, 2: Tp2, 3: Tp, 4: Msg , 5: 1735129800, 7: 2, 9: {1: "xBesTo - C4­", 2: xBunnEr(), 3: 901048018, 4: 330, 5: 827001005, 8: "xBesTo - C4", 10: 1, 11: 1,14: {1: 1158053040,2: 8,3: "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"}}, 10: "en", 13: {2: 1, 3: 1}, 14: {}}
    Pk1 = str(CrEaTe_ProTo(feilds).hex())
    Pk1 = "080112" + EnC_Uid(len(Pk1) // 2 , Tp = 'Uid') + Pk1
    return GeneRaTePk(str(Pk1) , '1215' , K , V)

def lagi(id , K , V):
    fields = {
        1: int(id), 
        2: 14,          
        4: 77            
    }
    print(fields)
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0e15', K, V)

def Auth_Chat(idT, sq, K, V):
    fields = {
        1: 3,
        2: {
            1: idT,
            3: "fr",
            4: sq
        }
    }
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '1215' , K , V)
def xSendTeamMsg(msg, idT,  K, V):
    fields = {
    1: 1,
    2: {
        1: 12404281032,
        2: idT,
        4: msg,
        7: 2,
        10: "fr",
        9: {
            1: "C4 TEAM",
            2: xBunnEr(),
            4: 330,
            5: 827001005,
            8: "C4 TEAM",
            10: 1,
            11: 1,
            12: {
                1: 2
            },
            14: {
                1: 1158053040,
                2: 8,
                3: "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            }
        },
        13: {
            1: 2,
            2: 1
        },
        14:{}
    }
}
    
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '1215' , K , V)
def xDangr(msg, idT,  K, V):
    fields = {
    1: 1,
    2: {
        1: 12404281032,
        2: idT,
        4: msg,
        7: 4,
        10: "fr",
        9: {
            1: "C4 TEAM",
            2: xBunnEr(),
            4: 330,
            5: 827001005,
            8: "C4 TEAM",
            10: 1,
            11: 1,
            12: {
                1: 2
            },
            14: {
                1: 1158053040,
                2: 8,
                3: "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            }
        },
        13: {
            1: 2,
            2: 1
        },
        14:{}
    }
}
    
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '1215' , K , V)

def OpEnSq(K , V):
    fields = {1: 1, 2: {2: "\u0001", 3: 1, 4: 1, 5: "en", 9: 1, 11: 1, 13: 1, 14: {2: 5756, 6: 11, 8: "1.111.5", 9: 2, 10: 4}}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)

def cHSq(Nu , Uid , K , V):
    fields = {1: 17, 2: {1: int(Uid), 2: 1, 3: int(Nu - 1), 4: 62, 5: "\u001a", 8: 5, 13: 329}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)

def SEnd_InV(Nu , Uid , K , V):
    fields = {1: 2 , 2: {1: int(Uid) , 2: "ME" , 4: int(Nu)}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)
    
def ExiT(id , K , V):
    fields = {
        1: 7,
        2: {
            1: int(11037044965)
        }
        }
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)

def AuthClan(CLan_Uid , AuTh , K , V):
    fields = {1: 3, 2: {1: int(CLan_Uid) , 2: 1, 4: str(AuTh)}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '1201' , K , V) 
        
def GeT_Status(PLayer_Uid , K , V):
    PLayer_Uid = EnC_Uid(PLayer_Uid , Tp = 'Uid')
    if len(PLayer_Uid) == 8: Pk1 = f'080112080a04{PLayer_Uid}1005'
    elif len(PLayer_Uid) == 10: Pk1 = f"080112090a05{PLayer_Uid}1005"
    return GeneRaTePk(Pk1 , '0f15' , K , V)
           
def SPam_Room(Uid , Rm , Nm , K , V):
    fields = {1: 78, 2: {1: int(Rm), 2: f"[{ArA_CoLor()}]{Nm}", 3: {2: 1, 3: 1}, 4: 330, 5: 1, 6: 201, 10: xBunnEr(), 11: int(Uid), 12: 1}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0e15' , K , V)

def Join_Room(room_id , K , V):
    fields = {1: 3, 2: {1: int(room_id), 8: {1: "IDC1", 2: 3000, 3: "ME"}, 9: "\x01\t\n\x12\x19 ", 10: 1, 12: b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", 13: 3, 14: 3, 16: "ME"}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0e10' , K , V)

def SPamSq(Uid , K , V): 
    fields = {1: 33, 2: {1: int(Uid) , 2: 'ME', 3: 1, 4: 1, 7: 330, 8: 19459, 9: 100, 12: 1, 16: 1, 17: {2: 94, 6: 11, 8: '1.111.5', 9: 3, 10: 2}, 18: 201, 23: {2: 1, 3: 1}, 24: xBunnEr() , 26: {}, 28: {}}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)

def AccEpT(PLayer_Uid , AuTh_CodE_Sq , K , V): 
    fields = {1: 4, 2: {1: int(PLayer_Uid), 3: int(PLayer_Uid), 4: "\u0001\u0007\t\n\u0012\u0019\u001a ", 8: 1, 9: {2: 1393, 4: "wW_T", 6: 11, 8: "1.111.5", 9: 3, 10: 2}, 10: AuTh_CodE_Sq, 12: 1, 13: "en", 16: "OR"}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0515' , K , V)
def EmoTe(Uid , Em , K , V):
    fields = {
        1: 21,
        2: {
            1: 804266360,
            2: 909000001,
            5: {
                1: int(Uid),
                3: int(Em)}}}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()) , '0501' , K , V)
def GenJoinSquadsPacket(code, key, iv):
    fields = {}
    fields[1] = 4
    fields[2] = {}
    fields[2][4] = bytes.fromhex("01090a0b121920")
    fields[2][5] = str(code)
    fields[2][6] = 6
    fields[2][8] = 1
    fields[2][9] = {}
    fields[2][9][2] = 800
    fields[2][9][6] = 11
    fields[2][9][8] = "1.111.1"
    fields[2][9][9] = 5
    fields[2][9][10] = 1
    print(fields)
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0515', key, iv)
def ghost_pakcet(player_id , nm , secret_code , key ,iv):
    fields = {
        1: 61,
        2: {
            1: int(player_id),  
            2: {
                1: int(player_id),  
                2: 1159,  
                3: f"[b][c][{ArA_CoLor()}]{nm}",  
                5: 12,  
                6: 15,
                7: 1,
                8: {
                    2: 1,
                    3: 1,
                },
                9: 3,
            },
            3: secret_code,},}
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0515', key, iv)
def maq1(x, K, V):
    fields = {
        1: 5,
        2: {
            1: int(x),
            2: 1,
            3: int(x),  
            4: f"""\n\n\n\n\n
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ 
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ 
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ 
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ
                  
   [b][c][00FF00]  ██████╗░██╗███████╗░█████╗░██╗░░██╗██╗░░░██╗
   [b][c][FF0000]  ██╔══██╗██║╚════██║██╔══██╗██║░██╔╝╚██╗░██╔╝
  [b][c][00FF00]   ██████╔╝██║░░███╔═╝███████║█████═╝░░╚████╔╝░
   [b][c][FF0000]  ██╔══██╗██║██╔══╝░░██╔══██║██╔═██╗░░░╚██╔╝░░
 [b][c][00FF00]    ██║░░██║██║███████╗██║░░██║██║░╚██╗░░░██║░░░
   [b][c][FF0000]  ╚═╝░░╚═╝╚═╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ 
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ 
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ 
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ  
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ  
   [b][c][00FF00]  ██████╗░██╗███████╗░█████╗░██╗░░██╗██╗░░░██╗
   [b][c][FF0000]  ██╔══██╗██║╚════██║██╔══██╗██║░██╔╝╚██╗░██╔╝
  [b][c][00FF00]   ██████╔╝██║░░███╔═╝███████║█████═╝░░╚████╔╝░
   [b][c][FF0000]  ██╔══██╗██║██╔══╝░░██╔══██║██╔═██╗░░░╚██╔╝░░
 [b][c][00FF00]    ██║░░██║██║███████╗██║░░██║██║░╚██╗░░░██║░░░
   [b][c][FF0000]  ╚═╝░░╚═╝╚═╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░
[b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u]
[b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u]
[b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u]
[b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u][b][c][00FF00]tiktok:[FF0000][u]@rizakyi[/u]
   [b][c][00FF00]  ██████╗░██╗███████╗░█████╗░██╗░░██╗██╗░░░██╗
   [b][c][FF0000]  ██╔══██╗██║╚════██║██╔══██╗██║░██╔╝╚██╗░██╔╝
  [b][c][00FF00]   ██████╔╝██║░░███╔═╝███████║█████═╝░░╚████╔╝░
   [b][c][FF0000]  ██╔══██╗██║██╔══╝░░██╔══██║██╔═██╗░░░╚██╔╝░░
 [b][c][00FF00]    ██║░░██║██║███████╗██║░░██║██║░╚██╗░░░██║░░░
   [b][c][FF0000]  ╚═╝░░╚═╝╚═╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░
                  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ
                  
[b][c][FF0000]     ▒█▀▀█ ░█▀█░ 　 ▀▀█▀▀ ▒█▀▀▀ ░█▀▀█ ▒█▀▄▀█ 
[b][c][FF0000]     ▒█░░░ █▄▄█▄ 　 ░▒█░░ ▒█▀▀▀ ▒█▄▄█ ▒█▒█▒█ 
[b][c][FF0000]     ▒█▄▄█ ░░░█░ 　 ░▒█░░ ▒█▄▄▄ ▒█░▒█ ▒█░░▒█
              [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ ＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ  [b][c][00FF00]＠ ＩＮＳＴＡＧＲＡＭ： [FF0000]＠ＲＩＺＡＫＹＩ [00FF00]ＴＩＫＴＯＫ： [FF0000]＠ＲＩＺＡＫＹＩ [00FFFF]Ｃ４ ＴＥＡＭ ＯＦＦＩＣＩＥＬ [b][c][FFFFFF] ＰＬＥＡＳＥ ＳＵＢＳＣＲＩＢＥ  """
        }
    }
          
    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0515', K, V)         
def maq(x, K, V):
    xCo = ArA_CoLor()
    aaa = '@hook955'
    fields = {
        1: 5,
        2: {
            1: int(x),
            2: 1,
            3: int(x),  
            4:f"""\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n
            [b][c][{xCo}]▒█▀▀█ ░█▀█░   ▀▀█▀▀ ▒█▀▀▀ ░█▀▀█ ▒█▀▄▀█  
          ▒█░░░ █▄▄█▄   ░▒█░░ ▒█▀▀▀ ▒█▄▄█ ▒█▒█▒█   
          ▒█▄▄█ ░░░█░   ░▒█░░ ▒█▄▄▄ ▒█░▒█ ▒█░░▒█
            \n\n{aaa * 100}\n\n[b][c][{ArA_CoLor()}] HooKㅤaTTackinG !\n [b][c][{xCo}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[ffffff]
 [ffffff]  FoLLow Us To KeeP U SaFe :\n
 [ffffff]  TiKToK => [90EE90]@freefirehook | \n
 [ffffff]  InsTaGram => [90EE90]@hook._.999|  [ffffff]\n
 [ffffff]  TeLeGram => [90EE90]@hook955 | [ffffff]\n
 [ffffff]  Devlopper id => [90EE90]7902780342[ffffff]
 [b][c][{xCo}]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[ffffff]
 [FF0000] CHOBIK LOBIK LHOOK CHYETZAWAJ BIK HET WHATSAPPEK WALA NBANIK\n\n [ffffff]CHOBIK LOBIK [90EE90]HOOK BINE YDIK \n\n[{xCo}]{aaa * 100}\n\n
          [b][c][{xCo}]▒█▀▀█ ░█▀█░   ▀▀█▀▀ ▒█▀▀▀ ░█▀▀█ ▒█▀▄▀█  
          ▒█░░░ █▄▄█▄   ░▒█░░ ▒█▀▀▀ ▒█▄▄█ ▒█▒█▒█   
          ▒█▄▄█ ░░░█░   ░▒█░░ ▒█▄▄▄ ▒█░▒█ ▒█░░▒█\n\n\n\n\n\n"""
        }
    }
            

    return GeneRaTePk(str(CrEaTe_ProTo(fields).hex()), '0515', K, V)  
      



def _V(b, i):
    r = s = 0
    while True:
        c = b[i]; i += 1
        r |= (c & 0x7F) << s
        if c < 0x80: break
        s += 7
    return r, i

def PrOtO(hx):
    b, i, R = bytes.fromhex(hx), 0, {}
    while i < len(b):
        H, i = _V(b, i)
        F, T = H >> 3, H & 7
        if T == 0:
            R[F], i = _V(b, i)
        elif T == 2:
            L, i = _V(b, i)
            S = b[i:i+L]; i += L
            try: R[F] = S.decode()
            except:
                try: R[F] = PrOtO(S.hex())
                except: R[F] = S
        elif T == 5:
            R[F] = int.from_bytes(b[i:i+4], 'little'); i += 4
        else:
            raise ValueError(f'Unknown wire type: {T}')
    return R
    
def GeT_KEy(obj , target):
    values = []
    def collect(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == target:
                    values.append(v)
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)
    collect(obj)
    return values[-1] if values else None
 
 
def GeneRaTePk(Pk1 , N , K , V):
    PkEnc = EnC_PacKeT(Pk1 , K , V)
    _ = DecodE_HeX(int(len(PkEnc) // 2))
    if len(_) == 2: HeadEr = N + "000000"
    elif len(_) == 3: HeadEr = N + "00000"
    elif len(_) == 4: HeadEr = N + "0000"
    elif len(_) == 5: HeadEr = N + "000"
    return bytes.fromhex(HeadEr + _ + PkEnc)
    
def GuiLd_AccEss(Tg , Nm , Uid , BLk , OwN , AprV):
    return Tg in Nm and Uid not in BLk and Uid in (OwN | AprV)
            
def ChEck_Commande(id):
    return "<" not in id and ">" not in id and "[" not in id and "]" not in id
        
def L_DaTa():
    load = lambda f: json.load(open(f)) if os.path.exists(f) else {}
    return map(load, ["BesTo_CLan_LiKes.json" , "BesTo_RemaininG_LiKes.json" , "BesTo_RemaininG_Room.json"])
       
def ChEck_Limit_CLan(Uid , STaTus):
    data , max_use , file = (like_data_clan, 10, "BesTo_CLan_LiKes.json") if STaTus == "like" else ''
    t , limit = time.time(), 86400
    u = data.get(str(Uid), {"count": 0, "start_time": t})    
    if t - u["start_time"] >= limit:
        u = {"count": 0, "start_time": t}
    if u["count"] < max_use:
        u["count"] += 1
        data[str(Uid)] = u
        json.dump(data , open(file, "w"))
        return f"{max_use - u['count']}" , datetime.fromtimestamp(u["start_time"] + limit).strftime("%I:%M %p - %d/%m/%y")
    return False , datetime.fromtimestamp(u["start_time"] + limit).strftime("%I:%M %p - %d/%m/%y")

def ChEck_Limit(Uid , STaTus):
    data , max_use , file = (like_data, 10, "BesTo_RemaininG_LiKes.json") if STaTus == "like" else (room_data, 10, "BesTo_RemaininG_Room.json")
    t , limit = time.time(), 86400
    u = data.get(str(Uid), {"count": 0, "start_time": t})    
    if t - u["start_time"] >= limit:
        u = {"count": 0, "start_time": t}
    if u["count"] < max_use:
        u["count"] += 1
        data[str(Uid)] = u
        json.dump(data , open(file, "w"))
        return f"{max_use - u['count']}" , datetime.fromtimestamp(u["start_time"] + limit).strftime("%I:%M %p - %d/%m/%y")
    return False , datetime.fromtimestamp(u["start_time"] + limit).strftime("%I:%M %p - %d/%m/%y")
    
f = 'blacklist.txt'
approvee = 'approved.txt'
black , approve = [] , []

def load_blacklist():
    global black
    try: 
        with open(f, 'r') as file: 
            black = [line.strip() for line in file if line.strip()]
    except: black = []

def encrypt_uids():
    global black
    try: 
        if black: black = [EnC_Uid(uid , Tp = 'Uid') for uid in black]
    except: 
        try: open(f, 'w').close()
        except: pass
        load_blacklist()

if not black: open(f, 'w').close()

def load_approve():
    global approve
    try: 
        with open(approvee, 'r') as file: approve = [line.strip() for line in file if line.strip()]
    except: approve = []

def encrypt_uids2():
    global approve
    try: 
        if approve: approve = [EnC_Uid(uid , Tp = 'Uid') for uid in approve]
    except: 
        try: open(approvee, 'w').close()
        except: pass
        load_approve()

if not approve: open(approvee, 'w').close()
               
def Add_Uid(user_id):
    with open(f, 'r') as file: lines = file.read().splitlines()
    if str(user_id) not in lines:
        with open(f, 'a') as file: file.write(f"{user_id}\n")

def Remove_Uid(f, player_uid):
    try:
        with open(f, 'r+') as file: lines = file.readlines() ; file.seek(0), file.truncate(), file.writelines(l for l in lines if l.strip() != player_uid) ; return True
    except FileNotFoundError: return False
        
def A(user_id):
    with open(approvee, 'r') as file: lines = file.read().splitlines()
    if str(user_id) not in lines:
        with open(approvee, 'a') as file: file.write(f"{user_id}\n")

def D(approvee, player_uid):
    try:
        with open(approvee, 'r+') as file: lines = file.readlines() ; file.seek(0), file.truncate(), file.writelines(l for l in lines if l.strip() != player_uid) ; return True
    except FileNotFoundError: return False        

def Clear():
    try:
        open(f, 'w').close() ; black.clear() ; return True
    except: return False
                   
def Add_Black(user_id):
    Add_Uid(user_id)
    if EnC_Uid(user_id , Tp = 'Uid') not in black: black.append(EnC_Uid(user_id , Tp = 'Uid')) ; return True
    else: return False 
    
def Rem_Black(user_id):
    user_id_encrypted = EnC_Uid(user_id , Tp = 'Uid')
    if user_id_encrypted in black: black.remove(user_id_encrypted) ; Remove_Uid(f , user_id) ; return True
    else: return False       

def Show_Uids():
    try:
        with open(f) as file: return "\n".join(sorted(file.read().splitlines(), key=int)) or False
    except (FileNotFoundError, ValueError): return False 

def Approved(user_id):
    A(user_id)
    if EnC_Uid(user_id , Tp = 'Uid') not in approve: approve.append(EnC_Uid(user_id , Tp = 'Uid')) ; return True
    else: return False 
    
def DeApproved(user_id):
    user_id_encrypted = EnC_Uid(user_id , Tp = 'Uid')
    if user_id_encrypted in approve: approve.remove(user_id_encrypted) ; D(approvee , user_id) ; return True
    else: return False        
        
def Show_Approvs():
    try: 
        with open(approvee) as file: return "\n".join(sorted(file.read().splitlines(), key=int)) or False
    except (FileNotFoundError, ValueError): return False 
        
def Clear_Approvs():
    try: 
        open(approvee, 'w').close() ; approve.clear() ; return True
    except: return False

def Ua():
    TmP = "GarenaMSDK/4.0.13 ({}; {}; {};)"
    return TmP.format(random.choice(["iPhone 13 Pro", "iPhone 14", "iPhone XR", "Galaxy S22", "Note 20", "OnePlus 9", "Mi 11"]) , 
                     random.choice(["iOS 17", "iOS 18", "Android 13", "Android 14"]) , 
                     random.choice(["en-SG", "en-US", "fr-FR", "id-ID", "th-TH", "vi-VN"]))

def xGeT(u, p):
    print(f"جاري توليد التوكن لـ UID: {u}")
    try:
        r = requests.Session().post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            headers={
                "Host": "100067.connect.garena.com",
                "User-Agent": Ua(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "close"
            },
            data={
                "uid": u,
                "password": p,
                "response_type": "token",
                "client_type": "2",
                "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                "client_id": "100067"
            },
            verify=False
        )
        
        if r.status_code == 200:
            T = r.json()
            print("تم الحصول على التوكن بنجاح من Garena")
            a, o = T["access_token"], T["open_id"]
            jwt_token = xJwT(a, o)
            if jwt_token:
                print("تم توليد JWT بنجاح")
                return jwt_token
            else:
                print("فشل في توليد JWT")
                return None
        else:
            print(f"خطأ في الاستجابة من Garena: {r.status_code}")
            return None
    except Exception as e:
        print(f"حدث خطأ في xGeT: {str(e)}")
        return None

def xJwT(a, o):
    try:
        dT = bytes.fromhex('1a13323032362d30362d32392031333a34323a3531220966726565206669726528013a07322e3132362e36423a416e64726f6964204f532039202f204150492d32382028505133422e3139303830312e30333235303930332f47393635305a48553241524336294a0848616e6468656c6452074d6f62696e696c5a045749464960c00c68840772033234307a287838362d3634205353453320535345342e3120535345342e3220415658207c2032383635207c20368001c32e8a010f416472656e6f2028544d29203634309201104f70656e474c20455320332e312076319a012b476f6f676c657c38656162393736322d633065612d343064382d623634662d663135326263313265303362a2010d3139372e3230322e35352e3330aa01026172b201206465633265383233613766303737306338383765663163613464303131633063ba010134c2010848616e6468656c64ca01115869616f6d69203233303446504e364447d201024d45ea014066383830663031383933666337383264663063393538366562656232326134633663393464613632636334353365303166333465363538613830393561663730f00101ca02074d6f62696e696cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003c88a03e803c1f002f003d713f803de058004d0ba01880484d0019004ff81039804c88a03c80403d204402f646174612f6170702f636f6d2e6474732e66726565666972656d61782d716a7a583456364a6d654d744d656865766f6c6856513d3d2f6c69622f61726d3634e00402ea046064353038353336623261336331366266326265626264323432333365393239337c2f646174612f6170702f636f6d2e6474732e66726565666972656d61782d716a7a583456364a6d654d744d656865766f6c6856513d3d2f626173652e61706bf00402f804028a050236349a050a32303139313138303435a80503b205094f70656e474c455333b805ff1fc00504e005a73dea050b616e64726f69645f6d6178f2055c4b717348542b64772f4f504d523676524b7352545a55486a727272635779346333477974374b3649794157586665307238513943696261414231364b3538674244514d57314b6939626372382b78696f4b3278776453396a7330413df805e7e4068206257b226375725f72617465223a6e756c6c2c22737570706f72745f65746332223a747275657d8806019006019a060134a2060134b20600')
        dT = dT.replace(b'2026-06-29 13:42:51' , str(datetime.now())[:-7].encode())
        dT = dT.replace(b'f880f01893fc782df0c9586ebeb22a4c6c94da62cc453e01f34e658a8095af70', a.encode())
        dT = dT.replace(b'dec2e823a7f0770c887ef1ca4d011c0c', o.encode())
        
        PyL = bytes.fromhex(EnC_AEs(dT.hex()))
        r = requests.Session().post(
            "https://loginbp.ggpolarbear.com/MajorLogin",
            headers={
                "Expect": "100-continue",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB54",
                "Authorization": "Bearer ",
                "Host": "clientbp.ggpolarbear.com"
            },
            data=PyL,
            verify=False
        )
        
        if r.status_code == 200:
            response_data = json.loads(DeCode_PackEt(binascii.hexlify(r.content).decode('utf-8')))
            return response_data['8']['data']
        else:
            print(f"خطأ في MajorLogin: {r.status_code}")
            return None
    except Exception as e:
        print(f"حدث خطأ في xJwT: {str(e)}")
        return None

def ToK():
    while True:
        try:
            r = requests.get('https://tokens-asfufvfshnfkhvbb.francecentral-01.azurewebsites.net/ReQuesT?&type=ToKens')
            t = r.text
            i = t.find("ToKens : [")
            if i != -1:
                j = t.find("]", i)
                L = [x.strip(" '\"") for x in t[i+11:j].split(',') if x.strip()]
                if L:
                    with open("token.txt", "w") as f:
                        f.write(random.choice(L))
        except: pass
        time.sleep(5 * 60 * 60)

Thread(target=ToK , daemon = True).start()

def GeTToK():  
    with open("token.txt") as f: return f.read().strip()
    
def Likes(id):
    try:
        text = requests.get(f"https://aw-zebi-5ir.onrender.com/ReQuesT?id={id}&type=likes").text
        get = lambda p: re.search(p, text)
        name, lvl, exp, lb, la, lg = (get(r).group(1) if get(r) else None for r in 
            [r"PLayer NamE\s*:\s*(.+)", r"PLayer SerVer\s*:\s*(.+)", r"Exp\s*:\s*(\d+)", 
             r"LiKes BeFore\s*:\s*(\d+)", r"LiKes After\s*:\s*(\d+)", r"LiKes GiVen\s*:\s*(\d+)"])
        return name , f"{lvl}" if lvl else None, int(lb) if lb else None, int(la) if la else None, int(lg) if lg else None
    except: return None, None, None, None, None
    
def Requests_SPam(id):
    Api = requests.get(f'https://api-huh-c4.onrender.com//ReQuesT?id={id}&type=spam')        
    if Api.status_code in [200, 201] and '[SuccessFuLy] -> SenDinG Spam ReQuesTs !' in Api.text: return True
    else: return False




    
load_blacklist() ; encrypt_uids()    
load_approve() ; encrypt_uids2()   
like_data_clan , like_data , room_data = L_DaTa()
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
