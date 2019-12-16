#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#グローバル変数のdefine
len_gcid_upper = 16
len_private = 1191
len_gcid = len_gcid_upper + len_private
len_vcid_upper = 16
len_sequence = 16
len_vcid_plain = len_vcid_upper + len_sequence
len_vcid_cipher = 256
len_vcid = len_vcid_plain + len_vcid_cipher

#GCIDリストのパス設定
path_w = "./GCID_List.txt"

'''
<<Step4：socket通信の導入>>

'''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # サーバを指定
    s.connect(('127.0.0.1', 10000))
    # サーバにメッセージを送る
    s.sendall(b'I want you to give GCID')
    # ネットワークのバッファサイズは1024。サーバからの文字列を取得する
    GCID = s.recv(2048)
    print("Bought GCID:\n" + GCID.hex())
    print(len(GCID))

pdb.set_trace()

with open(path_w, mode='ab') as f:
    f.write(GCID + b',,,')

'''

1208 認証できた！！


result

Done：GCID生成

Done：VCID生成

Done：認証

'''
