#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


'''
<<Step4：socket通信の導入>>

'''

#CSからGCIDを貰う

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # サーバを指定
    s.connect(('127.0.0.1', 10001))
    # サーバにメッセージを送る
    s.sendall(b'I want you to give GCID.')
    # ネットワークのバッファサイズは1024。サーバからの文字列を取得する
    GCID = s.recv(2048)
    print("Got GCID:\n" + GCID.hex())

#CSにGCIDを送ってそれを元にしたVCLを作って貰う

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # サーバを指定
    s.connect(('127.0.0.1', 10002))
    # サーバにGCIDを送る
    s.sendall(GCID)
    # ネットワークのバッファサイズは2048。サーバからVCIDを取得する
    VCID = s.recv(2048)
    print("MADE VCID:\n" + VCID.hex())
            



# Clientの要求待ち            
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
    # IPアドレスとポートを指定
    s2.bind(('127.0.0.1', 10003))
    # 1 接続
    s2.listen(1)
    # connectionするまで待つ
    while True:
        # connectionがあればコネクションとアドレスを入れる
        conn, addr = s2.accept()
        with conn:
            while True:
                #データを受け取る
                data = conn.recv(2048)
                if not data:
                    break
                print('data : {}, addr: {}'.format(data, addr))
                conn.sendall(VCID)
        break

'''
result


'''
