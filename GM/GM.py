#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


'''
<<Step4：socket通信の導入>>

'''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # サーバを指定
    s.connect(('127.0.0.1', 10001))
    # サーバにメッセージを送る
    s.sendall(b'I want you to make VCL.')
    # ネットワークのバッファサイズは1024。サーバからの文字列を取得する
    VCID = s.recv(2048)
    print("MADE VCID:\n" + VCID.hex())
            



# Clientの要求待ち            
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
    # IPアドレスとポートを指定
    s2.bind(('127.0.0.1', 10002))
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
