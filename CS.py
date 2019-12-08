#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP



'''
<<Step1：GCIDの作成>>
・型はbytes型
・上位128bitはとりあえず適当な128bitにする
・秘密鍵はpythonのやつだと1191byteだった
・GCIDは1207byteになる
'''


#平文（GCIDの上位128bit,type:bytes）の作成
len_gcid_upper = 16
gcid_upper = random.randrange(2 ** 128).to_bytes(len_gcid_upper, 'big')

#秘密鍵の作成
private_key = RSA.generate(2048)
len_private = len(private_key.export_key('DER')) #len_private：秘密鍵のbyte長

#秘密鍵に基づく公開鍵の生成
public_key = private_key.publickey()

#GCID(bytes)の作成
GCID_int = (int.from_bytes(gcid_upper, 'big') << (len_private * 8)) | int.from_bytes(private_key.export_key('DER'), 'big') #gcid_upperの後に秘密鍵をくっつける
GCID = GCID_int.to_bytes(len_gcid_upper + len_private, 'big')
len_gcid = len(GCID)

#Step1の完了

print("Done：GCID生成\n")


'''
<<Step4：socket通信の導入>>
 
'''
 
 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # IPアドレスとポートを指定
    s.bind(('127.0.0.1', 10000))
    # 1 接続
    s.listen(1)
    # connectionするまで待つ
    while True:
        # connectionがあればコネクションとアドレスを入れる
        conn, addr = s.accept()
        with conn:
            while True:
                #データを受け取る
                data = conn.recv(2048)
                if not data:
                    break
                print('data : {}, addr: {}'.format(data, addr))
                conn.sendall(GCID)
                break
        break

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # IPアドレスとポートを指定
    s.bind(('127.0.0.1', 10001))
    # 1 接続
    s.listen(1)
    # connectionするまで待つ
    while True:
        # connectionがあればコネクションとアドレスを入れる
        conn, addr = s.accept()
        with conn:
            while True:
                #データを受け取る
                data = conn.recv(1024)
                if not data:
                    break
                print('data : {}, addr: {}'.format(data, addr))

                '''
                <<Step2：VCLの作成>>
                ・型はbytes型
                ・上位128bit
                ・シーケンス128bit（仮）
                ・暗号文256byte
                ・合わせて288byteになる
                '''



                #VCLの上位128bitの作成
                len_vcid_upper = 16
                vcid_upper = random.randrange(2 ** 128).to_bytes(len_vcid_upper, 'big')

                #シーケンス（とりあえず128bit）の作成
                len_sequence = 16
                sequence = random.randrange(2 ** (len_sequence * 8)).to_bytes(16, 'big')

                #平文（上位128bitとシーケンスの合計）の作成
                len_vcid_plain = len_vcid_upper + len_sequence
                vcid_plain_int = (int.from_bytes(vcid_upper, 'big') << (len_sequence * 8)) | int.from_bytes(sequence, 'big') #vcid_plain（int型）の作成)
                vcid_plain = vcid_plain_int.to_bytes(len_vcid_plain, 'big')

                #暗号文の作成
                cipher = PKCS1_OAEP.new(public_key)
                ciphertext = cipher.encrypt(vcid_plain)
                len_ciphertext = len(ciphertext)

                #VCLの作成
                VCID_int = (int.from_bytes(vcid_plain, 'big') << (len_ciphertext * 8)) | int.from_bytes(ciphertext, 'big')
                VCID = VCID_int.to_bytes(len_vcid_plain + len_ciphertext, 'big')
                len_vcid = len(VCID)

                #Step2の完了

                print("Done：VCID生成\n")
                
                #GMにVCLを送る
                conn.sendall(VCID)
                break
        break
'''
result


'''
