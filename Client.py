#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from time import sleep

#グローバル変数のdefine
len_gcid_upper = 16
len_private = 1191
len_gcid = len_gcid_upper + len_private
len_vcid_upper = 16
len_sequence = 16
len_vcid_plain = len_vcid_upper + len_sequence
len_vcid_cipher = 256
len_vcid = len_vcid_plain + len_vcid_cipher


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
    print(repr(GCID))

sleep(15)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:                                                                                                                                            
    # サーバを指定
    s2.connect(('127.0.0.1', 10002))
    # サーバにメッセージを送る
    s2.sendall(b'I want you to give VCL')
     # ネットワークのバッファサイズは1024。サーバからの文字列を取得する
    VCID = s2.recv(2048)
    print(repr(VCID))



'''
<<Step3：復号処理>>
・VCID・GCIDから鍵と平文を取り出す
・VCIDの暗号文を鍵で復号
・認証
'''

#GCIDから秘密鍵を取り出す
private_key_client_int = ((int.from_bytes(GCID, 'big') << (len_gcid_upper * 8)) & (2 ** (len_gcid * 8) - 1)) >> (len_gcid_upper * 8)
private_key_client = private_key_client_int.to_bytes(len_private, 'big')

	#秘密鍵の属性をRSAkeyに変換
private_key_client = RSA.import_key(private_key_client, None)

#秘密鍵でVCIDを開ける
	#VCIDの暗号文を取得
ciphertext_client_int = ((int.from_bytes(VCID, 'big') << (len_vcid_plain * 8)) & (2 ** (len_vcid * 8) - 1)) >> (len_vcid_plain * 8)
ciphertext_client = ciphertext_client_int.to_bytes(len_vcid - len_vcid_plain, 'big')

	#VCIDの平文を取得
vcid_plain_client_int = int.from_bytes(VCID, 'big') >> ((len_vcid - len_vcid_plain) * 8)
vcid_plain_client = vcid_plain_client_int.to_bytes(len_vcid_plain, 'big')

#復号処理
cipher_client = PKCS1_OAEP.new(private_key_client)
plaintext = cipher_client.decrypt(ciphertext_client)

#認証処理
if plaintext == vcid_plain_client:
	print("Done：認証")
elif plaintest != vcid_plain_client:
	print("認証失敗")
else:
	print("なんらかのerror")


'''

1208 認証できた！！


result

Done：GCID生成

Done：VCID生成

Done：認証

'''
