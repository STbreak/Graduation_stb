#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import random
import binascii
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA384
from Crypto.Signature import pkcs1_15

#グローバル変数のdefine
len_gcid_upper = 16
len_key = 16
len_vcid_upper = 16
len_sequence = 16
len_signature = 256
len_ciphertext = 288
len_tag = 16
len_nonce = 16
len_vcid_plain = len_vcid_upper + len_sequence + len_signature
len_vcid = len_vcid_plain + len_ciphertext + len_tag + len_nonce
n = 10

#GCIDリストへのパスの設定
path = "../setting/GCID_Lists/GCID_10.txt"

'''
<<Step4：socket通信の導入>>

'''

start = time.time()

for i in range(n):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2: 
        # サーバを指定
        s2.connect(('127.0.0.1', 10000 + i))
        # サーバにメッセージを送る
        s2.sendall(b'I want you to give VCL')
         # ネットワークのバッファサイズは1024。サーバからの文字列を取得する
        VCID = s2.recv(2048)
        print("Got VCID:\n" + VCID.hex())



    '''
    <<Step3：復号処理>>
    ・VCID・GCIDから鍵と平文を取り出す
    ・VCIDの暗号文を鍵で復号
    ・認証
    '''

    #GCIDをファイルから読み出す
    with open(path, mode='r') as f:
        GCID_List = f.read().split('\n')
        del GCID_List[-1]

    for GCID in GCID_List:
        #GCIDの型をbytesに戻す
        GCID = binascii.unhexlify(GCID)
        
        #GCIDから公開鍵を取り出す
        len_gcid = len(GCID)
        len_public = len_gcid - len_gcid_upper -len_key
        public_key_client_int = ((int.from_bytes(GCID, 'big') << ((len_gcid_upper + len_key) * 8)) & (2 ** (len_gcid * 8) - 1)) >> ((len_gcid_upper + len_key) * 8)
        public_key_client = public_key_client_int.to_bytes(len_public, 'big')

        #GCIDから共通鍵を取り出す
        key_client_int = ((int.from_bytes(GCID, 'big') >> (len_public * 8) << (len_gcid_upper * 8)) & (2 ** ((len_gcid - len_public) * 8) - 1)) >> (len_gcid_upper * 8)
        key_client = key_client_int.to_bytes(len_key, 'big')

        #VCIDの暗号文・tag・nonceを取得
        nonce_int = ((int.from_bytes(VCID, 'big') << ((len_vcid - len_nonce) * 8)) & (2 ** (len_vcid * 8) - 1)) >> ((len_vcid - len_nonce) * 8) 
        nonce = nonce_int.to_bytes(len_nonce, 'big')
        
        tag_int = ((int.from_bytes(VCID, 'big') >> (len_nonce * 8) << ((len_vcid_plain + len_ciphertext) * 8)) & (2 ** ((len_vcid - len_nonce) * 8) - 1)) >> ((len_vcid_plain + len_ciphertext) * 8)
        tag = tag_int.to_bytes(len_tag, 'big')

        ciphertext_int = ((int.from_bytes(VCID, 'big') >> ((len_nonce + len_tag) * 8) << (len_vcid_plain * 8)) & (2 ** ((len_vcid_plain + len_ciphertext) * 8) - 1)) >> (len_vcid_plain * 8)
        ciphertext = ciphertext_int.to_bytes(len_ciphertext, 'big')
        

        #VCIDの平文を取得
        vcid_plain_client_int = int.from_bytes(VCID, 'big') >> ((len_vcid - len_vcid_plain) * 8)
        vcid_plain_client = vcid_plain_client_int.to_bytes(len_vcid_plain, 'big')

        #復号処理
        #共通鍵を使う
        cipher = AES.new(key_client, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        len_plaintext = len(plaintext)
        try:
            cipher.verify(tag)
            print("第一段階クリア")

            #署名と元文を取り出す
            signature_int = ((int.from_bytes(plaintext, 'big') << ((len_vcid_upper + len_sequence) * 8)) & (2 ** (len_plaintext * 8) - 1)) >> ((len_vcid_upper + len_sequence) * 8)
            signature = signature_int.to_bytes(len_signature, 'big')

            original_int = int.from_bytes(plaintext, 'big') >> (len_signature * 8)
            original = original_int.to_bytes(len_vcid_upper + len_sequence, 'big')

            #認証
            h2 = SHA384.new(original)
            try:
                pkcs1_15.new(RSA.import_key(public_key_client, passphrase=None)).verify(h2, signature)
                print("第二段階クリア")

                break
            except ValueError:
                print("通報しましょう")
                break

        except ValueError:
            print("認証失敗")
            continue

elapsed_time = time.time() - start

#処理時間を出力
print("elapsed time:{}".format(elapsed_time) + "[sec]")

'''
result

Got VCID:
dd43e207ce148dd2b10e66de9cc9d222dafc7741637b3bc4e3874da637e89e20251c2c6972d62ebcba2f1e5cc5b750ed28055acdb58a935851f70f343fa6c41490f29e3687d5f21725bee6c9d8471babb215a4a0178317ca5b82facca5cb304e8d8db4d96723628f099f2e88c7e883c366c6eaa946c8368b95ff42685814d4ab7db70aaa58c7d0cb2898772ebd7f79997cac019a2e13739abe6b486bef3387567eebe6703b835949e7806811359a5bf5378b4d476e7c0db5830a966db5b0782a843997d54c41496a8d65ea45c52ab078cfa098918e515943e52c497e60b7608e231773ecb77746d54900184c2aba1e66365317e914ce2058c3e60da934d3ad9e5d6fc3213beda256f63cf08cf7be872714daea8a09108caae7f3c81e34bdecb8
Traceback (most recent call last):
  File "authentication.py", line 55, in <module>
    private_key_client = RSA.import_key(private_key_client, None)
  File "/Users/tanakasatoshishi/.pyenv/versions/3.7.0/lib/python3.7/site-packages/Crypto/PublicKey/RSA.py", line 781, in import_key
    raise ValueError("RSA key format is not supported")
ValueError: RSA key format is not supported

'''
