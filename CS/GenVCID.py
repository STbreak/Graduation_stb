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



'''
<<Step4：socket通信の導入>>
 
'''
 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # IPアドレスとポートを指定
    s.bind(('127.0.0.1', 10002))
    # 1 接続
    s.listen(1)
    # connectionするまで待つ
    while True:
        # connectionがあればコネクションとアドレスを入れる
        conn, addr = s.accept()
        with conn:
            while True:
                #データを受け取る
                GCID = conn.recv(2048)
                if not GCID:
                    break
                print('Got GCID:\n' + GCID.hex())

                '''
                <<Step2：VCLの作成>>
                ・型はbytes型
                ・上位128bit
                ・シーケンス128bit（仮）
                ・暗号文256byte
                ・合わせて288byteになる
                '''

                #GCIDから鍵を取り出す
                private_key_int = ((int.from_bytes(GCID, 'big') << (len_gcid_upper * 8)) & (2 ** (len_gcid * 8) - 1)) >> (len_gcid_upper * 8)
                private_key_bytes = private_key_int.to_bytes(len_private, 'big')

                #秘密鍵の属性をRSAKeyに変換
                private_key = RSA.import_key(private_key_bytes, passphrase=None)

                #秘密鍵に基づく公開鍵を作成
                public_key = private_key.publickey()


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

Got GCID:
ca14606d6e6c1e3b21f3e45eaccadd68308204a50201000282010100ecef9dcff0871e4d8242b830e6e336f6ebee2263676992bb555debb5b539c2d32618b244281914034585919658c0726cd0992ffae6458138c651033222a3e8265ba2d3f97a9e92d37ed5b80da56a710edfd328422bbff5973e74ab07ef21ad9d9cd6e7db479082c4a2f3d66c8ef3a347a8be613fdf315bd12793d67eddda913a1f28ee0f038362c7d283799e41489c349e5178a8c1a117a99004cf4e13318aaa4df76a9f0eac5971aaffb34889c58ee245c2e4b1a27932af75dc04113f925fe6c13c8bb871d30e3b164740ad9fd7aff94288498c10afbd8ff6e7d9bc155784a9df4b7a73a37504cd7537bcd951d97fa702995708b3d4125380bee1d76645b84302030100010282010000e3ad5df8732963f5173705c7f8165ebae7fbed0f984fdab02958172884fcfc39ea61d0ebad9c6b9eb92fa0b6d89215627b10b90a603c69f024a1b47078d9083bd3d2a3df17f54921f2bf6c1db0d697cdb347356860a2155d40a6dbb2c41798bddbf8a6d40ff0cdb826de292e282ff6b6e5700c03547619c4e2432ddabb554c36b4332c23d7c621d81305e2a73fc64d0fc6239b3baf3b22f4050b5e152febf8e3d80e4e6b036bdf929a0cd3715c8d10765ab4ade8882a2a2f0576a0f25e106fa5ca7a50f35aaff36339cce15046faf9e14ed51417a964ba44f097494f7f3f792f3e1c4c1fb0595d5ed6a2cc8c7d44389da9b3942368435ebd99f5f51b22f44102818100ef2dc238b4e22b92d9269264d8de5f630e0b0d757f692af347dd3e740dc14d89ede6f3ba26f33e049907f543e09483af233d6da26d73f5b87ee6b5815862bf567066710563028b341cdb7155bf5ea7c4f689d9808f62cc9d7261bde5f65f8ee5f2a08009934c8cd657f83953b3e6b0e6d2356d9bf696dfd9ad18885f846f79b102818100fd997a92a62248413f3990257edd2d61186433a88ca98ab2ff4fbf8c6f947ee220a4149471418cdcf74dabd06eebeaecf9c2d41430c827ca05e5054a2efac22a1882bda2c01a14a3edc746e6483b5eb9345bb1af2856f14c5c157badc2cf67c96c5c5e12a9aea820876345ee6c3081dd72a9624e9331fb51456434f9dd9c9a3302818100afd5801798433dad739efbb8d0068b31933d64e3a08b7c5be5d52cf8bcb403810738e6ad4fbd3b36be1a2fa17b1533ca29aa1b53720bf1f574b5bf721bbc5cd5fb44148ad543257b664b9d82607201fcb71298a7fec1af93806782e7f0bc479d9d45895b80c2a23761ecc69856859e3fd3021c56b06e329b20ba0c67cc40f7c1028181009c6c56d6adf2e76e977902189eaffe95ad5de11f4de425d152f9f5c4c1ee6e753c7cf8d4b7271fa40c46b47bd46f6070db7df9229b145ab699fc31cf183b44188315e1b2c99b4caff0b2c260b89d264846ab68660a13d6b2aaf9f557b09a0e0287fc516a618f81d4ceadc52cd33ef85b87a6432504560816911ec62e792b675102818100da1b663389f73b497807ef3848cf5e99e9192b80c380e250b38ac550eea74061a7b168e355dbc2a0a77db7a13cf96eb93d6daac341d9f4ad559ac9626ae9a5e52476f1fec97a42ea7231ae3e774f61a25761db743fa260790fb2c4bd7c7a00c50c56d076d674c18415f25ff26a0b8e86cf7c4dc913ce01b1b1d90ec6255e6cb2
Traceback (most recent call last):
  File "GenVCID.py", line 51, in <module>
    private_key = RSA.import_key(private_key_bytes, None)
  File "/Users/tanakasatoshishi/.pyenv/versions/3.7.0/lib/python3.7/site-packages/Crypto/PublicKey/RSA.py", line 781, in import_key
    raise ValueError("RSA key format is not supported")
ValueError: RSA key format is not supported


'''
