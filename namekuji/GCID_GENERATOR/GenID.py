#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import random
import binascii
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#GCIDリストのパス設定
path = "./GCID_List9.txt"

'''
<<Step1：GCIDの作成>>
・型はbytes型
・上位128bitはとりあえず適当な128bitにする
・秘密鍵はpythonのやつだと1191byteだった
・GCIDは1207byteになる
'''

start = time.time()

for i in range(9):
    #平文（GCIDの上位128bit,type:bytes）の作成
    len_gcid_upper = 16
    gcid_upper = random.randrange(2 ** 128).to_bytes(len_gcid_upper, 'big')

    #秘密鍵の作成
    private_key = RSA.generate(2048)
    len_private = len(private_key.export_key('DER')) #len_private：秘密鍵のbyte長

    #GCID(bytes)の作成
    GCID_int = (int.from_bytes(gcid_upper, 'big') << (len_private * 8)) | int.from_bytes(private_key.export_key('DER'), 'big') #gcid_upperの後に秘密鍵をくっつける
    GCID = GCID_int.to_bytes(len_gcid_upper + len_private, 'big')
    len_gcid = len(GCID)


    #GCIDを文字列としてリストに格納
    with open(path, mode='a') as f:
        f.write(GCID.hex() + '\n')
    #Step1の完了

    print("Done：GCID生成[{}]\n".format(i))

elapsed_time = time.time() - start
print ("elapsed time;{}".format(elapsed_time) + "[sec]")

'''
result


'''
