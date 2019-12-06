#pdbとrandomとRSAとPKCS1のライブラリ導入
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
gcid_plain = random.randrange(2 ** 128).to_bytes(16, 'big')

#秘密鍵の作成
private_key = RSA.generate(2048)
len_private = len(private_key.export_key('DER')) #len_private：秘密鍵のbyte長

#秘密鍵に基づく公開鍵の生成
public_key = private_key.publickey()

pdb.set_trace()

#GCID(bytes)の作成
GCID_int = (int.from_bytes(gcid_plain, 'big') << (len_private * 8)) | int.from_bytes(private_key.export_key('DER'), 'big') #gcid_plainの後に秘密鍵をくっつける

GCID = GCID_int.to_bytes(16 + len_private, 'big')

#GCIDの出力

print("Made GCID:\n{}\n".format(GCID))




'''
<<Step2：VCLの作成>>

'''
#VCLの上位128bitの作成
vcid_upper = random.randrange(2 ** 128).to_bytes(16, 'big')

#シーケンス（とりあえず128bit）の作成
len_sequence = 16
sequence = random.randrange(2 ** (len_sequence * 8)).to_bytes(16, 'big')

#平文（上位128bitとシーケンスの合計）の作成
vcid_plain = int.from_bytes(vcid_upper, 'big') << (len_sequence * 8) | int.from_bytes(sequence, 'big') #vcid_plain（int型）の作成)



'''
result


1205 GCID bytes型で実装完了！！！！



'''
