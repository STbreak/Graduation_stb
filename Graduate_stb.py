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
