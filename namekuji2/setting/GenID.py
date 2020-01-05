#socketとpdbとrandomとRSAとPKCS1のライブラリ導入
import socket
import pdb
import binascii
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA384        
from Crypto.Signature import pkcs1_15   

#GCIDリストのパス設定
path_g = "./GCID_Lists/GCID_10.txt"
path_v = "./VCID_Lists/VCID_10.txt"

#繰り返し回数のdefine
num = 10

for i in range(num):


    '''
    <<Step1：GCIDの作成>>
    ・型はbytes型
    ・上位128bitはとりあえず適当な128bitにする
    ・秘密鍵はpythonのやつだと1191byteだった
    ・GCIDは1207byteになる
    '''

    #平文（GCIDの上位128bit,type:bytes）の作成
    len_gcid_upper = 16
    gcid_upper = get_random_bytes(16)

    #秘密鍵の作成
    private_key = RSA.generate(2048)
    len_private = len(private_key.export_key('DER')) #len_private：秘密鍵のbyte長

    #公開鍵を作成                           
    public_key = private_key.publickey()
    len_public = len(public_key.export_key('DER')) #len_public：公開鍵のbyte長

    #共通鍵を作成
    key = get_random_bytes(16)
    len_key = len(key)

    #GCID(bytes)の作成
    GCID_int = (int.from_bytes(gcid_upper, 'big') << (len_key * 8) << (len_public * 8)) | (int.from_bytes(key, 'big') << (len_public * 8)) | (int.from_bytes(public_key.export_key('DER'), 'big')) #gcid_upperの後に共通鍵、公開鍵を付与
    GCID = GCID_int.to_bytes(len_gcid_upper + len_public + len_key, 'big')
    len_gcid = len(GCID)


    #GCIDを文字列としてリストに格納
    with open(path_g, mode='a') as f:
        f.write(GCID.hex() + '\n')
    #Step1の完了

    print("Done：GCID生成\n")


    '''
    <<Step2：VCLの作成>>
    ・型はbytes型
    ・上位128bit
    ・シーケンス128bit（仮）
    ・暗号文?byte
    ・Signature
    ・暗号文にtagとnonceを付与
    ・合わせて?byteになる
    '''

    '''
    <<<pattern1:Signature->AES>>>
    '''

    #VCLの上位128bitの作成
    len_vcid_upper = 16
    vcid_upper = get_random_bytes(16)

    #シーケンス（とりあえず128bit）の作成
    len_sequence = 16
    sequence = get_random_bytes(16)

    #上位128bitとシーケンスの合計の作成
    len_vcid_upper_sequence = len_vcid_upper + len_sequence
    vcid_upper_sequence_int = (int.from_bytes(vcid_upper, 'big') << (len_sequence * 8)) | (int.from_bytes(sequence, 'big')) #vcid_upper_sequence（int型）の作成)
    vcid_upper_sequence = vcid_upper_sequence_int.to_bytes(len_vcid_upper_sequence, 'big')

    #電子署名の追加
    h1 = SHA384.new(vcid_upper_sequence)
    signature = pkcs1_15.new(private_key).sign(h1)
    len_signature = len(signature)

    #平文の生成
    len_vcid_plain = len_vcid_upper_sequence + len_signature
    vcid_plain_int = (int.from_bytes(vcid_upper_sequence, 'big') << (len_signature * 8)) | (int.from_bytes(signature, 'big')) 
    vcid_plain = vcid_plain_int.to_bytes(len_vcid_plain, 'big')

    #暗号文の作成
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(vcid_plain)
    len_ciphertext = len(ciphertext)
    len_tag = len(tag)
    len_nonce = len(nonce)

    #VCLの作成
    VCID_int = (int.from_bytes(vcid_plain, 'big') << ((len_ciphertext + len_tag + len_nonce) * 8)) | (int.from_bytes(ciphertext, 'big') << ((len_tag + len_nonce) * 8)) | (int.from_bytes(tag, 'big') << (len_nonce * 8)) | (int.from_bytes(nonce, 'big'))
    VCID = VCID_int.to_bytes(len_vcid_plain + len_ciphertext + len_tag + len_nonce, 'big')
    len_vcid = len(VCID)

    #VCIDを文字列としてリストに格納                                                                  
    with open(path_v, mode='a') as f:
        f.write(VCID.hex() + '\n')

    #Step2の完了

    print("Done：VCID生成\n")


'''
result


'''
