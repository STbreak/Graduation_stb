#ここにVCID_Listの内ランダムに任意個数分だけVCIDを取り出すプログラムを書く
import pdb
import random
import binascii

#limit後のパス設定
path = "./VCID_limited/VCID_10_in_10.txt"
path_r = "./VCID_Lists/VCID_10.txt"

#define
vlist_num = 10

#VCIDをファイルから読み出す
with open(path_r, mode='r') as f:
    VCID_List = f.read().split('\n')
    

    #最後の空白の要素を消す
    del VCID_List[-1]

#limitする
Limited_List = random.sample(VCID_List, vlist_num)

#格納する
with open(path, mode='a') as f:
    for x in Limited_List:
        f.write(x + '\n')

