import socket
import pdb
import random
import binascii

#pathの設定
path = "../setting/VCID_limited/VCID_10_in_10.txt"

#元のVCIDをランダムに選択
#VCIDをファイルから読み出す
with open(path, mode='r') as f:
    VCID_List = f.read().split('\n')

for i in range(len(VCID_List) - 1):
    #ClientにVCIDを渡す
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # IPアドレスとポートを指定
        s.bind(('127.0.0.1', 10000 + i))
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
                    
                    VCID = VCID_List[random.randrange(len(VCID_List) - 1)]
                    VCID = binascii.unhexlify(VCID)                    
                    conn.sendall(VCID)
                    break
            break
