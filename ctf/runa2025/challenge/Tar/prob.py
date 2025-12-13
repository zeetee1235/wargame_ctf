import gzip, base64

with open('./flag','r') as f:
    flag = f.readline()

try:
    data = base64.b64decode(input("Input : ").strip())
    unzip = gzip.decompress(data)
    if unzip == data and data:
        print(flag)
    else :
        print("GET OUT")
except:
    print("It is not gzip")