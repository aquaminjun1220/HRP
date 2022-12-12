import socket

serv_addr = "0.0.0.0"
serv_port = 8888

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((serv_addr, serv_port))
print("Serv Bind to {0}, {1}".format(serv_addr, serv_port))

while True:
    if input("Ready to recieve?") == "NO":
        break
    bdata, addr = sock.recvfrom(1024)
    print(bdata.decode())
    print(addr)
sock.close()