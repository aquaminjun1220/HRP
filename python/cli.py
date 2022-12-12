import socket

cli_addr = "0.0.0.0"
cli_port = 5060

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((cli_addr, cli_port))
print("Cli Bind to {0}, {1}".format(cli_addr, cli_port))

while True:
    if input("Ready to send?") == "NO":
        break
    ip = input("IP")
    if ip == '':
        ip = '127.0.0.1'
    prt = input("PORT")
    if prt == '':
        prt = '8888'
    data = "A" * 10
    sock.sendto(data.encode(), (ip, int(prt)))
sock.close()