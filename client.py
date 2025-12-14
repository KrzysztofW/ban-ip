import socket

HOST = "127.0.0.1"
PORT = 7777

ip = b"85.34.55.44"

# direct usage
#ip = request.META.get('REMOTE_ADDR')

cmd = b"ban"
desc = b"application XXX"

to_send = cmd + b"\0" + ip + b"\0" + desc
length = len(to_send).to_bytes(2, byteorder="big") # 16-bit unsigned, big-endian
to_send = length + to_send

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(to_send)


"""" In a django view: """
## direct usage
##ip = str.encode(request.META.get('REMOTE_ADDR'))
#
## if used behide a reverse proxy
#ip = request.META.get('HTTP_X_FORWARDED_FOR')
#if ip == "":
#    return HttpResponse('')
#
#ip = ip.split(', ')[-1]
#ip = str.encode(ip)
