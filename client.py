import socket

HOST = "127.0.0.1"
PORT = 7777

ip = b"127.0.0.2"

# direct usage
#ip = request.META.get('REMOTE_ADDR')

cmd = b"ban"

ip_pad = 16 - len(ip)
cmd_pad = 10 - len(cmd)

to_send = ip + b"\0" * ip_pad + cmd + b"\0" * cmd_pad

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
