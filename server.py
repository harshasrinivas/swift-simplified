import socket
import struct
import sys, os
import getpass
from subprocess import call

USERNAME = getpass.getuser()

def customized_recvall(conn, count):
    buf = ''.encode('utf-8')
    while count:
        newbuf = conn.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf


def customized_recv(conn):
	lengthbuf = customized_recvall(conn, 4)
	length, = struct.unpack('!I', lengthbuf)
	return customized_recvall(conn, length)


def create_socket():

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind(('', 0))
	sock.listen(1)

	PORT = sock.getsockname()[1]
	HOSTNAME = socket.getfqdn()
	IP_ADDRESS = socket.gethostbyname(HOSTNAME)

	print('Server IP: ', IP_ADDRESS)
	print('Server Port: ', PORT)
	print('Server Hostname: ', HOSTNAME)

	return sock


def create_remote_dir(ip, parent, dirname):
	command = 'ssh %s \"mkdir -p %s/%s && chmod 777 %s/%s\"' % (ip, parent, dirname, parent, dirname)
	os.system(command)


def validate_command_args():
	if len(sys.argv) < 3:
		print('Invalid command format.\nUsage: ./server.py 16 129.210.16.80 129.210.16.81 129.210.16.82')
		return False
	return True


def validate_disk_addresses(disks):

	return_val = True

	for i in disks:

		try:
			[i1, i2, i3, i4] = i.split('.')

			if i1 == '129' and i2 == '210' and i3 == '16' and i4 >= '80' and i4 <= '99':
				continue
			else:
				print('Invalid command format.\nIP addresses of the drives must be within the range of 129.210.16.80 - 129.210.16.99')
				return_val = return_val & False
				break
		except:
			print('Invalid IP address format')
			return_val = return_val & False
			break

	return return_val & validate_disk_duplicates(disks)


def validate_disk_duplicates(disks):

	seen = set()
	uniq = [x for x in disks if x not in seen and not seen.add(x)]
	if len(uniq) != len(disks):
		print('Invalid IP format - Duplicate IPs')
		return False
	return True


def main():

	if not validate_command_args():
		return

	partitions = sys.argv[1]
	disks = sys.argv[2:]

	if not validate_disk_addresses(disks):
		return

	sock = create_socket()

	for disk in disks:
		create_remote_dir(disk, '/tmp', USERNAME)

	while True:
		conn, addr = sock.accept()

		print('New client connected')

		# CREATE LOGGING

		client_command = customized_recv(conn).decode('utf-8')
		client_username = customized_recv(conn).decode('utf-8')
		client_filename = customized_recv(conn).decode('utf-8')
		client_filedata = customized_recv(conn)

		server_filename = client_filename + '_server'

		with open(server_filename, 'wb+') as f:
			f.write(client_filedata)



	socket.close()


main()