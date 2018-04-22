import socket
import struct
import sys
import os
import math
import getpass
import threading
from subprocess import call
from hashlib import md5

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


def create_remote_dir(ip, dirpath):
	command = 'ssh -q -o "StrictHostKeyChecking no" %s \"mkdir -p %s && chmod 777 %s\"' % (ip, dirpath, dirpath)
	os.system(command)


def create_remote_file(ip, filepath, localpath):

	command = 'scp -q -B %s %s:%s' % (localpath, ip, filepath)
	os.system(command)

	command = 'ssh -q -o "StrictHostKeyChecking no" %s \"chmod 666 %s/*\"' % (ip, filepath)
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


def get_partition(username, filename, partition_power):

        key = '%s/%s' % (username, filename)
        objhash = md5(key.encode('utf-8')).hexdigest()
        partition = int(int(objhash, 16) >> 128 - partition_power)
        return partition


def get_disk(partition, partition_power, disks):

	partitions = 2**partition_power
	partitions_per_disk = partitions/len(disks)
	disk = min(math.ceil(partition/partitions_per_disk), partition_power)
	backup_disk = (disk % len(disks)) + 1
	return disks[disk - 1], disks[backup_disk - 1]


def upload_to_disk(disk, remotepath, localpath, client_filename, prompt=False):
	create_remote_dir(disk, remotepath)
	create_remote_file(disk, remotepath, localpath)

	if prompt:
		print('Uploaded %s to disk %s' % (client_filename, disk))


def upload(conn, partition_power, disks):
	client_username = customized_recv(conn).decode('utf-8')
	client_filename = customized_recv(conn).decode('utf-8')
	client_filedata = customized_recv(conn)

	upload_dir = './upload-files/'

	if not os.path.exists(upload_dir):
		os.makedirs(upload_dir)

	localpath = upload_dir + client_filename

	with open(localpath, 'wb+') as f:
		f.write(client_filedata)

	partition = get_partition(client_username, client_filename, partition_power)
	disk, backup_disk = get_disk(partition, partition_power, disks)
	remotepath = '/tmp/' + USERNAME + '/' + client_username
	remotebackuppath = '/tmp/' + USERNAME + '/backup/' + client_username

	upload_to_disk(disk, remotepath, localpath, client_filename, True)
	threading.Thread(target=upload_to_disk, args=(backup_disk, remotebackuppath, localpath, client_filename,)).start()


def main():

	if not validate_command_args():
		return

	# Exception needed for partition power > 32
	try:
		partition_power = int(sys.argv[1])
	except:
		print('Invalid command format. Partition power must be an integer')

	disks = sys.argv[2:]

	if not validate_disk_addresses(disks):
		return

	# get valid disks within disks variable - include Y/n prompt

	sock = create_socket()

	for disk in disks:
		create_remote_dir(disk, '/tmp/' + USERNAME)

	while True:
		conn, addr = sock.accept()

		client_command = customized_recv(conn).decode('utf-8')
		if client_command == 'upload':
			upload(conn, partition_power, disks)

	socket.close()


main()