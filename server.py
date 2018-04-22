import socket
import struct
import sys
import os
import math
import getpass
import threading
import subprocess
import shutil
from hashlib import md5

USERNAME = getpass.getuser()

maindict = dict()

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


def customized_send(conn, data):
    length = len(data)
    conn.sendall(struct.pack('!I', length))
    conn.sendall(data)


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


def delete_remote_dir(ip, dirpath):
	command = 'ssh -q -o "StrictHostKeyChecking no" %s \"rm -rf %s/*\"' % (ip, dirpath)
	os.system(command)


def create_remote_file(ip, filepath, localpath):

	command = 'scp -q -B %s %s:%s' % (localpath, ip, filepath)
	os.system(command)

	command = 'ssh -q -o "StrictHostKeyChecking no" %s \"chmod 666 %s/*\"' % (ip, filepath)
	os.system(command)


def download_remote_file(ip, filepath, localpath):

	command = 'scp -q -B %s:%s %s' % (ip, filepath, localpath)
	os.system(command)


def delete_remote_file(ip, filepath, client_filename):

	command = 'ssh -q -o "StrictHostKeyChecking no" %s \"rm -rf %s/%s\"' % (ip, filepath, client_filename)
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

			if i1 == '129' and i2 == '210' and i3 == '16' and i4 >= '71' and i4 <= '95':
				continue
			else:
				print('Invalid command format.\nIP addresses of the drives must be within the range of 129.210.16.71 - 129.210.16.95')
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
	else:
		print('Uploaded backup of %s to disk %s' % (client_filename, disk))


def upload(conn, partition_power, disks):
	client_username = customized_recv(conn).decode('utf-8')
	client_filename = customized_recv(conn).decode('utf-8')
	client_filedata = customized_recv(conn)

	global maindict

	if client_username not in maindict:
		maindict[client_username] = set()

	if client_filename in maindict[client_username]:
		customized_send(conn, b'File already exists. Would you like to overwrite? (Y/n)')
		response = customized_recv(conn).decode('utf-8')

		if 'y' in response or 'Y' in response:
			pass
		else:
			return

	maindict[client_username].add(client_filename)

	upload_dir = './server-uploads/'
	upload_subdir = './server-uploads/%s/' % client_username

	if not os.path.exists(upload_dir):
		os.makedirs(upload_dir)

	if not os.path.exists(upload_subdir):
		os.makedirs(upload_subdir)

	localpath = upload_subdir + client_filename

	with open(localpath, 'wb+') as f:
		f.write(client_filedata)

	partition = get_partition(client_username, client_filename, partition_power)
	disk, backup_disk = get_disk(partition, partition_power, disks)
	remotepath = '/tmp/' + USERNAME + '/' + client_username
	remotebackuppath = '/tmp/' + USERNAME + '/backup/' + client_username

	upload_to_disk(disk, remotepath, localpath, client_filename, True)
	upload_to_disk(backup_disk, remotebackuppath, localpath, client_filename)

	try:
		shutil.rmtree(upload_dir)
	except FileNotFoundError:
		pass

	customized_send(conn, disk.encode('utf-8'))
	customized_send(conn, remotepath.encode('utf-8'))
	customized_send(conn, socket.gethostbyaddr(disk)[0].encode('utf-8'))


def download_from_disk(disk, remotepath, localpath, conn):

	download_remote_file(disk, remotepath, localpath)

	with open(localpath, 'rb') as f:
		customized_send(conn, f.read())


def download(conn, partition_power, disks):
	client_username = customized_recv(conn).decode('utf-8')
	client_filename = customized_recv(conn).decode('utf-8')
	
	global maindict

	if client_username not in maindict:
		print('User %s not found' % client_username)
		customized_send(conn, b'failuser')
		return

	elif client_filename not in maindict[client_username]:
		print('File %s not found for User %s' % (client_filename, client_username))
		customized_send(conn, b'failfile')
		return


	partition = get_partition(client_username, client_filename, partition_power)
	disk, backup_disk = get_disk(partition, partition_power, disks)
	remotepath = '/tmp/' + USERNAME + '/' + client_username + '/' + client_filename
	remotebackuppath = '/tmp/' + USERNAME + '/backup/' + client_username + '/' + client_filename

	download_dir = './server-downloads/'
	download_subdir = './server-downloads/%s/' % client_username

	if not os.path.exists(download_dir):
		os.makedirs(download_dir)

	if not os.path.exists(download_subdir):
		os.makedirs(download_subdir)

	localpath = download_subdir + client_filename

	download_from_disk(disk, remotepath, localpath, conn)

	try:
		shutil.rmtree(download_dir)
	except FileNotFoundError:
		pass


def delete_from_disk(disk, remotepath, client_filename, prompt=False):
	delete_remote_file(disk, remotepath, client_filename)

	if prompt:
		print('Deleted %s from disk %s' % (client_filename, disk))


def delete(conn, partition_power, disks):
	client_username = customized_recv(conn).decode('utf-8')
	client_filename = customized_recv(conn).decode('utf-8')

	global maindict

	if client_username not in maindict:
		print('User %s not found' % client_username)
		customized_send(conn, b'failuser')
		return

	elif client_filename not in maindict[client_username]:
		print('File %s not found for User %s' % (client_filename, client_username))
		customized_send(conn, b'failfile')
		return

	partition = get_partition(client_username, client_filename, partition_power)
	disk, backup_disk = get_disk(partition, partition_power, disks)
	remotepath = '/tmp/' + USERNAME + '/' + client_username
	remotebackuppath = '/tmp/' + USERNAME + '/backup/' + client_username

	delete_from_disk(disk, remotepath, client_filename, True)
	threading.Thread(target=delete_from_disk, args=(backup_disk, remotebackuppath, client_filename,)).start()

	customized_send(conn, b'success')


def list_from_disk(disk, client_username):

	HOST = disk
	COMMAND= 'ls -lrt /tmp/%s/%s' % (USERNAME, client_username)

	ssh = subprocess.Popen(["ssh", "%s" % HOST, COMMAND],
							shell=False,
							stdout=subprocess.PIPE,
							stderr=subprocess.PIPE)
	result = ssh.stdout.readlines()

	retval = ('%s (%s)\n' % (disk, socket.gethostbyaddr(disk)[0])).encode('utf-8')

	for i in result:
		retval += i


	if len(result) == 0:
		retval += b'total 0\n'

	retval += b'\n'
	print(retval.decode('utf-8'))
	return retval


def list(conn, disks):
	client_username = customized_recv(conn).decode('utf-8')

	global maindict

	if client_username not in maindict:
		print('User %s not found' % client_username)
		customized_send(conn, b'fail')
		return

	customized_send(conn, b'success')
	retval = b'\n'

	for disk in disks:
		retval += list_from_disk(disk, client_username)

	customized_send(conn, retval)



def main():

	if not validate_command_args():
		return

	try:
		partition_power = int(sys.argv[1])
	except:
		print('Invalid command format. Partition power must be an integer')

	disks = sys.argv[2:]

	if not validate_disk_addresses(disks):
		return

	sock = create_socket()

	for disk in disks:
		create_remote_dir(disk, '/tmp/' + USERNAME)
		delete_remote_dir(disk, '/tmp/' + USERNAME)

	upload_dir = './server-uploads/'
	download_dir = './server-downloads/'

	try:
		shutil.rmtree(upload_dir)
	except FileNotFoundError:
		pass

	try:
		shutil.rmtree(download_dir)
	except FileNotFoundError:
		pass

	while True:
		try:
			conn, addr = sock.accept()

			try:
				client_command = customized_recv(conn).decode('utf-8')
			except TypeError:
				continue

			if client_command == 'upload':
				upload(conn, partition_power, disks)
			elif client_command == 'download':
				download(conn, partition_power, disks)
			elif client_command == 'delete':
				delete(conn, partition_power, disks)
			elif client_command == 'list':
				list(conn, disks)
		
		except KeyboardInterrupt:
			break

	sock.close()


main()