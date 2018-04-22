import socket
import struct
import sys
import os

COMMANDS_LIST = ['upload', 'download', 'delete', 'list']

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


def customized_send(sock, data):
    length = len(data)
    sock.sendall(struct.pack('!I', length))
    sock.sendall(data)


def exceptions_log(case, arg=''):

	if case == 1:
		print('Oops! That is an invalid command. Type `help` for instructions.')
	elif case == 2:
		print('Oops! Invalid command format. Type `help` for instructions.')
	elif case == 3:
		print('Processing your request for %s. (Rest of the arguments would be ignored)' % arg)


def operation_upload(username, filename, sock):
	
	try:
		with open(filename, 'rb') as f:
			pass
	except FileNotFoundError:
		print('File %s does not exist in the current directory' % filename)
		return

	customized_send(sock, 'upload'.encode('utf-8'))
	customized_send(sock, username.encode('utf-8'))
	customized_send(sock, filename.encode('utf-8'))

	with open(filename, 'rb') as f:
		customized_send(sock, f.read())
	
	response = customized_recv(sock)

	if response == b'File already exists. Would you like to overwrite? (Y/n)':
		print(response.decode('utf-8'))
		x = ''

		while x == '':
			x = input('> (Y/n)? ')

		customized_send(sock, x.encode('utf-8'))

		if 'y' in x or 'Y' in x:
			response = customized_recv(sock)
		else:
			return

	remotepath = customized_recv(sock).decode('utf-8')
	hostname = customized_recv(sock).decode('utf-8')

	print('Upload operation completed. File has been stored in %s (%s) at %s' % (response.decode('utf-8'), hostname, remotepath))


def operation_download(username, filename, sock):
	customized_send(sock, 'download'.encode('utf-8'))
	customized_send(sock, username.encode('utf-8'))
	customized_send(sock, filename.encode('utf-8'))
	
	client_filedata = customized_recv(sock)

	if client_filedata == b'failuser':
		print('The requested user %s does not exist' % (username))
		return
	elif client_filedata == b'failfile':
		print('The requested file %s does not exist for user %s' % (filename, username))
		return

	download_dir = './client-downloads/'
	download_subdir = './client-downloads/%s/' % username

	if not os.path.exists(download_dir):
		os.makedirs(download_dir)

	if not os.path.exists(download_subdir):
		os.makedirs(download_subdir)

	localpath = download_subdir + filename

	with open(localpath, 'wb+') as f:
		f.write(client_filedata)

	print('Download operation completed. File has been stored in %s' % download_subdir)
	return


def operation_delete(username, filename, sock):
	customized_send(sock, 'delete'.encode('utf-8'))
	customized_send(sock, username.encode('utf-8'))
	customized_send(sock, filename.encode('utf-8'))

	response = customized_recv(sock)

	if response == b'failuser':
		print('The requested user %s does not exist' % (username))
		return
	elif response == b'failfile':
		print('The requested file %s does not exist for user %s' % (filename, username))
		return

	print('Delete operation completed.')


def operation_list(username, sock):
	customized_send(sock, 'list'.encode('utf-8'))
	customized_send(sock, username.encode('utf-8'))

	response = customized_recv(sock)

	if response == b'fail':
		print('The requested user %s does not exist' % (username))
		return
	
	response = customized_recv(sock)
	print(response.decode('utf-8'))


def evaluate_uname(username):

	if '/' in username:
		exceptions_log(2)
		return True

	return False


def evaluate_fpath(filepath):

	if '/' not in filepath:
		exceptions_log(2)
		return True

	if filepath[0] == '/' or filepath[-1] == '/':
		exceptions_log(2)
		return True

	filepath = filepath.split('/')
	if len(filepath) > 2:
		exceptions_log(2)
		return True

	return False


def process(query, HOST, PORT):

	query = query.split(' ')
	command = query[0]
	args = len(query)

	if command == 'help':
		print('USAGE:')
		print('\t1. upload user/object')
		print('\t2. download user/object')
		print('\t3. delete user/object')
		print('\t4. list user')
		print('\t5. exit')
		return True


	if command == 'exit':
		return False
	
	elif command == '':
		return True
	
	else:

		if command not in COMMANDS_LIST:
			exceptions_log(1)
			return True

		if args == 1:
			exceptions_log(2)
			return True

		####################
		#                  #
		#     EVALUATE     #
		#                  #
		####################

		if command == 'list':
			if evaluate_uname(query[1]):
				return True

		else:
			if evaluate_fpath(query[1]):
				return True

		username = query[1].split('/')[0]
		filename = query[1].split('/')[-1]

		####################
		#                  #
		#    EXTRA ARGS    #
		#                  #
		####################

		if args > 2 and query[2] != '':
			exceptions_log(3, query[1])


		###################
		#                 #
		#       RUN       #
		#                 #
		###################

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((HOST, PORT))

		if command == 'list':
			operation_list(username, sock)

		elif command == 'upload':
			operation_upload(username, filename, sock)
		
		elif command == 'download':
			operation_download(username, filename, sock)
		
		elif command == 'delete':
			operation_delete(username, filename, sock)

		sock.close()

	return True


def main():

	if len(sys.argv) < 3:
		print('Invalid command format\nUsage: python client.py 129.210.16.80 9999 (or) python client.py linux60810.dc.engr.scu.edu 9999')
		return

	try:
		HOST = sys.argv[1]
		PORT = int(sys.argv[2])
	except:
		print('Invalid command format. Please provide a valid IP/hostname and Port number of the server.')

	try:

		if HOST[:5] == 'linux':
			HOST = socket.gethostbyname(HOST)

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((HOST, PORT))
		sock.close()
	except:
		print('Unable to connect to the server. Kindly ensure that the server IP/hostname and Port number is accurate.')
		return
	
	print('> Welcome! Type `help` for instructions')

	flag = True
	
	while flag:
		try:
			query = input('> ')
			flag = process(query, HOST, PORT)
		except KeyboardInterrupt:
			return
		except ConnectionRefusedError:
			print('Server seems to be down at the moment. Please try again later.')
			return
		except:
			continue


main()