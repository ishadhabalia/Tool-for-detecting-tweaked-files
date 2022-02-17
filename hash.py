import glob, os
import hashlib
import json
import argparse
import sys
import time
import datetime
from xmlrpc.client import boolean
from os import popen

def parse_args():
	#Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--generate", help="Generates the hashdump file for the selected directory.",action="store_true")
    parser.add_argument("-c", "--check", help="Checks for file tampering using the hashdump file.",action="store_true")
    parser.add_argument("-p", "--path", help="Directory path for generation/checking. Example: -p /root/username/abc/impDir/")
    return parser



def sha256(fname):
	hash_md5 = hashlib.sha256()
	with open(fname, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()


def hashGenerator(filePaths, fileIDs, rootPath):
	data = {}
	for (filename, fileID) in zip(filePaths, fileIDs):
		hashdump = sha256(filename)
		data[fileID] = [hashdump, filename]
	return data

def filepathScan(directory):
    filePaths = []  # List which will store all of the full filepaths.
    # walk the directory tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            path = os.path.join(root, filename)
            filePaths.append(path) 
    return filePaths 

def generate(dumpfile,path):
	if path[-1] != "/":
		path += "/"
	filePaths = filepathScan(path)
	fileIDs=[]
	for path in filePaths:
		id = popen(fr"fsutil file queryfileid {path}").read()
		# print(len(id))
		id=id[12:45]
		# print(id)
		fileIDs.append(id)
	print(fileIDs)
	hashdata = hashGenerator(filePaths, fileIDs, path)
	with open(dumpfile, 'w') as fp:
	    json.dump(hashdata, fp)
	
def check(dumpfile,path):
	if path[-1] != "/":
		path += "/"
	filePaths = filepathScan(path)
	flag=False

	fileIDs=[]
	for path in filePaths:
		id = popen(fr"fsutil file queryfileid {path}").read()
		id=id[12:45]
		fileIDs.append(id)
	hashdata = hashGenerator(filePaths, fileIDs, path)
	with open(dumpfile, 'r') as fp:
		verificationData = json.load(fp)
	for key in hashdata:
		filename = os.path.basename(hashdata[key][1])
		file=os.path.abspath(key)
		if key in verificationData and filename!="hashdump.json" :
			if hashdata[key][0] != verificationData[key][0]:
				print("\n"+filename + " is tampered.")
				# print(hashdata[key][1])
				mtime=time.ctime(os.path.getmtime(str(hashdata[key][1])))
				mtime=datetime.datetime.strptime(mtime, "%a %b %d %H:%M:%S %Y")
				print("Last tampered: %s" % mtime.strftime('%Y-%m-%d %H:%M:%S'))
				flag=True 
			elif hashdata[key][1] != verificationData[key][1]:
				orgfilename = os.path.basename(verificationData[key][1])
				# print(orgfilename)
				print("\n"+str(orgfilename)+" has been renamed to "+str(filename))
				flag=True
		elif filename!="hashdump.json":
			print("\n"+str(filename) + " hashdump data not available.")

	for key in verificationData:
		if not key in hashdata:
			print("\n"+str(filename) + " is deleted/unavailable.")
			flag=True
	if(flag==False):
		print("\nNo files have been tampered or deleted")

if __name__ == "__main__":
	parse = parse_args()
	args = parse.parse_args()
	if args.path:
		dump=args.path+"hashdump.json"
		if not os.path.isdir(args.path):
			print("Invalid Input. path should be a directory, not a file.")
			sys.exit(1)
		if args.generate:
			generate(dump, args.path)
			print("Hash dump file has been generated in the same directory.")
		elif args.check:
			if(os.path.exists(dump)):
				check(dump, args.path)
			else:
				print("Hash dump file does not exist. Generate it first using the following options.")
				parse.print_help()
				sys.exit(1)
		else:            
			print("Invalid Command Line Arguments. \n")
			parse.print_help()
			sys.exit(1)
	else:
		print("Invalid Command Line Arguments. \n")
		parse.print_help()
		sys.exit(1)

