
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
    parser.add_argument("-d", "--dump", help="Path to the hashdump file. Example: -d /root/username/abc/hashdump.json")
    parser.add_argument("-p", "--path", help="Directory path for generation/checking. Example: -p /root/username/abc/impDir/")
    return parser
    


def sha256(fname):
	hash_md5 = hashlib.sha256()
	with open(fname, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()


def hashGenerator(filePaths,rootPath):
	data = {}
	for filename in filePaths:
		hashdump = sha256(filename)
		filenameShort = filename.replace(rootPath,"")
		data[filenameShort] = hashdump	
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
	
	hashdata = hashGenerator(filePaths,path)
	with open(dumpfile, 'w') as fp:
	    json.dump(hashdata, fp)

def check(dumpfile,path):
	if path[-1] != "/":
		path += "/"
	filePaths = filepathScan(path)
	flag=False
	hashdata = hashGenerator(filePaths,path)
	with open(dumpfile, 'r') as fp:
		verificationData = json.load(fp)
	for key in hashdata:
		file=os.path.abspath(key)
		
		if key in verificationData:
			if hashdata[key] != verificationData[key]:
				print(str(key) + " is tampered.")
				mtime=time.ctime(os.path.getmtime(path+str(key)))
				mtime=datetime.datetime.strptime(mtime, "%a %b %d %H:%M:%S %Y")
				print("Last tampered: %s" % mtime.strftime('%Y-%m-%d %H:%M:%S'))
				flag=True
		else:
			print(str(key) + " hashdump data not available.")
			
	for key in verificationData:
		if not key in hashdata:
			print(str(key) + " is deleted/unavailable.")
			flag=True
	if(flag==False):
		print("No files have been tampered or deleted")



if __name__ == "__main__":
	parse = parse_args()
	args = parse.parse_args()
	if args.dump and args.path:
		if os.path.isdir(args.dump):
			print("Invalid Input. dump should be a file, not a directory.")
			sys.exit(1)
		if not os.path.isdir(args.path):
			print("Invalid Input. path should be a directory, not a file.")
			sys.exit(1)
		
		if args.generate:
			generate(args.dump, args.path)
		elif args.check:
			check(args.dump, args.path)
		else:            
			print("Invalid Command Line Arguments. \n")
			parse.print_help()
			sys.exit(1)
	else:
		print("Invalid Command Line Arguments. \n")
		parse.print_help()
		sys.exit(1)

