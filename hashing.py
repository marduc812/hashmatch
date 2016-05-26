import hashlib
import os


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def sha1file(fname):
	import hashlib
	BLOCKSIZE = 65536
	hasher = hashlib.sha1()
	with open(fname, 'rb') as afile:
		buf = afile.read(BLOCKSIZE)
		while len(buf) > 0:
			hasher.update(buf)
			buf = afile.read(BLOCKSIZE)
	return hasher.hexdigest()

def sha256file(fname):
	import hashlib
	BLOCKSIZE = 65536
	hasher = hashlib.sha256()
	with open(fname, 'rb') as afile:
		buf = afile.read(BLOCKSIZE)
		while len(buf) > 0:
			hasher.update(buf)
			buf = afile.read(BLOCKSIZE)
	return hasher.hexdigest()


filepath = raw_input("Path prwtou arxeiou: ")
#filepath2 = raw_input("Path deuterou arxeiou: ")

print (80 * "*")
#print os.path.basename(filepath)
#print (80 * "*")
sha2a = sha256file(filepath)
sha1a = sha1file(filepath)
md5a = md5(filepath)
print ("\n SHA-1: " + sha1a)
print ("\n SHA-2: " + sha2a)
print ("\n MD5: " + md5a)
print (80 * "*")


