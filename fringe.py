#!/usr/bin/env python

import hashlib
import json
import os
import shutil
import sys

def md5(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()

def move_files(src, dest, hash_dict):
    return

def store_dest_hashes(dest):
    return

def check_dest_fs(src, dest):
    # TODO check if .fringe exists
    #      if it does, load it into memory
    #      if it doesn't, call store_dest_hashes to create one
    #      then continue on to move_files once the dictionary is in memory
    return

def cleanup_fs(src):
    hash_dict = {}
    if os.path.isfile(src+"/fringe_backup/.fringe"):
        pass
    else:
        backup_dir = src+"/fringe_backup"
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        for root, dirs, files in os.walk(src):
            for f in files:
                if '.' in f and not f.startswith('.') and not root.startswith(backup_dir):
                    f_path = root+"/"+f
                    rows,columns = os.popen('stty size', 'r').read().split()
                    rows = int(rows)
                    columns = int(columns)
                    sys.stdout.write('\r')
                    sys.stdout.write(' ' * columns)
                    sys.stdout.write('\r')
                    sys.stdout.write('processing {}'.format(f_path[:columns-12]))
                    sys.stdout.flush()

                    ext = f.split('.')[-1]
                    filename = f.split('/')[-1]
                    filenames = f.split('/')
                    dot_folder = False
                    for dir in filenames:
                        if dir.startswith("."):
                            dot_folder = True
                    if not dot_folder:
                        if not os.path.exists(backup_dir+"/"+ext):
                            os.makedirs(backup_dir+"/"+ext)
                        f_hash = md5(root+"/"+f)
                        if not f_hash in hash_dict:
                            hash_dict['f_hash'] = [filename]
                            shutil.move(f_path, backup_dir+"/"+ext+"/"+filename)
                        else:
                            if filename in hash_dict['f_hash']:
                                # same file hash and filename exist in more than one place
                                with open(src+"/fringe_backup/.fringedups", 'a') as fo:
                                    fo.write(f_path+", "+f_hash+"\n")
                            else:
                                # same file hash but different filename exist in more than one place
                                hash_dict['f_hash'].append(filename)
                                with open(src+"/fringe_backup/.fringedups", 'a') as fo:
                                    fo.write(f_path+", "+f_hash+"\n")
        with open(src+"/fringe_backup/.fringe", 'w') as f:
            json.dump(hash_dict, f)
    return

if __name__ == "__main__":
    if len(sys.argv) == 3:
        src = sys.argv[1]
        dest = sys.argv[2]
        check_dest_fs(src, dest)
    elif len(sys.argv) == 2:
        src = sys.argv[1]
        cleanup_fs(src)
    else:
        print "supply src and dest as first two arguments, or supply just a src to cleanup dups"
        sys.exit()
