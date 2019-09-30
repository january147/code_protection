#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Mon Sep 30 15:18:53 2019
# Author: January
from cryptography.fernet import Fernet
import sys
import os
import random

usage='''USAGE1:
code_protect generate_key_file [<key_file>]
USAGE2:
code_protect encrypt <py_script> [<key_file>]
USAGE2:
code_protect run <encrpyted_py_script> [<key_file>]
NOTE: This program will use filename 'key_file' to search current directory for key_file if the <key_file> argument is not specified. 
'''
tmp_file = 'tmp.run'

def main():
    if len(sys.argv) < 2:
        print(usage)
        exit(1)
    
    if sys.argv[1] == 'generate_key_file':
        if len(sys.argv) < 3:
            filename = 'key_file'
        else:
            filename = sys.argv[2]
        if os.path.exists(filename):
            decision = input("%s exists, overwrite it?(y or n):"%(filename))
            if decision != 'y':
                print('aborted')
                exit(0)
        key = Fernet.generate_key()
        with open(filename, 'wb') as f:
            f.write(key)
        print('%s generated'%(filename))

        
    elif sys.argv[1] == 'encrypt':
        if len(sys.argv) < 3:
            print(usage)
            exit(1)
        if len(sys.argv) >= 4:
            key_file = sys.argv[3]
        else:
            key_file = 'key_file'
        filename = sys.argv[2]
        
        new_filename = filename + '.ept'
        with open(key_file,'rb') as k:
            key = k.read(1024)
        with open(filename, 'rb') as f:
            code = f.read(4096*1024)
        cipher = Fernet(key)
        token = cipher.encrypt(code)
        with open(new_filename, 'wb') as nf:
            nf.write(token)
        print('%s generated'%(new_filename))
    elif sys.argv[1] == 'run':
        if len(sys.argv) < 3:
            print(usage)
            exit(1)
        if len(sys.argv) >= 4:
            key_file = sys.argv[3]
        else:
            key_file = 'key_file'
        
        filename = sys.argv[2]
        if filename[-4:-1] != '.ept':
            filename = filename + '.ept'
        if os.path.exists(filename) == False:
            print("no such file")
            exit(1)

        with open(key_file,'rb') as k:
            key = k.read(1024)
        with open(filename, 'rb') as f:
            encrypted_code = f.read(4096*1024)
        cipher = Fernet(key)
        code = cipher.decrypt(encrypted_code)

        with open(tmp_file, 'wb') as f:
             f.write(code)
        pid = os.fork()
        if pid == 0:
            # 子进程
            os.execlp('python3', 'python3', tmp_file)
        else:
            # 父进程
            os.wait()
            os.remove(tmp_file)
    else:
        print("unknown operation "+sys.argv[1])
        exit(1)
        
    
if __name__ == "__main__":
    main()
