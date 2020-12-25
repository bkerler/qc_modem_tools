#!/usr/bin/env python3
from struct import unpack
import os,sys

def parse_ubihdr(rf):
    curpos=rf.tell()
    magic = rf.read(4)
    if magic == b"UBI#":
        rf.seek(curpos+0x10)
        hdrsize = unpack(">I", rf.read(4))[0]
        blksize = unpack(">I", rf.read(4))[0]
        data = unpack(">I", rf.read(4))[0]
        rf.seek(curpos+0x3C)
        crc = unpack(">I", rf.read(4))[0]
        rf.seek(curpos)
        return [hdrsize,blksize,data,crc]

def parse_ubihdr2(rf):
    curpos=rf.tell()
    magic = rf.read(4)
    if magic == b"UBI!":
        flag = unpack("<I", rf.read(4))[0]
        rf.seek(curpos+0xC)
        blk = unpack(">I", rf.read(4))[0]
        rf.seek(curpos + 0x3C)
        crc = unpack(">I", rf.read(4))[0]
        rf.seek(curpos)
        return [flag,blk,crc]

def main():
    if len(sys.argv)<2:
        print("Usage: ubisqsh.py <filename>")
        sys.exit()
    filename=sys.argv[1]
    with open(filename,'rb') as rf:
        with open(filename+".out","wb") as wf:
            pos=0
            while pos<os.stat(filename).st_size:
                hdrsize,blksize,data,crc=parse_ubihdr(rf)
                rf.seek(pos+hdrsize)
                flag,blk,crc=parse_ubihdr2(rf)
                if flag&0xF000000==0:
                    print(f"Blk %d Flag %x WR" %(blk,flag))
                    rf.seek(pos + blksize)
                    rdata=rf.read(0x40000-blksize)
                    wf.write(rdata)
                else:
                    print(f"Blk %d Flag %x SK" %(blk,flag))
                    rf.seek(pos+0x40000)
                pos+=0x40000
    print("Done.")

if __name__=="__main__":
    main()