#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2019 under MIT license
# If you use my code, make sure you refer to my name
# If you want to use in a commercial product, ask me before integrating it

# Qualcomm Modem Loader (c) B. Kerler 2019

from PyQt5 import QtCore, QtGui, QtWidgets
import idaapi
from idaapi import *
from idautils import *
from idc import *
import idc
import ida_segment
import zlib
import os
import idautils
import ida_hexrays
import ida_bytes
import ida_loader
import collections
import logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def search_ea(sig, segment="", callback=None):
    eas=[]
    if segment!="":
        seg = idaapi.get_segm_by_name(segment)
        if not seg:
            return
        ea, maxea = seg.startEA, seg.endEA
        count = 0
        while ea != idaapi.BADADDR:
            ea = idaapi.find_binary(ea, maxea, sig, 16, idaapi.SEARCH_DOWN)
            if ea != idaapi.BADADDR:
                count = count + 1
                if callback!=None:
                    callback(ea)
                else:
                    eas.append(ea)
                ea += 2
    else:
        for seg in Segments():
            ea=SegStart(seg)
            maxea=SegEnd(ea)
            count = 0
            while ea != idaapi.BADADDR:
                ea = idaapi.find_binary(ea, maxea, sig, 16, idaapi.SEARCH_DOWN)
                if ea != idaapi.BADADDR:
                    count = count + 1
                    if callback!=None:
                        callback(ea)
                    else:
                        eas.append(ea)
                    ea += 2
    return eas 

def generatefunc(ea,name):
    idc.MakeCode(ea-1)
    idc.MakeFunction(ea-1)
    idc.MakeNameEx(ea-1, name, idc.SN_NOWARN)
    logger.debug("Rename %x:%s" % (ea,name))

def addr_to_bhex(ea):
    ea=hex(ea)[2:]
    return ea[6:8]+" "+ea[4:6]+" "+ea[2:4]+" "+ea[0:2]

def create_cmdref():
    sid = ida_struct.add_struc(0, "cmd_ref")
    idc.AddStrucMember(sid, "name", -1, offflag()|FF_DATA|FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "id", -1, idc.FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "id2", -1, idc.FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "id3", -1, idc.FF_DWRD, -1, 4)
    return sid

def create_cmdptr():
    sid = ida_struct.add_struc(0, "cmd_ptr")
    idc.AddStrucMember(sid, "id", -1, idc.FF_DWRD, -1, 4)
    idc.AddStrucMember(sid, "ptr", -1, offflag()|FF_DATA|FF_DWRD, -1, 4)
    return sid

references=[]
names=[]

def get_string(addr):
  out = ""
  while True:
    if Byte(addr) != 0:
      out += chr(Byte(addr))
    else:
      break
    addr += 1
  return out

def callback2(ea):
    print("Found ref to cmd string at %08X" % ea)
    ref=ida_bytes.get_dword(ea)&0xFFFF0000
    for i in range(0,0x1000*4,0x10):
        value=ida_bytes.get_dword(ea+i)
        if value&0xFFFF0000 != ref:
            valbyte=ida_bytes.get_byte(ea+i)
            if valbyte==ord('$') or valbyte==ord('!') or valbyte==ord('+') or valbyte==ord('^') or valbyte==ord('*'):
                return ea+i
            break
        logger.debug("cmd_ref:%x" % (ea+i))
        references.append(ea+i)
    return 0

res=search_ea("21 4C 42 00", "", None)
ea=res[0]
print("\n\nFound addr to cmd AT!LB at %08X" % ea)
val=search_ea(addr_to_bhex(ea),"",None)
ea=val[0]
while (1):
    ea=callback2(ea)
    if ea==0:
        break
    ea=search_ea(addr_to_bhex(ea),"",None)[0]

create_cmdref()
sid = idc.GetStrucIdByName("cmd_ref")
i=0
names=[]
for ea in references:
    nameptr=ida_bytes.get_dword(ea)
    name=get_string(nameptr)
    names.append(name)
    idc.MakeUnknown(ea, 0x10, idc.DOUNK_DELNAMES)
    idaapi.doStruct(ea, 0x10, sid)
    MakeComm(ea, str(i))
    i+=1

create_cmdptr()
sid = idc.GetStrucIdByName("cmd_ptr")
ea=search_ea("00 00 FC 3A 00 00","",None)[1]+2
offsets=[]
badoffsets={}
x=0
z=0
for i in range(0,0x20000,0x8):
    vea=ea+i
    MakeUnkn(vea, 0x8)
    idv=ida_bytes.get_dword(vea)
    if idv==0x660066:
        break
    notimpladdr=ida_bytes.get_dword(vea+4)
    if notimpladdr in offsets:
        if not notimpladdr in badoffsets:
            badoffsets[notimpladdr]="at_not_implemented_"+str(z)
            z+=1
    offsets.append(notimpladdr)

tbl={}
x=0
for i in range(0,0x20000,0x8):
    vea=ea+i
    idv=ida_bytes.get_dword(vea)
    if idv==0x660066:
        break
    eaaddr=ida_bytes.get_dword(vea+4)
    idc.MakeUnknown(eaaddr, 0x8, idc.DOUNK_DELNAMES)
    idc.MakeFunction(eaaddr)

    if x<len(names):
        if eaaddr in badoffsets:
            name=badoffsets[eaaddr]
        else:
            name="atcmd_"+names[x][1:]
            #print(info+" AT"+realname+":"+str(x))
        idc.MakeNameEx(eaaddr, name, idc.SN_NOWARN)

    info="%08X" % eaaddr
    MakeUnkn(vea, 0x8)
    idaapi.doStruct(vea, 0x8, sid)
    MakeComm(vea, "AT"+names[x]+":"+str(x))
    x+=1