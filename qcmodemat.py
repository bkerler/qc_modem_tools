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
import ida_struct
import collections
import logging
from struct import unpack
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def search_ea(sig, segment="", callback=None, start=None, end=None):
    eas=[]
    if segment!="":
        seg = idaapi.get_segm_by_name(segment)
        if not seg:
            return
        if start==None:
            start=seg.startEA
        if end==None:
            end=seg.endEA
        ea, maxea = start, end
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
            ea=get_segm_start(seg)
            maxea=get_segm_end(ea)
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
    sid = ida_struct.add_struc(0, "cmd_ref",0)
    idc.add_struc_member(sid, "name", -1, ida_bytes.off_flag()|ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4)
    idc.add_struc_member(sid, "reserve1", -1, ida_bytes.FF_DWORD, -1, 4)
    idc.add_struc_member(sid, "param", -1, ida_bytes.FF_WORD, -1, 4)
    idc.add_struc_member(sid, "id", -1, ida_bytes.FF_WORD, -1, 4)
    idc.add_struc_member(sid, "reserve2", -1, ida_bytes.FF_DWORD, -1, 4)
    return sid

def create_cmdptr():
    sid = ida_struct.add_struc(0, "cmd_ptr",0)
    idc.add_struc_member(sid, "id", -1, ida_bytes.FF_DWORD, -1, 4)
    idc.add_struc_member(sid, "ptr", -1, ida_bytes.off_flag()|ida_bytes.FF_DATA|ida_bytes.FF_DWORD, -1, 4)
    return sid

references=[]
names=[]

def get_string(addr):
  out = ""
  while True:
    if get_wide_byte(addr) != 0:
      out += chr(get_wide_byte(addr))
    else:
      break
    addr += 1
  return out

def callback2(ea):
    print("Found ref to cmd string at 0x%08X" % ea)
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
startea=res[0]
print("\n\nFound addr to cmd AT!LB at 0x%08X" % ea)
val=search_ea(addr_to_bhex(startea),"",None)
ea=val[0]
while (1):
    ea=callback2(ea)
    if ea==0:
        break
    print(hex(ea))
    ea=search_ea(addr_to_bhex(ea),"",None)[0]

create_cmdref()
sid = ida_struct.get_struc_id("cmd_ref")
if sid == idaapi.BADADDR:
    print("Structure {} does not exist".format(name))

i=0
lastea=0
names={}
firstcmdid=0
for ea in references:
    nameptr=ida_bytes.get_dword(ea)
    cmdid=ida_bytes.get_word(ea+0xA)
    if firstcmdid==0:
        firstcmdid=cmdid
    name=get_string(nameptr)
    names[cmdid]=name
    ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES,0x10)
    ida_bytes.create_struct(ea, 0x10, sid)
    print(f"EA:{hex(ea)} Name:{name} Cmdid:{hex(cmdid)}")
    #idc.set_cmt(ea, str(i),0)
    i+=1
    lastea=ea

create_cmdptr()
sid = ida_struct.get_struc_id("cmd_ptr")
ssize = ida_struct.get_struc_size(sid)
eas=search_ea("FC 3A 00 00","",None,startea-0x3000,lastea)
sea=None
for ea in eas:
    cmdid=ida_bytes.get_dword(ea+8)
    if cmdid==0x3AFD:
        sea=ea
        break
print(f"Found cmdtable at: {hex(ea)}")

if sea!=None:
    offsets=[]
    badoffsets={}
    x=0
    z=0
    for i in range(0,0x20000,ssize):
        vea=ea+i
        ida_bytes.del_items(vea, ida_bytes.DELIT_DELNAMES,ssize)
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
    for i in range(0,0x20000,ssize):
        vea=ea+i
        idv=ida_bytes.get_dword(vea)
        if idv==0x660066:
            break
        cmdid=ida_bytes.get_dword(vea)
        eaaddr=ida_bytes.get_dword(vea+4)
        ida_bytes.del_items(eaaddr, ida_bytes.DELIT_DELNAMES, ssize)
        ida_funcs.add_func(eaaddr)
        info="%08X" % eaaddr
    
        if x<len(names):
            if eaaddr in badoffsets:
                name=badoffsets[eaaddr]
            else:
                if cmdid in names:
                    name="atcmd_"+names[cmdid][1:]
                    print(info+" AT"+names[cmdid]+":"+str(x))
                    idc.set_name(eaaddr, name, idc.SN_NOWARN)
    
        ida_bytes.del_items(vea, ida_bytes.DELIT_DELNAMES,ssize)
        ida_bytes.create_struct(vea, ssize, sid)
        if cmdid in names:
            idc.set_cmt(vea, "AT"+names[cmdid],0)
        x+=1
