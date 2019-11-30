#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2019 under MIT license
# If you use my code, make sure you refer to my name
# If you want to use in a commercial product, ask me before integrating it
import os
import sys
from enum import Enum
from struct import unpack, pack
from binascii import unhexlify,hexlify

class elf:
    class memorysegment:
        phy_addr=0
        virt_start_addr=0
        virt_end_addr=0
        file_start_addr=0
        file_end_addr=0


    def __init__(self,indata):
        self.data=indata
        self.header, self.pentry = self.parse()
        self.memorylayout = []
        for entry in self.pentry:
            ms=self.memorysegment()
            ms.phy_addr=entry.phy_addr
            ms.virt_start_addr=entry.virt_addr
            ms.virt_end_addr=entry.virt_addr+entry.seg_mem_len
            ms.file_start_addr=entry.from_file
            ms.file_end_addr=entry.from_file+entry.seg_file_len
            self.memorylayout.append(ms)

    def getfileoffset(self,offset):
        for memsegment in self.memorylayout:
            if offset<=memsegment.virt_end_addr and offset>=memsegment.virt_start_addr:
                return offset-memsegment.virt_start_addr+memsegment.file_start_addr
        return None

    def getvirtaddr(self,fileoffset):
        for memsegment in self.memorylayout:
            if fileoffset<=memsegment.file_end_addr and fileoffset>=memsegment.file_start_addr:
                return memsegment.virt_start_addr+fileoffset-memsegment.file_start_addr
        return None

    def getbaseaddr(self,offset):
        for memsegment in self.memorylayout:
            if offset<=memsegment.virt_end_addr and offset>=memsegment.virt_start_addr:
                return memsegment.virt_start_addr
        return None

    class programentry:
        p_type = 0
        from_file = 0
        virt_addr = 0
        phy_addr = 0
        seg_file_len = 0
        seg_mem_len = 0
        p_flags = 0
        p_align = 0

    def parse_programentry(self,dat):
        pe = self.programentry()
        if self.elfclass==1:
            (pe.p_type,pe.from_file,pe.virt_addr,pe.phy_addr,pe.seg_file_len,pe.seg_mem_len,pe.p_flags,pe.p_align) = unpack("<IIIIIIII",dat)
        elif self.elfclass==2:
            (pe.p_type, pe.p_flags, pe.from_file, pe.virt_addr, pe.phy_addr, pe.seg_file_len, pe.seg_mem_len,pe.p_align) = unpack("<IIQQQQQQ", dat)
        return pe

    def parse(self):
        self.elfclass=self.data[4]
        if self.elfclass==1: #32Bit
            start=0x28
        elif self.elfclass==2: #64Bit
            start=0x34
        elfheadersize, programheaderentrysize, programheaderentrycount = unpack("<HHH", self.data[start:start + 3 * 2])
        programheadersize = programheaderentrysize * programheaderentrycount
        header = self.data[0:elfheadersize+programheadersize]
        pentry=[]
        for i in range(0,programheaderentrycount):
            start=elfheadersize+(i*programheaderentrysize)
            end=start+programheaderentrysize
            pentry.append(self.parse_programentry(self.data[start:end]))

        return [header,pentry]

class hexagon():
    dregister={
        0b0000:"R0",
        0b0001:"R1",
        0b0010:"R2",
        0b0011:"R3",
        0b0100:"R4",
        0b0101:"R5",
        0b0110:"R6",
        0b0111:"R7",
        0b1000:"R16",
        0b1001:"R17",
        0b1010:"R18",
        0b1011:"R19",
        0b1100:"R20",
        0b1101:"R21",
        0b1110:"R22",
        0b1111:"R23"
    }

    sregister={
        0:"SGP0",
        1:"SGP1",
        2:"STID",
        3:"ELR",
        4:"BADVA0",
        5:"BADVA1",
        6:"SSR",
        7:"CCR",
        8:"HTID",
        9:"BADVA",
        10:"IMASK",
        16:"EVB",
        17:"MODECTL",
        18:"SYSCFG",
        19:"-",
        20:"IPEND",
        21:"VID",
        22:"IAD",
        23:"-",
        24:"IEL",
        25:"-",
        26:"IAHL",
        27:"CFGBASE",
        28:"DIAG",
        29:"REV",
        30:"PCYCLELO",
        31:"PCYCLEHI",
        32:"ISDBST",
        33:"ISDBCFG0",
        34:"ISDBCFG1",
        35:"-",
        36:"BRKPTPC0",
        37:"BRKPTCFG0",
        38:"BRKPTPC1",
        39:"BRKPTCFG1",
        40:"ISDBMBXIN",
        41:"ISDBMBXOUT",
        42:"ISDBGPR",
        48:"PMUCNT0",
        49:"PMUCNT1",
        50:"PMUCNT2",
        51:"PMUCNT3",
        52:"PMUEVTCFG",
        53:"PMUCFG"
    }

    cregister={
        0b0000:"SA0",
        0b0001:"LC0",
        0b0010:"SA1",
        0b0011:"LC1",
        0b0100:"P3:0",
        0b0101:"Reserved",
        0b0110:"M0",
        0b0111:"R1",
        0b1000:"USR",
        0b1001:"PC",
        0b1010:"UGP",
        0b1011:"GP",
        0b1100:"CS0",
        0b1101:"CS1",
        0b1110:"UPCYCLELO",
        0b1111:"UPCYCLEHI"
    }

    ccregister={
        0:"C1:0",
        2:"C3:2",
        4:"C5:4",
        6:"C7:6",
        8:"C9:8",
        10:"C11:10",
        12:"C13:12",
        14:"C15:14",
        16:"C17:16",
        18:"C19:18",
        20:"C21:20",
        22:"C23:22",
        24:"C25:24",
        26:"C27:26",
        28:"C29:28",
        30:"C31:30",
    }


    mregister={
        0b00000:"R1:0",
        0b00010:"R3:2",
        0b00100:"R5:4",
        0b00110:"R7:6",
        0b01000:"R9:8",
        0b01010:"R11:10",
        0b01100:"R13:12",
        0b01110:"R15:14",
        0b10000:"R17:16",
        0b10010:"R19:18",
        0b10100:"R21:20",
        0b10110:"R23:22",
        0b11000:"R25:24",
        0b11010:"R27:26",
        0b11100:"R29:28"
    }

    drregister={
        0b000:"R1:0",
        0b001:"R3:2",
        0b010:"R5:4",
        0b011:"R7:6",
        0b100:"R17:16",
        0b101:"R19:18",
        0b110:"R21:20",
        0b111:"R23:22"
    }

    def __init__(self, mode="hex"):
        self.mode = mode
        self.aregister=[]
        self.offset = 0
        self.immext=0

    def pushreg(self, reg, mode=1):
        if len(self.aregister)>4:
            self.aregister.pop(0)
        self.aregister.append([reg,mode])

    def aheadreg(self, ahead):
        ahead=ahead>>1
        if (len(self.aregister)-ahead)>0:
            reg,mode=self.aregister[-ahead]
            if mode==1:
                return self.toreg(reg)
            elif mode==2:
                return self.torreg(reg)
            elif mode==3:
                return self.topreg(reg)
            elif mode==4:
                return self.togreg(reg)
            elif mode==4:
                return self.togrreg(reg)
            elif mode==5:
                return self.tosreg(reg)
            elif mode==6:
                return self.tosrreg(reg)
            elif mode==7:
                return self.toduplexreg(reg)
            elif mode==8:
                return self.toduplexrreg(reg)
        return "Error"

    def torreg(self,data):
        return self.tomultireg(data) #64Bit register

    def togrreg(self,data):
        return self.togreg(data) #64Bit register

    def tovreg(self,data):
        return self.toreg(data) #Vector register

    def tovrreg(self,data):
        return self.toreg(data) #Vector register

    def toreg(self, data):
        if data==29:
            return "SP"
        elif data==30:
            return "FP"
        elif data==31:
            return "LR"
        return "R"+str(data)

    def togreg(self, data):
        if data==0:
            return "G0"
        elif data==1:
            return "G1"
        elif data==2:
            return "G2"
        elif data==3:
            return "G3"
        elif data==16:
            return "ISDBMBXIN"
        elif data==17:
            return "ISDBMBXOUT"
        elif data==24:
            return "GPCYCLELO"
        elif data==25:
            return "GPCYCLEHI"
        elif data==26:
            return "GPMUCNT0"
        elif data==27:
            return "GPMUCNT1"
        elif data==28:
            return "GPMUCNT2"
        elif data==29:
            return "GPMUCNT3"
        else:
            return "Reserved"

    def topreg(self, data):
        if data==29:
            return "SP"
        elif data==30:
            return "FP"
        elif data==31:
            return "LR"
        return "P"+str(data)

    def tosrreg(self, data):
        return self.tosreg(data)

    def tosreg(self,data):
        if data in self.sregister:
            return self.sregister[data]
        else:
            return "Reserved"

    def tomultireg(self, data):
        if data in self.mregister:
            return self.mregister[data]

    def toduplexreg(self, data):
        if data in self.dregister:
            return self.dregister[data]

    def tocreg(self, data):
        if data in self.cregister:
            return self.cregister[data]

    def toccreg(self, data):
        if data in self.ccregister:
            return self.ccregister[data]

    def toduplexrreg(self, data):
        if data in self.drregister:
            return self.drregister[data]

    def cstr(self, data):
        if self.mode=="hex":
            if data<0:
                return "-"+hex(-data)
            return hex(data)
        return str(data)

    def apply_ext(self,data):
        if self.immext!=0:
            if self.mode == "hex":
                data=self.immext+(int(data,16)&0x3F)
            else:
                data = self.immext + (int(data, 10)&0x3F)
            self.immext=0
            return self.cstr(data)
        return data

    def tou(self,data,bit,shift=0,offset=False):
        max=pow(2,bit)-1
        v=(data & max)<<shift
        if not offset:
            return self.cstr(v)
        else:
            return self.cstr(self.offset+v)

    def tos(self,data,bit,shift=0,offset=False):
        max=pow(2,bit-1)-1
        data=data<<shift
        v=-(data & max+1) | (data & max)
        if not offset:
            return self.cstr(v)
        else:
            return self.cstr(self.offset+v)

    def tom(self,data,bit,shift=0):
        max=pow(2,bit-1)-1
        val=-(data & max+1) | (data & max)
        return self.cstr(val<<shift)

    '''
    def tou64(self, data):
        return self.cstr(data&0xFFFFFFFFFFFFFFFF)

    def tos64(self, data):
        return self.cstr(-(data & 0x8000000000000000) | (data & 0x7fffffffffffffff))

    def tou32(self, data):
        return self.cstr(data&0xFFFFFFFF)

    def tos32(self, data):
        return self.cstr(-(data & 0x80000000) | (data & 0x7fffffff))

    def tou16(self, data):
        return self.cstr(data&0xFFFF)

    def tos16(self, data):
        v=-(data & 0x8000) | (data & 0x7fff)
        return self.cstr(v)

    def tou8(self, data):
        return self.cstr(data&0xFF)

    def tos8(self, data):
        return self.cstr(-(data & 0x80) | (data & 0x7f))
    '''

    iclasses={
        #Table 10-6
        0b0000: "Constant extender", #Section 10.10,
        0b0001: "J",
        0b0010: "J",
        0b0011: "LD,ST",
        0b0100: "LD,ST",
        0b0101: "J",
        0b0110: "CR",
        0b0111: "ALU32",
        0b1000: "XTYPE",
        0b1001: "LD",
        0b1010: "ST",
        0b1011: "ALU32",
        0b1100: "XTYPE",
        0b1101: "XTYPE",
        0b1110: "XTYPE",
        0b1111: "ALU32"
    }

    def alu32(self, iclass,dword):
        if iclass == 0b0111:
            d5 = dword & 0x1F
            i = (((dword >> 21) & 0x1) << 8) + (dword >> 5) & 0x1FF
            s5 = (dword >> 16) & 0x1F
            MajOp = (dword >> 24) & 7
            MinOp = (dword >> 21) & 7

            Rs = (dword >> 27) & 1  # No Rs read
            C = (dword >> 13) & 1  # Conditional

            if MajOp == 0b000:
                if Rs == 0:
                    u2 = (dword >> 8) & 3
                    S = (dword >> 11) & 1  # Predicate sense
                    dn = (dword >> 10) & 1  # Dot-new
                    if MinOp == 0b000:
                        if C == 1 and S == 0 and dn == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}) {self.toreg(d5)}=aslh({self.toreg(s5)})"
                        elif C == 1 and S == 0 and dn == 1:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}.new) {self.toreg(d5)}=aslh({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}) {self.toreg(d5)}=aslh({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 1:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}.new) {self.toreg(d5)}=aslh({self.toreg(s5)})"
                        elif C==0:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=aslh({self.toreg(s5)})"
                    elif MinOp == 0b001:
                        if C == 1 and S == 0 and dn == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}) {self.toreg(d5)}=aslr({self.toreg(s5)})"
                        elif C == 1 and S == 0 and dn == 1:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}.new) {self.toreg(d5)}=aslr({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}) {self.toreg(d5)}=aslr({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 1:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}.new) {self.toreg(d5)}=aslr({self.toreg(s5)})"
                        elif C == 0:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=asrh({self.toreg(s5)})"
                    elif MinOp == 0b011:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}={self.toreg(s5)}"
                    elif MinOp == 0b100:
                        if C == 1 and S == 0 and dn == 0 and Rs == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}) {self.toreg(d5)}=zxtb({self.toreg(s5)})"
                        elif C == 1 and S == 0 and dn == 1 and Rs == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}.new) {self.toreg(d5)}=zxtb({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 0 and Rs == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}) {self.toreg(d5)}=zxtb({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 1 and Rs == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}.new) {self.toreg(d5)}=zxtb({self.toreg(s5)})"
                    elif MinOp == 0b101:
                        if C == 1 and S == 0 and dn == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}) {self.toreg(d5)}=sxtb({self.toreg(s5)})"
                        elif C == 1 and S == 0 and dn == 1:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}.new) {self.toreg(d5)}=sxtb({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}) {self.toreg(d5)}=sxtb({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 1:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}.new) {self.toreg(d5)}=sxtb({self.toreg(s5)})"
                        else:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sxtb({self.toreg(s5)})"
                    elif MinOp == 0b110:
                        if C == 1 and S == 0 and dn == 0 and Rs == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}) {self.toreg(d5)}=zxth({self.toreg(s5)})"
                        elif C == 1 and S == 0 and dn == 1 and Rs == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}.new) {self.toreg(d5)}=zxth({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 0 and Rs == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}) {self.toreg(d5)}=zxth({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 1 and Rs == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}.new) {self.toreg(d5)}=zxth({self.toreg(s5)})"
                        else:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=zxth({self.toreg(s5)})"
                    elif MinOp == 0b111:
                        if C == 1 and S == 0 and dn == 0:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}) {self.toreg(d5)}=sxth({self.toreg(s5)})"
                        elif C == 1 and S == 0 and dn == 1:
                            self.pushreg(d5)
                            return f"if ({self.toreg(u2)}.new) {self.toreg(d5)}=sxth({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 0:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}) {self.toreg(d5)}=sxth({self.toreg(s5)})"
                        elif C == 1 and S == 1 and dn == 1:
                            self.pushreg(d5)
                            return f"if (!{self.toreg(u2)}.new) {self.toreg(d5)}=sxth({self.toreg(s5)})"
                        else:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sxth({self.toreg(s5)})"
                elif Rs==1:
                    i = (((dword >> 22) & 3) << 14) + (((dword >> 16) & 0x1F) << 9) + ((dword >> 5) & 0x1FF)
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=#{self.apply_ext(self.tos(i,16))}"
            elif MajOp == 0b001:
                if MinOp & 1 == 0b1:
                    i = (((dword >> 22) & 3) << 14) + (dword & 0x3FFF)
                    x = dword >> 16 & 0x1F
                    self.pushreg(x)
                    return f"{self.toreg(x)}.L=#{self.tou(i,16)}"
            elif MajOp == 0b010:
                if MinOp & 1 == 0b1:
                    i = (((dword >> 22) & 3) << 14) + (dword & 0x3FFF)
                    x = dword >> 16 & 0x1F
                    self.pushreg(x)
                    return f"{self.toreg(x)}.H=#{self.tou(i,16)}"
            elif MajOp == 0b011:
                i = (dword >> 5) & 0xFF
                if (MinOp & 3) == 0b00:
                    self.pushreg(d5,2)
                    return f"{self.torreg(d5)}=combine({self.toreg(s5)},#{self.apply_ext(self.tos(i,8))})"
                elif (MinOp & 3) == 0b01:
                    self.pushreg(d5,2)
                    return f"{self.torreg(d5)}=combine(#{self.apply_ext(self.tos(i,8))},{self.toreg(s5)})"
                elif (MinOp & 3) == 0b10 and (dword >> 13) & 1 == 1 and Rs == 0:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=cmp.eq({self.toreg(s5)},#{self.apply_ext(self.tos(i,8))})"
                elif (MinOp & 3) == 0b11 and ((dword >> 13) & 1) == 1 and Rs == 0:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=!cmp.eq({self.toreg(s5)},#{self.apply_ext(self.tos(i,8))})"
                if ((MinOp >> 2) & 3) == 0b0 and Rs == 0:
                    i = (dword >> 5) & 0xFF
                    u2 = (dword >> 21) & 3
                    self.pushreg(d5)
                    return f"{self.topreg(d5)}=mux({self.toreg(u2)},{self.toreg(s5)},#{self.apply_ext(self.tos(i,8))})"
                elif ((MinOp >> 2) & 3) == 0b1 and Rs == 0:
                    i = (dword >> 5) & 0xFF
                    u2 = (dword >> 21) & 3
                    self.pushreg(d5)
                    return f"{self.topreg(d5)}=mux({self.toreg(u2)},#{self.apply_ext(self.tos(i,8))},{self.toreg(s5)})"
            elif MajOp == 0b100:
                DN = (dword >> 13) & 1  # DOTNEW
                PS = (dword >> 23) & 0x1  # Predicate sense
                i = (dword >> 5) & 0xFF
                u2 = (dword >> 23) & 3
                if Rs==0:
                    if DN == 0 and PS == 0:
                        self.pushreg(d5)
                        return f"if ({self.toreg(u2)}) {self.toreg(d5)}=add({self.toreg(s5)},#{self.tos(i,8)})"
                    elif DN == 1 and PS == 0:
                        self.pushreg(d5)
                        return f"if ({self.toreg(u2)}.new) {self.toreg(d5)}=add({self.toreg(s5)},#{self.tos(i,8)})"
                    elif DN == 0 and PS == 1:
                        self.pushreg(d5)
                        return f"if (!{self.toreg(u2)}) {self.toreg(d5)}=add({self.toreg(s5)},#{self.tos(i,8)})"
                    elif DN == 1 and PS == 1:
                        self.pushreg(d5)
                        return f"if (!{self.toreg(u2)}.new) {self.toreg(d5)}=add({self.toreg(s5)},#{self.tos(i,8)})"
                elif Rs==1:
                    if ((MinOp >> 2) & 3) == 0b0:
                        i = (dword >> 5) & 0xFF
                        l = (((dword >> 16) & 0x7F) << 1) + ((dword >> 13) & 1)
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=combine(#{self.apply_ext(self.tos(i,8))},#{self.tos(l,8)})"
                    elif ((MinOp >> 2) & 3) == 0b1:
                        i = (dword >> 5) & 0xFF
                        l = (((dword >> 16) & 0x3F) << 1) + ((dword >> 13) & 1)
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=combine(#{self.tos(i,8)},#{self.apply_ext(self.tou(l,6))})"
            elif MajOp == 0b101:
                d2 = dword & 3
                flag = (dword >> 2) & 7
                i = (((dword >> 21) & 1) << 8) + ((dword >> 5) & 0xFF)  # 10bit
                if (MinOp >> 1) & 0x3 == 0b00 and Rs == 0:
                    if flag == 0b000:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmp.eq({self.toreg(s5)},#{self.apply_ext(self.tos(i,10))})"
                    elif flag == 0b100:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=!cmp.eq({self.toreg(s5)},#{self.apply_ext(self.tos(i,10))})"
                elif (MinOp >> 1) & 0x3 == 0b01 and Rs == 0:
                    if flag == 0b000:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmp.gt({self.toreg(s5)},#{self.apply_ext(self.tos(i,10))})"
                    elif flag == 0b100:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=!cmp.gt({self.toreg(s5)},#{self.apply_ext(self.tos(i,10))})"
                elif MinOp == 0b100 and Rs == 0:
                    i = ((dword >> 5) & 0xFF)  # 9bit
                    if flag == 0b000:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmp.gtu({self.toreg(s5)},#{self.apply_ext(self.tou(i,9))})"
                    elif flag == 0b100:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=!cmp.gtu({self.toreg(s5)},#{self.apply_ext(self.tou(i,9))})"
            elif MajOp == 0b110:
                if C==0:
                    if ((MinOp >> 1) & 3) == 0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=and({self.toreg(s5)},#{self.apply_ext(self.tos(i,10))})"
                    elif ((MinOp >> 1) & 3) == 0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=or({self.toreg(s5)},#{self.apply_ext(self.tos(i,10))})"
                    elif ((MinOp >> 1) & 3) == 0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub(#{self.apply_ext(self.tos(i,10))},{self.toreg(s5)})"
                elif C==1:
                    if (dword >> 20) & 1 == 0:
                        i = (((dword >> 16) & 0xF) << 8) + ((dword >> 5) & 0xFF)  # 12bit
                        u2 = (dword >> 21) & 3
                        DN = (dword >> 13) & 1  # DOTNEW
                        PS = (dword >> 23) & 1  # Predicate sense
                        if PS == 0 and DN == 0:
                            self.pushreg(d5)
                            return f"if {self.toreg(u2)} {self.toreg(d5)}=#{self.apply_ext(self.tos(i,12))})"
                        elif PS == 0 and DN == 1:
                            self.pushreg(d5)
                            return f"if {self.toreg(u2)}.new {self.toreg(d5)}=#{self.apply_ext(self.tos(i,12))})"
                        elif PS == 1 and DN == 0:
                            self.pushreg(d5)
                            return f"if !{self.toreg(u2)} {self.toreg(d5)}=#{self.apply_ext(self.tos(i,12))})"
                        elif PS == 1 and DN == 1:
                            self.pushreg(d5)
                            return f"if !{self.toreg(u2)}.new {self.toreg(d5)}=#{self.apply_ext(self.tos(i,12))})"
            elif MajOp == 0b111:
                if Rs == 0b1:
                    self.pushreg(None)
                    return f"nop"
            elif ((MajOp >> 1) & 3) == 0b01 and Rs == 1:
                i = (dword >> 5) & 0xFF
                l = (((dword >> 16) & 0x7F) << 1) + ((dword >> 13) & 1)
                u1 = (dword >> 23) & 3
                self.pushreg(d5)
                return f"{self.topreg(d5)}=mux({self.toreg(u1)},#{self.apply_ext(self.tos(l,8))},#{self.tos(i,8)})"
        elif iclass == 0b1011:
            d5 = dword & 0x1F
            i = (((dword >> 21) & 0x7F) << 9) + (dword >> 5) & 0x1FF
            s5 = (dword >> 16) & 0x1F
            self.pushreg(d5)
            return f"{self.toreg(d5)}=add({self.toreg(s5)},#{self.apply_ext(self.tos(i,16))})"
        elif iclass == 0b1111:
            d5 = dword & 0x1F
            t5 = (dword >> 8) & 0x1F
            s5 = (dword >> 16) & 0x1F
            P = (dword >> 27) & 1  # Predicated
            MajOp = (dword >> 24) & 7
            MinOp = (dword >> 21) & 7
            if MajOp == 0b011 and MinOp == 0b000:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b001 and MinOp == 0b000:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=and({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b001 and MinOp == 0b001:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=or({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b001 and MinOp == 0b011:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=xor({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b001 and MinOp == 0b100:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=and({self.toreg(s5)},~{self.toreg(t5)})"
            elif MajOp == 0b001 and MinOp == 0b101:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=or({self.toreg(s5)},~{self.toreg(t5)})"
            elif MajOp == 0b011 and MinOp == 0b001:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=sub({self.toreg(t5)},{self.toreg(s5)})"
            elif MajOp == 0b110 and MinOp == 0b010:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)}):sat"
            elif MajOp == 0b110 and MinOp == 0b110:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=sub({self.toreg(t5)},{self.toreg(s5)}):sat"
            elif MajOp == 0b110 and MinOp == 0b000:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vaddh({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b110 and MinOp == 0b001:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vaddh({self.toreg(s5)},{self.toreg(t5)}):sat"
            elif MajOp == 0b110 and MinOp == 0b011:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vadduh({self.toreg(s5)},{self.toreg(t5)}):sat"
            elif MajOp == 0b111 and (MinOp & 3) == 0b00:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vavgh({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b111 and (MinOp & 3) == 0b01:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vavgh({self.toreg(s5)},{self.toreg(t5)}):rnd"
            elif MajOp == 0b111 and (MinOp & 3) == 0b11:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vnavgh({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b110 and MinOp == 0b100:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vsubh({self.toreg(t5)},{self.toreg(s5)})"
            elif MajOp == 0b110 and MinOp == 0b101:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vsubh({self.toreg(t5)},{self.toreg(s5)}):sat"
            elif MajOp == 0b110 and MinOp == 0b111:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=vsubuh({self.toreg(t5)},{self.toreg(s5)}):sat"
            elif MajOp == 0b011 and MinOp == 0b100 and P == 0:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=combine({self.toreg(t5)}.H,{self.toreg(s5)}.H)"
            elif MajOp == 0b011 and MinOp == 0b101 and P == 0:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=combine({self.toreg(t5)}.H,{self.toreg(s5)}.L)"
            elif MajOp == 0b011 and MinOp == 0b110 and P == 0:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=combine({self.toreg(t5)}.L,{self.toreg(s5)}.H)"
            elif MajOp == 0b011 and MinOp == 0b111 and P == 0:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=combine({self.toreg(t5)}.L,{self.toreg(s5)}.L)"
            elif MajOp == 0b101 and ((MinOp >> 2) & 1) == 0b0 and P == 0:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=combine({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b100 and P == 0:
                u2 = (dword >> 5) & 3
                self.pushreg(d5)
                return f"{self.toreg(d5)}=mux({self.toreg(u2)},{self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b101 and ((MinOp >> 2) & 1) == 0b1 and P == 0:
                self.pushreg(d5)
                return f"{self.torreg(d5)}=packhl({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b011 and (MinOp & 1) == 0b0 and ((MinOp >> 2) & 1 == 0b0) and P == 1:
                DN = (dword >> 13) & 1  # Dot-new
                PS = (dword >> 7) & 1  # Predicate sense
                u2 = (dword >> 5) & 3
                if DN == 0 and PS == 0:
                    self.pushreg(d5)
                    return f"if {self.toreg(u2)} {self.toreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)})"
                elif DN == 0 and PS == 1:
                    self.pushreg(d5)
                    return f"if !{self.toreg(u2)} {self.toreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)})"
                elif DN == 1 and PS == 0:
                    self.pushreg(d5)
                    return f"if {self.toreg(u2)}.new {self.toreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)})"
                elif DN == 1 and PS == 1:
                    self.pushreg(d5)
                    return f"if !{self.toreg(u2)}.new {self.toreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b101 and MinOp == 0b000 and P == 1:
                DN = (dword >> 13) & 1  # Dot-new
                PS = (dword >> 7) & 1  # Predicate sense
                u2 = (dword >> 5) & 3
                if DN == 0 and PS == 0:
                    self.pushreg(d5)
                    return f"if {self.toreg(u2)} {self.toreg(d5)}=combine({self.toreg(s5)},{self.toreg(t5)})"
                elif DN == 0 and PS == 1:
                    self.pushreg(d5)
                    return f"if !{self.toreg(u2)} {self.toreg(d5)}=combine({self.toreg(s5)},{self.toreg(t5)})"
                elif DN == 1 and PS == 0:
                    self.pushreg(d5)
                    return f"if {self.toreg(u2)}.new {self.toreg(d5)}=combine({self.toreg(s5)},{self.toreg(t5)})"
                elif DN == 1 and PS == 1:
                    self.pushreg(d5)
                    return f"if !{self.toreg(u2)}.new {self.toreg(d5)}=combine({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b001 and P == 1:
                DN = (dword >> 13) & 1  # Dot-new
                PS = (dword >> 7) & 1  # Predicate sense
                u2 = (dword >> 5) & 3
                if (MinOp & 3) == 0b00:
                    if DN == 0 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)} {self.toreg(d5)}=and({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 0 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)} {self.toreg(d5)}=and({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)}.new {self.toreg(d5)}=and({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)}.new {self.toreg(d5)}=and({self.toreg(s5)},{self.toreg(t5)})"
                elif (MinOp & 3) == 0b01:
                    if DN == 0 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)} {self.toreg(d5)}=or({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 0 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)} {self.toreg(d5)}=or({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)}.new {self.toreg(d5)}=or({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)}.new {self.toreg(d5)}=or({self.toreg(s5)},{self.toreg(t5)})"
                elif (MinOp & 3) == 0b11:
                    if DN == 0 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)} {self.toreg(d5)}=xor({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 0 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)} {self.toreg(d5)}=xor({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)}.new {self.toreg(d5)}=xor({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)}.new {self.toreg(d5)}=xor({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b011 and P == 1:
                DN = (dword >> 13) & 1  # Dot-new
                PS = (dword >> 7) & 1  # Predicate sense
                u2 = (dword >> 5) & 3
                if (MinOp & 1) == 0b01 and (MinOp >> 2) & 1 == 0b00:
                    if DN == 0 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)} {self.toreg(d5)}=sub({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 0 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)} {self.toreg(d5)}=sub({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 0:
                        self.pushreg(d5)
                        return f"if {self.toreg(u2)}.new {self.toreg(d5)}=sub({self.toreg(s5)},{self.toreg(t5)})"
                    elif DN == 1 and PS == 1:
                        self.pushreg(d5)
                        return f"if !{self.toreg(u2)}.new {self.toreg(d5)}=sub({self.toreg(s5)},{self.toreg(t5)})"
                elif (MinOp & 3) == 0b10:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=cmp.eq({self.toreg(s5)},{self.toreg(t5)})"
                elif (MinOp & 3) == 0b11:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=!cmp.eq({self.toreg(s5)},{self.toreg(t5)})"
            elif MajOp == 0b010:
                flag = (dword >> 2) & 7
                d2 = dword & 3
                if (MinOp & 3) == 0b00 and P == 0:
                    if flag == 0b000:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmp.eq({self.toreg(s5)},{self.toreg(t5)})"
                    elif flag == 0b100:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=!cmp.eq({self.toreg(s5)},{self.toreg(t5)})"
                elif (MinOp & 3) == 0b10 and P == 0:
                    if flag == 0b000:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmp.gt({self.toreg(s5)},{self.toreg(t5)})"
                    elif flag == 0b100:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=!cmp.gt({self.toreg(s5)},{self.toreg(t5)})"
                if (MinOp & 3) == 0b11 and P == 0:
                    if flag == 0b000:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmp.gtu({self.toreg(s5)},{self.toreg(t5)})"
                    elif flag == 0b100:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=!cmp.gtu({self.toreg(s5)},{self.toreg(t5)})"

        return "Error"

    def cr(self, iclass,dword):
        if iclass == 0b0110:
            d5 = dword & 0x1F
            d2 = dword & 0x3
            t2 = (dword >> 8) & 3
            s2 = (dword >> 16) & 3
            s5 = (dword >> 16) & 0x1F
            sm = (dword >> 26) & 1  # supervisor mode only
            flag27 = (dword >> 27) & 1
            flag13 = (dword >> 13) & 1
            flag7 = (dword >> 7) & 1
            flag4 = (dword >> 4) & 1
            if sm == 0:
                if flag27 == 0:
                    #01100S00000sssssPP-iiiii---ii---
                    #0110xS10001sssssPP---------ddddd
                    MinOp = (dword >> 21) & 0x1F
                    i = (((dword >> 8) & 0x1F) << 2) + ((dword >> 3) & 3)
                    if MinOp == 0b00000:
                        self.pushreg(None)
                        return f"loop0(#{self.apply_ext(self.tos(i,7,2))},{self.toreg(s5)})"
                    elif MinOp == 0b00001:
                        self.pushreg(None)
                        return f"loop1(#{self.apply_ext(self.tos(i,7,2))},{self.toreg(s5)})"
                    elif MinOp == 0b10001:
                        self.pushreg(d5)
                        return f"{self.tocreg(d5)}={self.toreg(s5)} (Cd=Rs)"
                    elif MinOp == 0b11001:
                        self.pushreg(d5)
                        return f"{self.toccreg(d5)}={self.torreg(s5)} (Cdd=Rss)"
                    elif MinOp == 0b11100:
                        self.pushreg(d2)
                        return f"{self.topreg(d2)}=any8({self.topreg(s2)})"
                    elif MinOp == 0b11101:
                        self.pushreg(d2)
                        return f"{self.topreg(d2)}=all8({self.topreg(s2)})"
                elif flag27 == 1:
                    MinOp = (dword >> 21) & 0x1F  # 5Bit
                    MinOp2 = (dword >> 16) & 0x3FF  # 10Bit
                    MinOp3 = (dword >> 20) & 0x3F  # 6Bit
                    i = (((dword >> 8) & 0x1F) << 2) + ((dword >> 3) & 3)
                    l = (((dword >> 16) & 0x1F) << 2) + (((dword >> 5) & 7) << 2) + (dword & 3)
                    u2 = (dword >> 6) & 3
                    if MinOp == 0b01000:
                        self.pushreg(None)
                        return f"loop0(#{self.apply_ext(self.tos(i,7,2))},#{self.tou(l,10)})"
                    elif MinOp == 0b01001:
                        self.pushreg(None)
                        return f"loop1(#{self.apply_ext(self.tos(i,7,2))},#{self.tou(l,10)})"
                    elif MinOp == 0b01101:
                        self.pushreg(None)
                        return f"sp3loop0(#{self.apply_ext(self.tos(i,7,2))},#{self.tou(l,10)})"
                    elif MinOp == 0b01110:
                        self.pushreg(None)
                        return f"sp3loop0(#{self.apply_ext(self.tos(i,7,2))},#{self.tou(l,10)})"
                    elif MinOp == 0b01111:
                        self.pushreg(None)
                        return f"sp3loop0(#{self.apply_ext(self.tos(i,7,2))},#{self.tou(l,10)})"
                    elif MinOp == 0b00101:
                        self.pushreg(None)
                        return f"p3=sp1loop0(#{self.apply_ext(self.tos(i,7,2))},{self.topreg(s5)})"
                    elif MinOp == 0b00110:
                        self.pushreg(None)
                        return f"p3=sp2loop0(#{self.apply_ext(self.tos(i,7,2))},{self.topreg(s5)})"
                    elif MinOp == 0b00111:
                        self.pushreg(None)
                        return f"p3=sp3loop0(#{self.apply_ext(self.tos(i,7,2))},{self.topreg(s5)})"
                    elif MinOp == 0b00000:
                        self.pushreg(d5)
                        return f"{self.torreg(d5)}={self.toccreg(s5)} (Rdd=Css)"
                    elif MinOp == 0b10000:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}={self.tocreg(s5)} (Rd=Cs)"
                    elif MinOp2 == 0b1001001001:
                        u6 = (dword >> 7) & 0x3F
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add(pc,#{self.apply_ext(self.tou(u6,6))})"
                    elif flag13 == 1 and flag7 == 1 and flag4 == 1:
                        #01101S11000--ssPP1---tt1--1--dd
                        MinOp = (dword >> 20) & 0x3F
                        if MinOp == 0b110000:
                            self.pushreg(d2)
                            return f"{self.topreg(d2)}=fastcorner9({self.topreg(s2)},{self.topreg(t2)})"
                        elif MinOp == 0b110001:
                            self.pushreg(d2)
                            return f"{self.topreg(d2)}=!fastcorner9({self.topreg(s2)},{self.topreg(t2)})"
                    elif flag13 == 0:
                        if MinOp3 == 0b110000:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=and({self.topreg(t2)},{self.topreg(s2)})"
                        elif MinOp3 == 0b110001:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=and({self.topreg(s2)},and({self.topreg(t2)},{self.topreg(u2)}))"
                        elif MinOp3 == 0b110010:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=or({self.topreg(t2)},{self.topreg(s2)})"
                        elif MinOp3 == 0b110011:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=and({self.topreg(s2)},or({self.topreg(t2)},{self.topreg(u2)}))"
                        elif MinOp3 == 0b110100:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=xor({self.topreg(s2)},{self.topreg(t2)})"
                        elif MinOp3 == 0b110101:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=or({self.topreg(s2)},and({self.topreg(t2)},{self.topreg(u2)}))"
                        elif MinOp3 == 0b110110:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=and({self.topreg(t2)},!{self.topreg(s2)})"
                        elif MinOp3 == 0b110111:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=or({self.topreg(s2)},or({self.topreg(t2)},{self.topreg(u2)}))"
                        elif MinOp3 == 0b111001:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=and({self.topreg(s2)},and({self.topreg(t2)},!{self.topreg(u2)}))"
                        elif MinOp3 == 0b111011:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=and({self.topreg(s2)},or({self.topreg(t2)},!{self.topreg(u2)}))"
                        elif MinOp3 == 0b111100:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=not({self.topreg(s2)})"
                        elif MinOp3 == 0b111101:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=or({self.topreg(s2)},and({self.topreg(t2)},!{self.topreg(u2)}))"
                        elif MinOp3 == 0b111110:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=or({self.topreg(t2)},!{self.topreg(s2)})"
                        elif MinOp3 == 0b111111:
                            self.pushreg(d5)
                            return f"{self.topreg(d5)}=or({self.topreg(s2)},or({self.topreg(t2)},!{self.topreg(u2)}))"
        return "Error"

    def jrclass(self, iclass, dword):
        # 01010000101sssssPP----uu--------
        if iclass == 0b0101:
            bit21=(dword>>21)&0x7F
            u2 = (dword>>8) & 3
            s5 = (dword >> 16) & 0x1F
            if bit21==0b0000101:
                self.pushreg(None)
                return f"callr {self.toreg(s5)}"
            elif bit21==0b0001000:
                self.pushreg(None)
                return f"if ({self.topreg(u2)}) callr {self.toreg(s5)}"
            elif bit21==0b0001001:
                self.pushreg(None)
                return f"if (!{self.topreg(u2)}) callr {self.toreg(s5)}"
            elif bit21==0b0010101:
                self.pushreg(None)
                return f"hintjr {self.toreg(s5)}"
            elif bit21==0b0010100:
                self.pushreg(None)
                return f"jumpr {self.toreg(s5)}"
            elif (bit21>>1)==0b001101:
                bit11=(dword>>11)&3
                if bit21==0b0011010:
                    if bit11==0b00:
                        self.pushreg(None)
                        return f"if ({self.topreg(u2)}) jumpr:nt {self.toreg(s5)}"
                    elif bit11==0b01:
                        self.pushreg(None)
                        return f"if ({self.topreg(u2)}.new) jumpr:nt {self.toreg(s5)}"
                    elif bit11==0b10:
                        self.pushreg(None)
                        return f"if ({self.topreg(u2)}) jumpr:t {self.toreg(s5)}"
                    elif bit11==0b11:
                        self.pushreg(None)
                        return f"if ({self.topreg(u2)}.new) jumpr:t {self.toreg(s5)}"
                elif bit21==0b0011011:
                    if bit11==0b00:
                        self.pushreg(None)
                        return f"if (!{self.topreg(u2)}) jumpr:nt {self.toreg(s5)}"
                    elif bit11==0b01:
                        self.pushreg(None)
                        return f"if (!{self.topreg(u2)}.new) jumpr:nt {self.toreg(s5)}"
                    elif bit11==0b10:
                        self.pushreg(None)
                        return f"if (!{self.topreg(u2)}) jumpr:t {self.toreg(s5)}"
                    elif bit11==0b11:
                        self.pushreg(None)
                        return f"if (!{self.topreg(u2)}.new) jumpr:t {self.toreg(s5)}"
        return "Error"

    def jclass(self, iclass, dword):
        if iclass==0b0001:
            bit22=(dword>>20)&0x3F
            s4=(dword>>16)&0xF
            bit13=(dword>>13)&1
            minop=(dword>>22)&7
            majop=(dword>>25)&7
            if majop==0b000:
                bit8=(dword>>8)&3
                i=(((dword>>20)&0x3)<<7)+((dword>>1)&0x7F) #9 Bits
                l = (dword >> 8) & 0x1F  # 5Bit
                if minop==0b000:
                    # 0001000000iissssPP0llllliiiiiii-
                    # 0001010000iissssPP00ttttiiiiiii-
                    i=(((dword>>20)&0x3)<<7)+(dword>>1)&0x7F
                    if bit13==0:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b001:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b010:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b011:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b100:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b101:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b110:
                    # 0001000110iissssPP0---00iiiiiii-
                    if bit13==0:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p0=cmp.eq({self.toreg(s4)},#-1); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p0=cmp.gt({self.toreg(s4)},#-1); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p0=tstbit({self.toreg(s4)},#0); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p0=cmp.eq({self.toreg(s4)},#-1); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p0=cmp.gt({self.toreg(s4)},#-1); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p0=tstbit({self.toreg(s4)},#0); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b111:
                    # 0001000110iissssPP0---00iiiiiii-
                    if bit13==0:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p0=cmp.eq({self.toreg(s4)},#-1); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p0=cmp.gt({self.toreg(s4)},#-1); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p0=tstbit({self.toreg(s4)},#0); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p0=cmp.eq({self.toreg(s4)},#-1); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p0=cmp.gt({self.toreg(s4)},#-1); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p0=tstbit({self.toreg(s4)},#0); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
            elif majop == 0b001:
                bit8 = (dword >> 8) & 3
                i = (((dword >> 20) & 0x3) << 7) + ((dword >> 1) & 0x7F)  # 9 Bits
                l = (dword >> 8) & 0x1F  # 5Bit
                if minop==0b110:
                    # 0001000110iissssPP0---00iiiiiii-
                    if bit13==0:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p1=cmp.eq({self.toreg(s4)},#-1); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p1=cmp.gt({self.toreg(s4)},#-1); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p1=tstbit({self.toreg(s4)},#0); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p1=cmp.eq({self.toreg(s4)},#-1); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p1=cmp.gt({self.toreg(s4)},#-1); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p1=tstbit({self.toreg(s4)},#0); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b111:
                    # 0001000110iissssPP0---00iiiiiii-
                    if bit13==0:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p1=cmp.eq({self.toreg(s4)},#-1); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p1=cmp.gt({self.toreg(s4)},#-1); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p1=tstbit({self.toreg(s4)},#0); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        if bit8==0b00:
                            self.pushreg(None)
                            return f"p1=cmp.eq({self.toreg(s4)},#-1); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b01:
                            self.pushreg(None)
                            return f"p1=cmp.gt({self.toreg(s4)},#-1); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                        elif bit8==0b11:
                            self.pushreg(None)
                            return f"p1=tstbit({self.toreg(s4)},#0); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b000:
                    # 0001000000iissssPP0llllliiiiiii-
                    # 0001010000iissssPP00ttttiiiiiii-
                    i=(((dword>>20)&0x3)<<7)+((dword>>1)&0x7F) #9 Bits
                    if bit13==0:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b001:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},#{self.tou(l,5)}); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b010:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b011:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},#{self.tou(l,5)}); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b100:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop==0b101:
                    if bit13==0:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit13==1:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},#{self.tou(l,5)}); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
            elif majop == 0b010:
                #0001010000iissssPP00ttttiiiiiii-
                i = (((dword >> 20) & 0x3) << 7) + ((dword >> 1) & 0x7F)
                s4=(dword>>16)&0xF
                t4=(dword>>8)&0xF
                bit12=(dword>>13)&3
                if minop == 0b000:
                    if bit12==0b00:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b01:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b10:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b11:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop == 0b001:
                    if bit12==0b00:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b01:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b10:
                        self.pushreg(None)
                        return f"p0=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b11:
                        self.pushreg(None)
                        return f"p1=cmp.eq({self.toreg(s4)},{self.toreg(t4)}); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop == 0b010:
                    if bit12==0b00:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b01:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b10:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b11:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop == 0b011:
                    if bit12==0b00:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b01:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b10:
                        self.pushreg(None)
                        return f"p0=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b11:
                        self.pushreg(None)
                        return f"p1=cmp.gt({self.toreg(s4)},{self.toreg(t4)}); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop == 0b100:
                    if bit12==0b00:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b01:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b10:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b11:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                elif minop == 0b101:
                    if bit12==0b00:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (!p0.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b01:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (!p1.new) jump:nt #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b10:
                        self.pushreg(None)
                        return f"p0=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (!p0.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
                    elif bit12==0b11:
                        self.pushreg(None)
                        return f"p1=cmp.gtu({self.toreg(s4)},{self.toreg(t4)}); if (!p1.new) jump:t #{self.apply_ext(self.tos(i,9,2,True))}"
            elif majop == 0b011:
                bit24=(dword>>24)&1
                i = (((dword >> 20) & 0x3) << 7) + ((dword >> 1) & 0x7F)
                if bit24==0b0:
                    l=(dword>>8)&0x3F #6Bit
                    #00010110--iiddddPPlllllliiiiiii-
                    d4=(dword>>16)&0xF
                    self.pushreg(d4)
                    return f"{self.toreg(d4)}={self.tou(l,6)} ; jump #{self.apply_ext(self.tou(i,9,2,True))}"
                elif bit24==0b1:
                    #00010111--iissssPP--ddddiiiiiii-
                    s4=(dword>>16)&0xF
                    d4=(dword>>8)&0xF
                    self.pushreg(d4)
                    return f"{self.toreg(d4)}={self.toreg(s4)} ; jump #{self.apply_ext(self.tou(i,9,2,True))}"
        elif iclass==0b0101:
            # 0101101iiiiiiiiiPPiiiiiiiiiiiii0
            # 01011101ii0iiiiiPPi-D-uuiiiiiii-
            DN=(dword>>11)&1
            majop=(dword>>25)&7
            u2 = (dword >> 8) & 3
            if majop==0b101:
                self.pushreg(None)
                i=(((dword>>16)&0x1FF)<<13)+((dword>>1)&0x1FFF) #22 Bits
                return f"call #{self.apply_ext(self.tos(i,22,2,True))}"
            elif majop==0b100:
                self.pushreg(None)
                i = (((dword >> 16) & 0x1FF) << 13) + ((dword >> 1) & 0x1FFF)  # 22 Bits
                return f"jump #{self.apply_ext(self.tou(i,22,2,True))}"
            elif majop==0b110:
                self.pushreg(None)
                bit21=(dword>>21)&1
                i=(((dword>>16)&0x1F)<<8)+(((dword>>13)&0x1)<<7)+((dword>>1)&0x7F) #15 Bits
                PT=(dword>>12)&1
                bit24=(dword>>24)&1
                if bit24==0:
                    if DN==0:
                        if bit21==0:
                            if PT == 0:
                                self.pushreg(None)
                                return f"if ({self.topreg(u2)}) jump:nt #{self.apply_ext(self.tou(i,15,2,True))}"
                            elif PT == 1:
                                self.pushreg(None)
                                return f"if ({self.topreg(u2)}) jump:t #{self.apply_ext(self.tou(i,15,2,True))}"
                        elif bit21==0:
                            if PT == 0:
                                self.pushreg(None)
                                return f"if (!{self.topreg(u2)}) jump:nt #{self.apply_ext(self.tou(i,15,2,True))}"
                            elif PT == 1:
                                self.pushreg(None)
                                return f"if (!{self.topreg(u2)}) jump:t #{self.apply_ext(self.tou(i,15,2,True))}"
                    elif DN==1:
                        if bit21==0:
                            if PT == 0:
                                self.pushreg(None)
                                return f"if ({self.topreg(u2)}.new) jump:nt #{self.apply_ext(self.tou(i,15,2,True))}"
                            elif PT == 1:
                                self.pushreg(None)
                                return f"if ({self.topreg(u2)}.new) jump:t #{self.apply_ext(self.tou(i,15,2,True))}"
                        elif bit21==1:
                            if PT == 0:
                                self.pushreg(None)
                                return f"if (!{self.topreg(u2)}.new) jump:nt #{self.apply_ext(self.tou(i,15,2,True))}"
                            elif PT == 1:
                                self.pushreg(None)
                                return f"if (!{self.topreg(u2)}.new) jump:t #{self.apply_ext(self.tou(i,15,2,True))}"
                elif bit24==1:
                    if DN==0:
                        #01011101ii0iiiiiPPi-0-uuiiiiiii-
                        i = (((dword>>22)&3)<<13)+ (((dword >> 16) & 0x1F) << 8) + (((dword >> 13) & 0x1) << 7) + ((dword >> 1) & 0x7F)  # 15 Bits
                        if bit21==0:
                            self.pushreg(None)
                            return f"if ({self.topreg(u2)}) call #{self.apply_ext(self.tou(i,15,2,True))}"
                        elif bit21==1:
                            self.pushreg(None)
                            return f"if (!{self.topreg(u2)}) call #{self.apply_ext(self.tou(i,15,2,True))}"
        elif iclass==0b0110:
            #01100S0100isssssPPi0iiiiiiiiiiii-
            i=(((dword >> 21) & 0x1) << 12) + (((dword >> 13) & 0x1) << 11) + ((dword >> 1) & 0x7FF)
            s5 = (dword >> 16) & 0x1F
            minop = (dword >> 22) & 7
            sm = (dword >> 26) & 1  # Supervisor only
            majop = (dword >> 25) & 7
            bit12=(dword>>12)&1
            if majop==0b000:
                if minop==0b100:
                    if bit12==0b0:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}!=#0) jump:nt #{self.tou(i,13,2,True)}"
                    elif bit12==0b1:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}!=#0) jump:t #{self.tou(i,13,2,True)}"
                elif minop==0b101:
                    if bit12==0b0:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}>=#0) jump:nt #{self.tou(i,13,2,True)}"
                    elif bit12==0b1:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}>=#0) jump:t #{self.tou(i,13,2,True)}"
                elif minop==0b110:
                    if bit12==0b0:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}==#0) jump:nt #{self.tou(i,13,2,True)}"
                    elif bit12==0b1:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}==#0) jump:t #{self.tou(i,13,2,True)}"
                elif minop==0b111:
                    if bit12==0b0:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}<=#0) jump:nt #{self.tou(i,13,2,True)}"
                    elif bit12==0b1:
                        self.pushreg(None)
                        return f"if ({self.toreg(s5)}<=#0) jump:t #{self.tou(i,13,2,True)}"
        return "Error"

    def typeconv2(self, type,UN):
        ftype=(type&3)
        if UN == 0b0:
            if ftype == 0b11:
                return "d",3
            elif ftype == 0b10:
                return "w",2
            elif ftype == 0b01:
                return "h",1
            elif ftype == 0b00:
                return "b",0
        elif UN == 0b1:
            if ftype == 0b00:
                return "ub",0
            elif ftype == 0b00:
                return "uh",1
        return "",0

    def typeconv3(self, type,UN):
        ftype=(type&3)
        if ((type>>2)&1)==0:
            if UN == 0b1:
                if ftype == 0b11:
                    return "bh",2
                elif ftype == 0b10:
                    return "ubh",2
                elif ftype == 0b01:
                    return "ubh",1
                elif ftype == 0b00:
                    return "bh",1
            else:
                if ftype == 0b11:
                    return "d_fifo", 3
                elif ftype == 0b10:
                    return "w_fifo", 2
                elif ftype == 0b01:
                    return "h_fifo", 1
                elif ftype == 0b00:
                    return "b_fifo", 0
        else:
            if UN == 0b0:
                if ftype == 0b11:
                    return "d", 3
                elif ftype == 0b10:
                    return "w", 2
                elif ftype == 0b01:
                    return "h", 1
                elif ftype == 0b00:
                    return "b", 0
            elif UN == 0b1:
                if ftype == 0b00:
                    return "ub", 0
                elif ftype == 0b01:
                    return "uh", 1
        return "",0

    def ld(self, iclass,dword):
        s5=(dword>>16)&0x1F
        x5=(dword>>16)&0x1F
        e5=(dword>>16)&0x1F
        t5=(dword>>16)&0x1F
        d5=dword&0x1F
        y5=dword&0x1F #normally used for fifo
        if iclass==0b0011:
            flag = (dword >> 24) & 0xF
            UN = (dword >> 21) & 1
            ftype = (dword >> 22) & 3
            tc,tv = self.typeconv2(ftype, UN)
            i = (((dword >> 13) & 1) << 1) + ((dword >> 7) & 1) #2Bit
            t5 = (dword >> 8) & 0x1F

            if tc == "d":
                reg = self.torreg(d5)
            else:
                reg = self.toreg(d5)

            if flag==0b0000:
                v=(dword>>5)&3
                self.pushreg(d5)
                return f"if ({self.topreg(v)}) {reg}=mem{tc}({self.toreg(s5)}+{self.toreg(t5)}<<#{self.tou(i,2)})"
            elif flag==0b0001:
                v=(dword>>5)&3
                self.pushreg(d5)
                return f"if (!{self.topreg(v)}) {reg}=mem{tc}({self.toreg(s5)}+{self.toreg(t5)}<<#{self.tou(i,2)})"
            elif flag == 0b0010:
                v = (dword >> 5) & 3
                self.pushreg(d5)
                return f"if ({self.topreg(v)}.new) {reg}=mem{tc}({self.toreg(s5)}+{self.toreg(t5)}<<#{self.tou(i,2)})"
            elif flag == 0b0011:
                v = (dword >> 5) & 3
                self.pushreg(d5)
                return f"if !({self.topreg(v)}.new) {reg}=mem{tc}({self.toreg(s5)}+{self.toreg(t5)}<<#{self.tou(i,2)})"
            elif flag == 0b1010:
                self.pushreg(d5)
                return f"{reg}=mem{tc}({self.toreg(s5)}+{self.toreg(t5)}<<#{self.tou(i,2)})"
        elif iclass==0b0100:
            flag27 = (dword >> 27) & 1
            flag24 = (dword >> 24) & 1
            flag13 = (dword >> 13) & 1
            ftype =(dword>>22)&3
            UN=(dword>>21)&1
            tc,tv = self.typeconv2(ftype, UN)
            if tc == "d":
                reg = self.torreg(d5)
            else:
                reg = self.toreg(d5)
            if flag27==0b1 and flag24==0b1: #OK
                i = (((dword >> 25) & 3) << 14) + (((dword >> 16) & 0x1F)<<9) + ((dword >> 5) & 0x1FF)
                if tc == "d":
                    self.pushreg(d5, 2)
                else:
                    self.pushreg(d5)
                return f"{reg}=mem{tc}(gp+#{self.apply_ext(self.tou(i,16,tv))})"
            elif flag24==0b1 and flag27==0b0 and flag13==0b0:
                sense=(dword>>26)&1
                prednew=(dword>>25)&1
                t2=(dword>>11)&3
                i=(dword>>5)&0x3F #6Bit
                if sense==0 and prednew==0:
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if {self.topreg(t2)} {reg}=mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}"
                elif sense==0 and prednew==1:
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if {self.topreg(t2)}.new {reg}=mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}"
                elif sense==1 and prednew==0:
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if !{self.topreg(t2)} {reg}=mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}"
                elif sense==1 and prednew==1:
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if !{self.topreg(t2)}.new {reg}=mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}"
        elif iclass==0b1001:
            amode=(dword>>25)&7
            ftype=(dword>>22)&7
            UN = (dword>>21)& 1
            tc, tv = self.typeconv3(ftype, UN)
            if tc == "d":
                reg = self.torreg(d5)
            else:
                reg = self.toreg(d5)
            flag13=(dword>>13)&1
            if amode==0b000:
                if ftype==0b000 and UN==0b0 and flag13==0:
                    self.pushreg(d5, 2)
                    return f"{self.torreg(d5)}=deallocframe({self.toreg(s5)}):raw)"
            elif amode==0b011:
                if ftype==0b000 and UN==0b0:
                    flag10 = (dword >> 10) & 0xF
                    v = (dword >> 8) & 3
                    if flag10==0b0000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=dealloc_return({self.toreg(s5)}):raw)"
                    elif flag10 == 0b0010:
                        self.pushreg(d5,2)
                        return f"if ({self.topreg(v)}.new) {self.torreg(d5)}=dealloc_return({self.toreg(s5)}):nt:raw)"
                    elif flag10 == 0b0100:
                        self.pushreg(d5,2)
                        return f"if ({self.topreg(v)}) {self.torreg(d5)}=dealloc_return({self.toreg(s5)}):raw)"
                    elif flag10 == 0b0110:
                        self.pushreg(d5,2)
                        return f"if ({self.topreg(v)}.new) {self.torreg(d5)}=dealloc_return({self.toreg(s5)}):t:raw)"
                    elif flag10 == 0b1010:
                        self.pushreg(d5,2)
                        return f"if ({self.topreg(v)}.new) {self.torreg(d5)}=dealloc_return({self.toreg(s5)}):nt:raw)"
                    elif flag10 == 0b1100:
                        self.pushreg(d5,2)
                        return f"if (!{self.topreg(v)}) {self.torreg(d5)}=dealloc_return({self.toreg(s5)}):raw)"
                    elif flag10 == 0b1110:
                        self.pushreg(d5,2)
                        return f"if (!{self.topreg(v)}.new) {self.torreg(d5)}=dealloc_return({self.toreg(s5)}):t:raw)"
            elif amode==0b100:
                flag12 = (dword >> 12) & 1
                flag9 = (dword >> 9) & 1
                flag7 = (dword >> 9) & 1
                u1 = (dword >> 13) & 1
                if flag12==0 and flag9==0:
                    i=(dword>>4)&0xF #4 Bit
                    if tc == "d":
                        self.pushreg(d5,2)
                    else:
                        self.pushreg(d5)
                    return f"{reg}=mem{tc}({self.toreg(x5)}++#{self.apply_ext(self.tos(i,4,tv))}:circ({self.toreg(u1)}))"
                elif flag12==0 and flag9==1 and flag7==0:
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"{reg}=mem{tc}({self.toreg(x5)}++I:circ({self.toreg(u1)}))"
            elif amode==0b101:
                flag12=(dword >> 12) & 3
                flag11=(dword >> 11) & 7
                if flag12==0b01:
                    l=(((dword>>8)&0xF)<<2) + ((dword>>5)&3) #6Bit
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"{reg}=mem{tc}({self.toreg(e5)}=#{self.apply_ext(self.tou(l,6))})"
                elif flag12==0b00:
                    i=(dword>>5)&0xF #4Bit
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"{reg}=mem{tc}({self.toreg(x5)}++#{self.apply_ext(self.tos(i,4,tv))})"
                elif flag11==0b100:
                    i = (dword >> 5) & 0xF  # 4Bit
                    t2=(dword>>9)&3
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if {self.toreg(t2)} {reg}=mem{tc}({self.toreg(t2)}++#{self.apply_ext(self.tos(i,4,tv))})"
                elif flag11==0b101:
                    i = (dword >> 5) & 0xF  # 4Bit
                    t2 = (dword >> 9) & 3
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if !{self.toreg(t2)} {reg}=mem{tc}({self.toreg(t2)}++#{self.apply_ext(self.tos(i,4,tv))})"
                elif flag11==0b110:
                    i = (dword >> 5) & 0xF  # 4Bit
                    t2 = (dword >> 9) & 3
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if {self.toreg(t2)}.new {reg}=mem{tc}({self.toreg(t2)}++#{self.apply_ext(self.tos(i,4,tv))})"
                elif flag11==0b111:
                    i = (dword >> 5) & 0xF  # 4Bit
                    t2 = (dword >> 9) & 3
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"if !{self.toreg(t2)}.new {reg}=mem{tc}({self.toreg(t2)}++#{self.apply_ext(self.tos(i,4,tv))})"
            elif amode==0b110:
                flag12 = (dword >> 12) & 1
                if flag12==1:
                    i=(((dword>>13)&1)<<1)+((dword>>7)&1) #2Bit
                    l=(((dword>>8)&0xF)<<2) + ((dword>>5)&3) #6Bit
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"{reg}=mem{tc}({self.toreg(t5)}<<#{self.tou(i,2)}+#{self.apply_ext(self.tou(l,6))})"
                elif flag12==0:
                    flag7=(dword>>7)&1
                    u1=(dword>>13)&1
                    if flag7==0:
                        if tc == "d":
                            self.pushreg(d5, 2)
                        else:
                            self.pushreg(d5)
                        return f"{reg}=mem{tc}({self.toreg(x5)}++{self.toreg(u1)})"
            elif amode==0b111:
                flag7 = (dword >> 7) & 1
                u1 = (dword >> 13) & 1
                flag11 = (dword >> 11) & 7
                if flag7 == 0b0:
                    if tc == "d":
                        self.pushreg(d5, 2)
                    else:
                        self.pushreg(d5)
                    return f"{reg}=mem{tc}({self.toreg(x5)}++{self.toreg(u1)}:brev)"
                elif flag7==0b1:
                    t2=(dword>>9)&3
                    i=(((dword>>16)&0x1F)<<1)+((dword>>8)&1)
                    if flag11==0b100:
                        if tc == "d":
                            self.pushreg(d5, 2)
                        else:
                            self.pushreg(d5)
                        return f"if {self.toreg(t2)} {reg}=mem{tc}(#{self.tou(i,6)})"
                    elif flag11==0b101:
                        if tc == "d":
                            self.pushreg(d5, 2)
                        else:
                            self.pushreg(d5)
                        return f"if !{self.toreg(t2)} {reg}=mem{tc}(#{self.tou(i,6)})"
                    elif flag11==0b110:
                        if tc == "d":
                            self.pushreg(d5, 2)
                        else:
                            self.pushreg(d5)
                        return f"if {self.toreg(t2)}.new {reg}=mem{tc}(#{self.tou(i,6)})"
                    elif flag11==0b111:
                        if tc == "d":
                            self.pushreg(d5, 2)
                        else:
                            self.pushreg(d5)
                        return f"if !{self.toreg(t2)}.new {reg}=mem{tc}(#{self.tou(i,6)})"
            if ((amode>>2)&1)==0:
                i = (((dword >> 25) & 3) << 9) + ((dword >> 5) & 0x1FF)  # 11bit
                if tc == "d":
                    self.pushreg(d5, 2)
                else:
                    self.pushreg(d5)
                return f"{reg}=mem{tc}({self.toreg(s5)}+#{self.apply_ext(self.tos(i,11,tv))})"
        return "Error"

    def memop(self, iclass, dword):
        if iclass==0b0011:
            ftype=(dword>>21)&3
            UN=0
            s5=(dword>>16)&0x1F
            i=(dword>>7)&0x3F
            tc,tv=self.typeconv2(ftype,UN)
            flag13=(dword>>13)&1
            flag5=(dword>>5)&3
            mclass=(dword>>24)&0xF
            if mclass==0b1110:
                if flag13 == 0:
                    t5 = dword & 0x1F
                    if flag5==0b00:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})+={self.toreg(t5)}"
                    elif flag5==0b01:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})-={self.toreg(t5)}"
                    elif flag5==0b10:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})&={self.toreg(t5)}"
                    elif flag5==0b11:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})|={self.toreg(t5)}"
            elif mclass==0b1111:
                if flag13 == 0:
                    l5 = dword & 0x1F
                    if flag5==0b00:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})+={self.tou(l5,5)}"
                    elif flag5==0b01:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})-={self.tou(l5,5)}"
                    elif flag5==0b10:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})=clrbit(#{self.tou(l5,5)})"
                    elif flag5==0b11:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)})=setbit(#{self.tou(l5,5)})"
        return "Error"

    def nv(self, iclass, dword):
        if iclass==0b0010:
            #0010000000ii-sssPPxtttttiiiiiii0
            flag=(dword>>22)&0x3F
            s3=(dword>>16)&7
            flag13=(dword>>13)&1
            t5=(dword>>8)&0x1F
            l5=(dword >> 8)&0x1F
            reg = self.aheadreg(s3)
            i=(((dword>>20)&3)<<7)+((dword>>1)&0x7F)
            if flag==0b000000:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.eq({reg}.new,{self.toreg(t5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.eq({reg}.new,{self.toreg(t5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b000001:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.eq({reg}.new,{self.toreg(t5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.eq({reg}.new,{self.toreg(t5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b000010:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.gt({reg}.new,{self.toreg(t5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.gt({reg}.new,{self.toreg(t5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b000011:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.gt({reg}.new,{self.toreg(t5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.gt({reg}.new,{self.toreg(t5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b000100:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.gtu({reg}.new,{self.toreg(t5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.gtu({reg}.new,{self.toreg(t5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b000101:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.gtu({reg}.new,{self.toreg(t5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.gtu({reg}.new,{self.toreg(t5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b000110:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.gt({self.toreg(t5)},{reg}.new)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.gt({self.toreg(t5)},{reg}.new)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b000111:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.gt({self.toreg(t5)},{reg}.new)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.gt({self.toreg(t5)},{reg}.new)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b001000:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.gtu({self.toreg(t5)},{reg}.new)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.gtu({self.toreg(t5)},{reg}.new)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b001001:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.gtu({self.toreg(t5)},{reg}.new)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.gtu({self.toreg(t5)},{reg}.new)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010000:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.eq({reg}.new,#{self.tou(l5,5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.eq({reg}.new,#{self.tou(l5,5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010001:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.eq({reg}.new,#{self.tou(l5,5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.eq({reg}.new,#{self.tou(l5,5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010010:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.gt({reg}.new,#{self.tou(l5,5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.gt({reg}.new,#{self.tou(l5,5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010011:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.gt({reg}.new,#{self.tou(l5,5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.gt({reg}.new,#{self.tou(l5,5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010100:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.gtu({reg}.new,#{self.tou(l5,5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.gtu({reg}.new,#{self.tou(l5,5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010101:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.gtu({reg}.new,#{self.tou(l5,5)})) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.gtu({reg}.new,#{self.tou(l5,5)})) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010110:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (tstbit({reg}.new,#0)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (tstbit({reg}.new,#0)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b010111:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!tstbit({reg}.new,#0)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!tstbit({reg}.new,#0)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b011000:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.eq({reg}.new,#-1)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.eq({reg}.new,#-1)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b011001:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.eq({reg}.new,#-1)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.eq({reg}.new,#-1)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b011010:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (cmp.gt({reg}.new,#-1)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (cmp.gt({reg}.new,#-1)) jump:t #{self.tos(i,9,2)}"
            elif flag==0b011011:
                if flag13==0b0:
                    self.pushreg(None)
                    return f"if (!cmp.gt({reg}.new,#-1)) jump:nt #{self.tos(i,9,2)}"
                elif flag13==0b1:
                    self.pushreg(None)
                    return f"if (!cmp.gt({reg}.new,#-1)) jump:t #{self.tos(i,9,2)}"
        return "Error"

    def nv_st(self, iclass, dword):
        if iclass==0b0011:
            #00111011110sssssPPiuuuuui--00ttt
            #00110100110sssssPPiuuuuuivv00ttt
            s5=(dword>>16)&0x1F
            i = (((dword >> 13) & 1) << 1) + ((dword >> 7) & 1)  # 2Bit
            t3 = dword & 0x7
            reg=self.aheadreg(t3)
            u5=(dword>>8)&0x1F
            flag=(dword>>24)&0xF
            v2=(dword>>5)&3
            UN = (dword >> 21) & 1
            tc=None
            if UN==0b1: #NV Type 0011 10111 01 sssssPPiuuuuui--00ttt
                ftype=(dword >> 3) & 3
                UN=0
                tc, tv = self.typeconv2(ftype, UN)
                add=".new"
            elif UN==0b0: #ST Type 0011 10111 10 sssssPPiuuuuui--ttttt
                ftype = (dword >> 22) & 3
                tc, tv = self.typeconv2(ftype, UN)
                add=""
            if flag==0b1011:
                self.pushreg(None)
                return f"mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={reg}.new"
            elif flag == 0b0100:
                self.pushreg(None)
                return f"if ({self.toreg(v2)}) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={reg}.new"
            elif flag == 0b0101:
                self.pushreg(None)
                return f"if (!{self.toreg(v2)}) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={reg}.new"
            elif flag == 0b0110:
                self.pushreg(None)
                return f"if ({self.toreg(v2)}.new) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={reg}.new"
            elif flag == 0b0111:
                self.pushreg(None)
                return f"if (!{self.toreg(v2)}.new) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={reg}.new"
        elif iclass==0b0100:
            #01001ii1101iiiiiPPi00tttiiiiiiii
            #01001sp0101sssssPPi00tttiiiii0vv
            #01001ii0TTTiiiiiPPi01tttiiiiiiii
            t3=(dword>>8)&0x7
            reg = self.aheadreg(t3)
            ftype=(dword>>11)&3
            flag27=(dword>>27)&1
            flag24=(dword>>24)&1
            rtype=(dword>>21)&7
            UN=(dword>>21)&1
            tc,tv=self.typeconv2(ftype,0)

            if flag27==0b1:
                #01001ii0110iiiiiPPitttttiiiiiiii   memd(gp+#u16:3)=Rtt
                #01001ii0000iiiiiPPitttttiiiiiiii   memb(gp+#u16:0)=Rt
                #01001ii0101iiiiiPPi00tttiiiiiiii   memb(gp+#u16:0)=Nt.new
                #01001000101010001100001001100000
                t5=(dword>>8)&0x1F
                i = (((dword >> 25) & 3) << 14) + (((dword >> 16) & 0x1F) << 9) + (((dword >> 13) & 1) << 8) + (dword & 0xFF)
                if flag24==0b0:
                   return f"mem{tc}(gp+#{self.tou(i,16,tv)})={reg}.new"
            elif flag27==0b0:
                s5=(dword>>16)&0x1F
                v2=dword&3
                flag2=(dword>>2)&1
                i=(((dword>>13)&1)<<5)+((dword>>4)&0x1F) #6 Bit
                if flag2==0b0:
                    sense = (dword >> 26) & 1
                    prednew = (dword >> 25) & 1
                    if sense==0 and prednew==0:
                        self.pushreg(None)
                        return f"if ({self.toreg(v2)}) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={reg}.new"
                    elif sense==0 and prednew==1:
                        self.pushreg(None)
                        return f"if ({self.toreg(v2)}.new) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={reg}.new"
                    elif sense==1 and prednew==0:
                        self.pushreg(None)
                        return f"if (!{self.toreg(v2)}) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={reg}.new"
                    elif sense==1 and prednew==1:
                        self.pushreg(None)
                        return f"if (!{self.toreg(v2)}.new) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={reg}.new"
        elif iclass==0b1010:
            #1010aaaTTTUxxxxxPPu00ttt0-----1-
            #1010aaaTTTUxxxxxPPu00ttt1-llllll
            #1010aaaTTTUxxxxxPPu00ttt0iiii-0-
            #1010aaaTTTUuuuuuPPi00ttt1illllll
            #1010aaaTTTUxxxxxPPu00ttt0-------
            #1010aaaTTTUsssssPPi00tttiiiiiiii
            #1010aaaTTTUeeeeePP000ttt1-llllll
            #1010aaaTTTU---iiPP000ttt1iiii0vv
            flag13 = (dword >> 13) & 1
            t3=(dword>>8)&0x7
            reg=self.aheadreg(t3)
            i=((dword>>25)&3<<9) +(((dword>>13)&1)<<8)+(dword&0xFF)
            amode=(dword>>25)&7
            #rtype=(dword>>22)&7
            rtype = (dword >> 11) & 3
            UN=(dword>>21)&1
            flag7 = (dword >> 7) & 1
            stype = (dword >> 21) & 7
            tc, tv = self.typeconv2(rtype, 0)

            if ((amode>>2)&1)==0b0: #ok
                #10100ii1000sssssPPitttttiiiiiiii   memb(Rs+#s11:0)=Rt
                #10100ii1100sssssPPitttttiiiiiiii   memw(Rs+#s11:2)=Rt
                s5 = (dword >> 16) & 0x1F
                t5=(dword >>8) & 0x1F
                self.pushreg(None)
                return f"mem{tc}({self.toreg(s5)}+#{self.tos(i,11,tv)})={reg}.new"
            elif amode==0b100:
                u1=(dword>>13)&1
                x5 = (dword >> 16) & 0x1F
                flag1=(dword>>1)&1
                if flag7==0b0:
                    if flag1==0b1:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(x5)}++I:circ({self.toreg(u1)}))={reg}.new"
                    elif flag1==0b0:
                        self.pushreg(None)
                        i=(dword>>3)&0xF
                        return f"mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)}:circ({self.toreg(u1)}))={reg}.new"
            elif amode==0b101:
                if flag7==0b1:
                    if flag13==0b0:
                        e5 = (dword >> 16) & 0x1F
                        l6 = (dword & 0x3F)
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(e5)}=#{self.tou(l6,6)})={reg}.new"
                    elif flag13==0b1:
                        flag1 = (dword >> 1) & 1
                        i = (dword >> 3) & 0xF
                        v2=dword&3
                        x5 = (dword >> 16) & 0x1F
                        if flag1==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}.new) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={reg}.new"
                        elif flag1==0b1:
                            self.pushreg(None)
                            return f"if (!{self.toreg(v2)}.new) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={reg}.new"
                elif flag7==0b0:
                    x5 = (dword >> 16) & 0x1F
                    flag1=(dword>>1)&1
                    i=(dword>>3)&0xF
                    if flag13==0b0:
                        if flag1==0b0:
                            self.pushreg(None)
                            return f"mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={reg}.new"
                    elif flag13==0b1:
                        v2=dword&3
                        if flag1==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={reg}.new"
                        elif flag1==0b1:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={reg}.new"
            elif amode==0b110:
                if flag7==1:
                    u5= (dword >> 16) & 0x1F
                    l6 = (dword & 0x3F)
                    i=(((dword>>13)&1)<<1)+((dword>>6)&1)
                    self.pushreg(None)
                    return f"mem{tc}({self.toreg(u5)}<<#{self.tou(i,2)}+#{self.tou(l6,6)})={reg}.new"
                elif flag7==0:
                    x5 = (dword >> 16) & 0x1F
                    u1 = (dword >> 13) & 0x1
                    self.pushreg(None)
                    return f"mem{tc}({self.toreg(x5)}++{self.toreg(u1)})={reg}.new"
            elif amode==0b111:
                if flag7 == 0b0:
                    x5 = (dword >> 16) & 0x1F
                    u1 = (dword >> 13) & 0x1
                    self.pushreg(None)
                    return f"mem{tc}({self.toreg(x5)}++{self.toreg(u1)}:brev)={reg}.new"
                elif flag7==0b1:
                    v2=dword&3
                    i=(((dword>>16)&3)<<4)+(dword>>3)&0xF
                    flag2 = (dword >> 2) & 1
                    if flag13==0b0:
                        if flag2==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}) mem{tc}(#{self.tou(i,6)}={reg}.new"
                        elif flag2==0b1:
                            self.pushreg(None)
                            return f"if (!{self.toreg(v2)}) mem{tc}(#{self.tou(i,6)}={reg}.new"
                    elif flag13==0b1:
                        if flag2==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}.new) mem{tc}(#{self.tou(i,6)}={reg}.new"
                        elif flag2==0b1:
                            self.pushreg(None)
                            return f"if (!{self.toreg(v2)}.new) mem{tc}(#{self.tou(i,6)}={reg}.new"
        return "Error"

    def st(self, iclass, dword):
        if iclass==0b0011:
            #00111011110sssssPPiuuuuui--ttttt
            #00110100110sssssPPiuuuuuivvttttt
            #0011110--00sssssPPiiiiiiilllllll
            #00111000000sssssPPliiiiiivvlllll
            s5=(dword>>16)&0x1F
            i = (((dword >> 13) & 1) << 1) + ((dword >> 7) & 1)  # 2Bit
            t5 = dword & 0x1F
            u5=(dword>>8)&0x1F
            flag=(dword>>24)&0xF
            v2=(dword>>5)&3
            UN = (dword >> 21) & 1
            if UN==0b1: #NV Type 0011 10111 01 sssssPPiuuuuui--00ttt
                ftype=(dword >> 3) & 3
                UN=0
                tc, tv = self.typeconv2(ftype, UN)
                add=".new"
            elif UN==0b0: #ST Type 0011 10111 10 sssssPPiuuuuui--ttttt
                ftype = (dword >> 22) & 3
                tc, tv = self.typeconv2(ftype, UN)
                add=""
            if tc=="d":
                treg=self.torreg(t5)
            else:
                treg=self.toreg(t5)

            if flag==0b1011:
                self.pushreg(None)
                return f"mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={treg}{add}"
            elif flag == 0b0100:
                self.pushreg(None)
                return f"if ({self.toreg(v2)}) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={treg}{add}"
            elif flag == 0b0101:
                self.pushreg(None)
                return f"if (!{self.toreg(v2)}) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={treg}{add}"
            elif flag == 0b0110:
                self.pushreg(None)
                return f"if ({self.toreg(v2)}.new) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={treg}{add}"
            elif flag == 0b0111:
                self.pushreg(None)
                return f"if (!{self.toreg(v2)}.new) mem{tc}({self.toreg(s5)}+{self.toreg(u5)}<<#{self.tou(i,2)})={treg}{add}"
        elif iclass==0b0100:
            #01001ii0110iiiiiPPitttttiiiiiiii
            #01000sp0110sssssPPitttttiiiiiiii
            #01001ii0TTTiiiiiPPitttttiiiiiiii
            t5=(dword>>8)&0x1F
            ftype=(dword>>11)&3
            flag27=(dword>>27)&1
            flag24=(dword>>24)&1
            rtype=(dword>>21)&7
            UN=(dword>>21)&1
            if UN==0b1:
                UN=0
                tc,tv=self.typeconv2(ftype,UN)
                add=".new"
            else:
                ftype = (dword >> 22) & 3
                UN = (dword>>21)&1
                tc, tv = self.typeconv2(ftype, UN)
                add=""

            if tc=="d":
                treg=self.torreg(t5)
            else:
                treg=self.toreg(t5)

            if flag27==0b1:
                #01001ii0110iiiiiPPitttttiiiiiiii   memd(gp+#u16:3)=Rtt
                #01001ii0000iiiiiPPitttttiiiiiiii   memb(gp+#u16:0)=Rt
                #01001ii0101iiiiiPPi00tttiiiiiiii   memb(gp+#u16:0)=Nt.new
                #01001000101010001100001001100000
                t5=(dword>>8)&0x1F
                i = (((dword >> 25) & 3) << 14) + (((dword >> 16) & 0x1F) << 9) + (((dword >> 13) & 1) << 8) + (dword & 0xFF)
                if flag24==0b0:
                    if add=="":
                        self.pushreg(None)
                        return f"mem{tc}(gp+#{self.apply_ext(self.tou(i,16,tv))})={treg}"
                    elif add==".new":
                        n3=((dword>>8)&0x7)
                        reg=self.aheadreg(n3)
                        self.pushreg(None)
                        return f"mem{tc}(gp+#{self.apply_ext(self.tou(i,16,tv))})={reg}.new"
            elif flag27==0b0:
                s5=(dword>>16)&0x1F
                v2=dword&3
                flag2=(dword>>2)&1
                i=(((dword>>13)&1)<<5)+((dword>>4)&0x1F) #6 Bits
                if flag2==0b0:
                    sense = (dword >> 26) & 1
                    prednew = (dword >> 25) & 1
                    if sense==0 and prednew==0:
                        self.pushreg(None)
                        return f"if ({self.topreg(v2)}) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={treg}{add}"
                    elif sense==0 and prednew==1:
                        self.pushreg(None)
                        return f"if ({self.topreg(v2)}.new) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={treg}{add}"
                    elif sense==1 and prednew==0:
                        self.pushreg(None)
                        return f"if (!{self.topreg(v2)}) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={treg}{add}"
                    elif sense==1 and prednew==1:
                        self.pushreg(None)
                        return f"if (!{self.topreg(v2)}.new) mem{tc}({self.toreg(s5)}+#{self.tou(i,6,tv)}={treg}{add}"
        elif iclass==0b1010:
            #1010aaaTTTUxxxxxPPuttttt0-----1-
            #1010aaaTTTUxxxxxPPuttttt1-llllll
            #1010aaaTTTUxxxxxPPuttttt0iiii-0-
            #1010aaaTTTUuuuuuPPittttt1illllll
            #1010aaaTTTUxxxxxPPuttttt0-------
            #1010aaaTTTUsssssPPitttttiiiiiiii
            #1010aaaTTTUeeeeePP0ttttt1-llllll
            #1010aaaTTTU---iiPP0ttttt1iiii0vv
            flag13 = (dword >> 13) & 1
            t5=(dword>>8)&0x1F
            i=((dword>>25)&3<<9) +(((dword>>13)&1)<<8)+(dword&0xFF)
            amode=(dword>>25)&7
            rtype=(dword>>22)&7
            UN=(dword>>21)&1
            flag7 = (dword >> 7) & 1

            if UN==0b1:
                stype = (dword >> 21) & 7
                if stype==0b101 and iclass!=0b011:
                    return self.nv_st(iclass,dword)
            else:
                UN = (dword >> 21) & 1
                tc, tv = self.typeconv3(rtype, UN)
                add = ""

            if tc=="d":
                treg=self.torreg(t5)
            else:
                treg=self.toreg(t5)


            if amode==0b000 and rtype==0b010 and UN==0b0:
                x5 = (dword >> 16) & 0x1F
                i=(dword&0x3FF)
                self.pushreg(None)
                return f"allocframe({self.toreg(x5)},#{self.tou(i,11,3)}:raw"
            elif ((amode>>2)&1)==0b0: #ok
                #10100ii1000sssssPPitttttiiiiiiii   memb(Rs+#s11:0)=Rt
                #10100ii1100sssssPPitttttiiiiiiii   memw(Rs+#s11:2)=Rt
                s5 = (dword >> 16) & 0x1F
                t5=(dword >>8) & 0x1F
                self.pushreg(None)
                return f"mem{tc}({self.toreg(s5)}+#{self.tos(i,11,tv)})={treg}"
            elif amode==0b100:
                u1=(dword>>13)&1
                x5 = (dword >> 16) & 0x1F
                flag1=(dword>>1)&1
                if flag7==0b0:
                    if flag1==0b1:
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(x5)}++I:circ({self.toreg(u1)}))={treg}"
                    elif flag1==0b0:
                        i=(dword>>3)&0xF
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(x5)}++#{self.to(i,4,tv)}:circ({self.toreg(u1)}))={treg}"
            elif amode==0b101:
                if flag7==0b1:
                    if flag13==0b0:
                        e5 = (dword >> 16) & 0x1F
                        l6 = (dword & 0x3F)
                        self.pushreg(None)
                        return f"mem{tc}({self.toreg(e5)}=#{self.tou(l6,6)})={treg}"
                    elif flag13==0b1:
                        flag1 = (dword >> 1) & 1
                        i = (dword >> 3) & 0xF
                        v2=dword&3
                        x5 = (dword >> 16) & 0x1F
                        if flag1==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}.new) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={treg}"
                        elif flag1==0b1:
                            self.pushreg(None)
                            return f"if (!{self.toreg(v2)}.new) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={treg}"
                elif flag7==0b0:
                    x5 = (dword >> 16) & 0x1F
                    flag1=(dword>>1)&1
                    i=(dword>>3)&0xF
                    if flag13==0b0:
                        if flag1==0b0:
                            self.pushreg(None)
                            return f"mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={treg}"
                    elif flag13==0b1:
                        v2=dword&3
                        if flag1==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={treg}"
                        elif flag1==0b1:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}) mem{tc}({self.toreg(x5)}++#{self.tos(i,4,tv)})={treg}"
            elif amode==0b110:
                if flag7==1:
                    u5= (dword >> 16) & 0x1F
                    l6 = (dword & 0x3F)
                    i=(((dword>>13)&1)<<1)+((dword>>6)&1)
                    self.pushreg(None)
                    return f"mem{tc}({self.toreg(u5)}<<#{self.tou(i,2)}+#{self.tou(l6,6)})={treg}"
                elif flag7==0:
                    x5 = (dword >> 16) & 0x1F
                    u1 = (dword >> 13) & 0x1
                    self.pushreg(None)
                    return f"mem{tc}({self.toreg(x5)}++{self.toreg(u1)})={treg}"
            elif amode==0b111:
                if flag7 == 0b0:
                    x5 = (dword >> 16) & 0x1F
                    u1 = (dword >> 13) & 0x1
                    self.pushreg(None)
                    return f"mem{tc}({self.toreg(x5)}++{self.toreg(u1)}:brev)={treg}"
                elif flag7==0b1:
                    v2=dword&3
                    i=(((dword>>16)&3)<<4)+((dword>>3)&0xF)
                    flag2 = (dword >> 2) & 1
                    if flag13==0b0:
                        if flag2==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}) mem{tc}(#{self.tou(i,6)}={treg}"
                        elif flag2==0b1:
                            self.pushreg(None)
                            return f"if (!{self.toreg(v2)}) mem{tc}(#{self.tou(i,6)}={treg}"
                    elif flag13==0b1:
                        if flag2==0b0:
                            self.pushreg(None)
                            return f"if ({self.toreg(v2)}.new) mem{tc}(#{self.tou(i,6)}={treg}"
                        elif flag2==0b1:
                            self.pushreg(None)
                            return f"if (!{self.toreg(v2)}.new) mem{tc}(#{self.tou(i,6)}={treg}"
        return "Error"

    def xtype(self, iclass, dword):
        if iclass==0b0001:
            regtype=(dword>>24)&0xF
            majop=(dword>>21)&7
            bit13=(dword>>13)&1
            bits0=dword&0x7
            u5=(dword>>16)&0x1F
            v5=(dword>>8)&0x1F
            x5=(dword>>3)&0x1F
            if regtype==0b1111:
                if majop==0b000:
                    if bit13==0b1:
                        if bits0==0b111:
                            self.pushreg(x5, 2)
                            return f"{self.tovrreg(x5)}+=vrcmpy({self.tovreg(u5)},{self.tovreg(v5)}):sat"
                elif majop==0b110:
                    if bit13==1:
                        if bits0==0b000:
                            self.pushreg(x5, 2)
                            return f"{self.tovrreg(x5)}=vrcmpy({self.tovreg(u5)},{self.tovreg(v5)}):sat"
        elif iclass==0b1000:
            #10000000OO0sssssPP------MMMddddd
            regtype=(dword>>24)&0xF
            majop=(dword>>22)&3
            bit21=(dword>>21)&1
            s5=(dword>>16)&0x1F
            minop=(dword>>5)&7
            d5=dword&0x1F
            if regtype == 0b0000:
                if bit21 == 0:
                    if majop==0b00:
                        if minop==0b000:
                            i=(dword>>8)&0x3F
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=asr({self.torreg(s5)},#{self.tou(i,6)})"
                        elif minop==0b001:
                            i=(dword>>8)&0x3F
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=lsr({self.torreg(s5)},#{self.tou(i,6)})"
                        elif minop==0b010:
                            i=(dword>>8)&0x3F
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=asl({self.torreg(s5)},#{self.tou(i,6)})"
                        elif minop==0b011:
                            i=(dword>>8)&0x3F
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=rol({self.torreg(s5)},#{self.tou(i,6)})"
                    elif majop==0b01:
                        i = (dword >> 8) & 0x1F
                        bit13 = (dword >> 13) & 1
                        if bit13==0b0:
                            if minop==0b000:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=vasrw({self.torreg(s5)},#{self.tou(i,5)})"
                            elif minop==0b001:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=vlsrw({self.torreg(s5)},#{self.tou(i,5)})"
                            elif minop==0b010:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=vaslw({self.torreg(s5)},#{self.tou(i,5)})"
                        if minop==0b100:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vabsh({self.torreg(s5)})"
                        elif minop==0b101:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vabsh({self.torreg(s5)}):sat"
                        elif minop==0b110:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vabsw({self.torreg(s5)})"
                        elif minop==0b111:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vabsw({self.torreg(s5)}):sat"
                    elif majop==0b10:
                        i=(dword>>8) & 0xF
                        bits12=(dword>>12)&3
                        if bits12==0b00:
                            if minop==0b000:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=vasrh({self.torreg(s5)},#{self.tou(i,4)})"
                            elif minop==0b001:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=neg({self.torreg(s5)})"
                            elif minop==0b010:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=abs({self.torreg(s5)})"
                        if minop==0b100:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=not({self.torreg(s5)})"
                        elif minop==0b101:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=neg({self.torreg(s5)})"
                        elif minop==0b110:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=abs({self.torreg(s5)})"
                        elif minop==0b111:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vconj({self.torreg(s5)}):sat"
                    elif majop==0b11:
                        if minop==0b100:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=deinterleave({self.torreg(s5)})"
                        elif minop==0b101:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=interleave({self.torreg(s5)})"
                        elif minop==0b110:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=brev({self.toreg(s5)})"
                        elif minop==0b111:
                            i=(dword>>8)&0x3F
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=asr({self.torreg(s5)},#{self.tou(i,6)}):rnd"
                elif bit21 == 0b1:
                    bits12=(dword>>12)&3
                    i=(dword>>8)&0xF
                    if bits12==0b00:
                        if majop==0b00:
                            if minop==0b000:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=vasrh({self.torreg(s5)},#{self.tou(i,4)}):raw"
                    if majop==0b11:
                        bit13=(dword>>13)&1
                        s5=(dword>>16)&0x1F
                        if bit13==0b0:
                            if minop==0b000:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=convert_df2d({self.torreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=convert_dfu2d({self.torreg(s5)})"
                            elif minop==0b010:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=convert_ud2df({self.torreg(s5)})"
                            elif minop==0b011:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=convert_d2df({self.torreg(s5)})"
                            elif minop==0b110:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=convert_df2d({self.torreg(s5)}):chop"
                            elif minop==0b111:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=convert_df2ud({self.torreg(s5)}):chop"
            elif regtype==0b0001:
                    i=(dword>>8)&0x3F
                    s5=(dword>>16)&0x1F
                    d5=dword&0x1F
                    l=(((dword>>21)&0x7)<<3)+((dword>>5)&7)
                    self.pushreg(d5,2)
                    return f"{self.torreg(d5)}=extractu({self.torreg(s5)},#{self.tou(i,6)},#{self.tou(l,6)})"
            elif regtype==0b0010:
                #1000001000-sssssPPiiiiii000xxxxx
                s5=(dword>>16)&0x1F
                i=(dword>>8)&0x3F
                minop=(dword>>5)&0x7
                x5=dword&0x1F
                majop=(dword>>22)&3
                if majop==0b00:
                    if minop==0b000:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}-=asr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b001:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}-=lsr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b010:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}-=asl({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b011:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}-=rol({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b100:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}+=asr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b101:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}+=lsr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b110:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}+=asl({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b111:
                        self.pushreg(x5,2)
                        return f"{self.torreg(x5)}+=rol({self.torreg(s5)},#{self.tou(i, 6)})"
                elif majop==0b01:
                    if minop==0b000:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}&=asr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b001:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}&=lsr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b010:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}&=asl({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b011:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}&=rol({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b100:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}|=asr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b101:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}|=lsr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b110:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}|=asl({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b111:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}|=rol({self.torreg(s5)},#{self.tou(i, 6)})"
                elif majop==0b10:
                    if minop==0b001:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}^=lsr({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b010:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}^=asl({self.torreg(s5)},#{self.tou(i, 6)})"
                    elif minop==0b011:
                        self.pushreg(x5, 2)
                        return f"{self.torreg(x5)}^=rol({self.torreg(s5)},#{self.tou(i, 6)})"
            elif regtype==0b0011:
                    i=(dword>>8)&0x3F
                    s5=(dword>>16)&0x1F
                    d5=dword&0x1F
                    l=(((dword>>21)&0x7)<<3)+((dword>>5)&7)
                    self.pushreg(d5,2)
                    return f"{self.torreg(d5)}=insert({self.torreg(s5)},#{self.tou(i,6)},#{self.tou(l,6)})"
            elif regtype==0b0100:
                    if majop==0b00:
                        if (minop >> 1) == 0b00:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vsxtbh({self.toreg(s5)})"
                        elif (minop >> 1) == 0b01:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vzxtbh({self.toreg(s5)})"
                        elif (minop >> 1) == 0b10:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vsxthw({self.toreg(s5)})"
                        elif (minop >> 1) == 0b11:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vzxthw({self.toreg(s5)})"
                    elif majop==0b01:
                        if (minop>>1)==0b00:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=sxtw({self.torreg(s5)})"
                        elif (minop>>1)==0b01:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vsplath({self.toreg(s5)})"
                        if minop==0b011:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=convert_sf2ud({self.toreg(s5)})"
                        elif minop==0b100:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=convert_sf2d({self.toreg(s5)})"
                        elif minop==0b101:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=convert_sf2ud({self.toreg(s5)}):chop"
                        elif minop==0b110:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=convert_sf2d({self.toreg(s5)}):chop"
                    if majop>>1==0b1:
                        if minop==0b000:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=convert_sf2df({self.toreg(s5)})"
                        elif minop==0b001:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=convert_uw2df({self.toreg(s5)})"
                        elif minop==0b010:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=convert_w2df({self.toreg(s5)})"
                    if majop==0b01:
                        if (minop>>1)==0b10:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vsplatb({self.toreg(s5)})"
            elif regtype==0b0101:
                bit21=(dword>>21)&1
                bit13=(dword>>13)&1
                d2 = dword & 3
                if majop==0b00:
                    if bit21==0:
                        if bit13==0b0:
                            self.pushreg(d2)
                            i = (dword >> 8) & 0x1F
                            return f"{self.topreg(d2)}=tstbit({self.toreg(s5)},#{self.tou(i, 5)})"
                    elif bit21==1:
                        if bit13==0b0:
                            self.pushreg(d2)
                            i = (dword >> 8) & 0x1F
                            return f"{self.topreg(d2)}=!tstbit({self.toreg(s5)},#{self.tou(i, 5)})"
                if majop==0b01:
                    if bit21 == 0b0:
                        self.pushreg(d2)
                        return f"{self.topreg(d2)}={self.toreg(s5)}"
                elif majop==0b10:
                    if bit21 == 0b0:
                        self.pushreg(d2)
                        i=(dword>>8)&0x3F
                        return f"{self.topreg(d2)}=bitsclr({self.toreg(s5)},#{self.tou(i, 6)})"
                    elif bit21 == 0b1:
                        self.pushreg(d2)
                        i=(dword>>8)&0x3F
                        return f"{self.topreg(d2)}=!bitsclr({self.toreg(s5)},#{self.tou(i, 6)})"
                elif majop==0b11:
                    if bit21==0b1:
                       if bit13==0b0:
                            self.pushreg(d2)
                            i=(dword>>8)&0x1F
                            return f"{self.topreg(d2)}=sfclass({self.toreg(s5)},#{self.tou(i,5)})"
            elif regtype==0b0110:
                self.pushreg(d5,2)
                t2=(dword>>8)&3
                return f"{self.torreg(d5)}=mask({self.topreg(t2)})"
            elif regtype==0b0111:
                x5=dword&0x1F
                i=(((dword>>21)&1)<<3) + ((dword>>5)&7)
                l=(dword>>8)&0x3F
                if majop==0b00:
                    self.pushreg(x5)
                    return f"{self.toreg(x5)}=tableidxb({self.toreg(s5)},#{self.tou(i,4)},#{self.tos(l,6)}):raw"
                elif majop==0b01:
                    self.pushreg(x5)
                    return f"{self.toreg(x5)}=tableidxh({self.toreg(s5)},#{self.tou(i,4)},#{self.tos(l,6)}):raw"
                elif majop==0b10:
                    self.pushreg(x5)
                    return f"{self.toreg(x5)}=tableidxw({self.toreg(s5)},#{self.tou(i,4)},#{self.tos(l,6)}):raw"
                elif majop==0b11:
                    self.pushreg(x5)
                    return f"{self.toreg(x5)}=tableidxd({self.toreg(s5)},#{self.tou(i,4)},#{self.tos(l,6)}):raw"
            elif regtype==0b1000:
                    if majop == 0b00:
                        if bit21==0b0:
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vsathub({self.torreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_df2sf({self.torreg(s5)})"
                            elif minop==0b010:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vsatwh({self.torreg(s5)})"
                            elif minop==0b100:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vsatwuh({self.torreg(s5)})"
                            elif minop==0b110:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vsathb({self.torreg(s5)})"
                        elif bit21==0b1:
                            if minop==0b000:
                                i = (dword >> 8) & 0x3F
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=add(clb,{self.toreg(s5)},#{self.tos(i, 6)})"
                            elif minop==0b001:
                                i = (dword >> 8) & 0x3F
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_ud2sf({self.toreg(s5)})"
                    elif majop==0b01:
                        if bit21==0:
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=clb({self.torreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_d2sf({self.torreg(s5)})"
                            elif minop==0b010:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=cl0({self.torreg(s5)})"
                            elif minop==0b100:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=cl1({self.torreg(s5)})"
                        elif bit21==1:
                            i=(dword>>8)&0xF
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=normamt({self.torreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_df2uw({self.torreg(s5)})"
                            elif minop==0b010:
                                i=(dword>>8)&0x3F
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=add(clb,{self.torreg(s5)},#{self.tos(i,6)})"
                            elif minop==0b011:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=popcount({self.torreg(s5)})"
                            elif minop==0b100:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vasrhub({self.torreg(s5)},#{self.tou(i,4)}):raw"
                            elif minop==0b101:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vasrhub({self.torreg(s5)},#{self.tou(i,4)}):sat"
                    elif majop==0b10:
                        if bit21==0:
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vtrunohb({self.torreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_df2uw({self.torreg(s5)})"
                            elif minop==0b010:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vtrunehb({self.torreg(s5)})"
                            elif minop==0b100:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vrndwh({self.torreg(s5)})"
                            elif minop==0b110:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vrndwh({self.torreg(s5)}):sat"
                        elif bit21==1:
                            if minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_df2w({self.torreg(s5)})"
                    elif majop==0b11:
                        if bit21==0:
                            if minop == 0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=sat({self.torreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=round({self.torreg(s5)}):sat"
                            elif minop==0b010:
                                i=(dword>>8)&0x1F
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vasrw({self.torreg(s5)},#{self.tou(i,5)})"
                            elif minop==0b100:
                                i=(dword>>8)&0x1F
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=bitsplit({self.toreg(s5)},#{self.tou(i,5)})"
                            elif minop==0b101:
                                self.pushreg(d5)
                                i=(dword>>8)&0x1F #5bit
                                return f"{self.toreg(d5)}=clip({self.toreg(s5)},{self.tou(i,5)})"
                            elif minop==0b110:
                                self.pushreg(d5,2)
                                i=(dword>>8)&0x1F #5bit
                                return f"{self.torreg(d5)}=vclip({self.torreg(s5)},{self.tou(i,5)})"
                        if bit21==1:
                            if minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_df2w({self.torreg(s5)}):chop"
                            elif minop==0b010:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=ct0({self.torreg(s5)})"
                            elif minop==0b100:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=ct1({self.torreg(s5)})"
            elif regtype==0b1001:
                if majop&1==0b1:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}={self.toreg(s5)}"
            elif regtype==0b1010:
                    i=(dword>>8)&0x3F
                    s5=(dword>>16)&0x1F
                    d5=dword&0x1F
                    l=(((dword>>21)&0x7)<<3)+((dword>>5)&7)
                    self.pushreg(d5,2)
                    return f"{self.torreg(d5)}=extract({self.torreg(s5)},#{self.tou(i,6)},#{self.tou(l,6)})"
            elif regtype==0b1011:
                    s5=(dword>>16)&0x1F
                    d5=dword&0x1F
                    minop=(dword>>5)&0x7
                    majop=(dword>>22)&3
                    bit21=(dword>>21)&1
                    if majop==0b00:
                        if bit21==0b1:
                            self.pushreg(d5,2)
                            return f"{self.toreg(d5)}=convert_uw2sf({self.torreg(s5)})"
                    elif majop==0b01:
                        if bit21==0b0:
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_w2sf({self.torreg(s5)})"
                        elif bit21==0b1:
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_sf2uw({self.toreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_sf2uw({self.toreg(s5)}):chop"
                    elif majop==0b10:
                        if bit21==0b0:
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_sf2w({self.toreg(s5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=convert_sf2w({self.toreg(s5)}):chop"
                        elif bit21==0b1:
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=sffixupr({self.toreg(s5)})"
                    elif majop==0b11:
                        if bit21==0b1:
                            bit7=(dword>>7)&1
                            if bit7==0:
                                e2=(dword>>5)&3
                                d5=dword&0x1F
                                self.pushreg(d5)
                                return f"{self.toreg(d5)},{self.topreg(e2)}=sfinvsqrta({self.toreg(s5)})"
            elif regtype==0b1100:
                bit13=(dword>>13)&1
                bit21=(dword>>21)&1
                if majop==0b00:
                    if bit21==0b0:
                        if bit13==0b0:
                            i=(dword>>8)&0x1F
                            if minop==0b000:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=asr({self.toreg(s5)},#{self.tou(i,5)})"
                            elif minop==0b001:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=lsr({self.toreg(s5)},#{self.tou(i,5)})"
                            elif minop==0b010:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=asl({self.toreg(s5)},#{self.tou(i,5)})"
                            elif minop==0b011:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=rol({self.toreg(s5)},#{self.tou(i,5)})"
                        if minop == 0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=clb({self.toreg(s5)})"
                        elif minop == 0b101:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cl0({self.toreg(s5)})"
                        elif minop == 0b110:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cl1({self.toreg(s5)})"
                        elif minop==0b111:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=normamt({self.toreg(s5)})"
                if majop==0b01:
                    if bit21==0b0:
                        if minop==0b000:
                            self.pushreg(d5)
                            i=(dword>>8)&0x1F
                            return f"{self.toreg(d5)}=asr({self.toreg(s5)},#{self.tou(i,5)})"
                        elif minop==0b010:
                            self.pushreg(d5)
                            i=(dword>>8)&0x1F
                            return f"{self.toreg(d5)}=asl({self.toreg(s5)},#{self.tou(i,5)}):sat"
                        elif minop==0b110:
                            #10001100010sssssPP-----110ddddd
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=brev({self.toreg(s5)})"
                        elif minop==0b111:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vsplatb({self.toreg(s5)})"
                elif majop==0b10:
                    if bit21==0b0:
                        if minop==0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=abs({self.toreg(s5)})"
                        elif minop==0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=abs({self.toreg(s5)}):sat"
                        elif minop==0b110:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=neg({self.toreg(s5)}):sat"
                        elif minop==0b111:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=swiz({self.toreg(s5)})"
                elif majop==0b11:
                    i = (dword >> 8) & 0x1F
                    if bit21==0b0:
                        if minop==0b000:
                            if bit13==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=setbit({self.toreg(s5)},{self.tou(i,5)})"
                        elif minop==0b001:
                            if bit13==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=clrbit({self.toreg(s5)},{self.tou(i,5)})"
                        elif minop==0b010:
                            if bit13==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=togglebit({self.toreg(s5)},{self.tou(i,5)})"
                        elif minop==0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sath({self.toreg(s5)})"
                        elif minop==0b101:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=satuh({self.toreg(s5)})"
                        elif minop==0b110:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=satub({self.toreg(s5)})"
                        elif minop==0b111:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=satb({self.toreg(s5)})"
                    elif bit21==0b1:
                        if minop==0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=ct0({self.toreg(s5)})"
                        elif minop==0b101:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=ct1({self.toreg(s5)})"
            elif regtype==0b1101:
                    bit13=(dword>>13)&1
                    i=(dword>>8)&0x1F
                    s5 = (dword >> 16) & 0x1F
                    d5 = dword & 0x1F
                    l = (((dword >> 21) & 0x3) << 3) + ((dword >> 5) & 7)
                    if bit13==0b0:
                        if majop>>1==0b0:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=extractu({self.torreg(s5)},#{self.tou(i, 5)},#{self.tou(l, 5)})"
                        elif majop>>1==0b1:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=extract({self.torreg(s5)},#{self.tou(i, 5)},#{self.tou(l, 5)})"
                    elif bit13==0b1:
                        bit23=(dword>>23)&1
                        if bit23==0b0:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mask({self.torreg(s5)},#{self.tou(i, 5)},#{self.tou(l, 5)})"
            elif regtype==0b1110:
                #1000111000-sssssPP0iiiii000xxxxx
                s5=(dword>>16)&0x1F
                i=(dword>>8)&0x1F
                bit13=(dword>>13)&1
                minop=(dword>>5)&0x7
                x5=dword&0x1F
                majop=(dword>>22)&3
                if majop==0b00:
                    if bit13==0b0:
                        if minop==0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=asr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=lsr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b010:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=asl({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b011:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=rol({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b100:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=asr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b101:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=lsr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b110:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=asl({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b111:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=rol({self.toreg(s5)},#{self.tou(i, 5)})"
                elif majop==0b01:
                    if bit13==0b0:
                        if minop==0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=asr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=lsr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b010:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=asl({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b011:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=rol({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b100:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=asr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b101:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=lsr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b110:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=asl({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b111:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=rol({self.toreg(s5)},#{self.tou(i, 5)})"
                elif majop==0b10:
                    if bit13==0b00:
                        if minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}^=lsr({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b010:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}^=asl({self.toreg(s5)},#{self.tou(i, 5)})"
                        elif minop==0b011:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}^=rol({self.toreg(s5)},#{self.tou(i, 5)})"
            elif regtype==0b1111:
                    bit13=(dword>>13)&1
                    bit23 = (dword >> 23) & 1
                    i=(dword>>8)&0x1F
                    s5=(dword>>16)&0x1F
                    d5=dword&0x1F
                    l=(((dword>>21)&0x3)<<3)+((dword>>5)&7)
                    if bit13==0b0:
                        if bit23==0b0:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=insert({self.torreg(s5)},#{self.tou(i,5)},#{self.tou(l,5)})"
        elif iclass==0b1100:
            regtype = (dword >> 24) & 0xF
            bit21 = (dword >> 21) & 1
            maj = (dword>>22)&3

            s5 = (dword >> 16) & 0x1F
            d5=dword&0x1F
            t5=(dword>>8)&0x1F
            x2=(dword>>5)&3
            if regtype == 0b0000:
                if (maj>>1)&1==0b0:
                    #110000000--sssssPP-tttttiiiddddd
                    i=(dword>>5)&7
                    self.pushreg(d5,2)
                    return f"{self.torreg(d5)}=valignb({self.torreg(t5)},{self.torreg(s5)},#{self.tou(i,3)})"
                elif (maj>>1)&1==0b1:
                    i=(dword>>5)&7
                    self.pushreg(d5,2)
                    return f"{self.torreg(d5)}=vspliceb({self.torreg(t5)},{self.torreg(s5)},#{self.tou(i,3)})"
            elif regtype==0b0001:
                if maj==0b00:
                    mmin = (dword >> 6) & 3
                    if mmin==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=extractu({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=shuffeb({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=shuffob({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=shuffeh({self.torreg(s5)},{self.torreg(t5)})"
                elif maj==0b01:
                    mmin=(dword>>6)&3
                    bit5=(dword>>5)&1
                    if mmin==0b00:
                        if bit5 == 0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vxaddsubw({self.torreg(s5)},{self.torreg(t5)}):sat"
                        elif bit5 == 0b1:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vaddhub({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif mmin==0b01:
                        if bit5 == 0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vxsubaddw({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif mmin==0b10:
                        if bit5 == 0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vxaddsubh({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif mmin==0b11:
                        if bit5 == 0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vxsubaddh({self.torreg(s5)},{self.torreg(t5)}):sat"
                elif maj==0b10:
                    mmin = (dword >> 6) & 3
                    bit5=(dword>>5)&1
                    if mmin==0b00:
                        if bit5 == 0b0:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=shuffoh({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin==0b01:
                        if bit5 == 0b0:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vtrunewh({self.torreg(s5)},{self.torreg(t5)})"
                        elif bit5 == 0b1:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vtrunehb({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin==0b10:
                        if bit5 == 0b0:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vtrunowh({self.torreg(s5)},{self.torreg(t5)})"
                        elif bit5 == 0b1:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vtrunohb({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin == 0b11:
                        if bit5 == 0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=lfs({self.torreg(s5)},{self.torreg(t5)})"
                elif maj==0b11:
                    mmin = (dword >> 6) & 3
                    if mmin == 0b00:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vxaddsubh({self.torreg(s5)},{self.torreg(t5)}):rnd:>>1:sat"
                    elif mmin == 0b01:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vxsubaddh({self.torreg(s5)},{self.torreg(t5)}):rnd:>>1:sat"
                    elif mmin == 0b10:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=extract({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin == 0b11:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=decbin({self.torreg(s5)},{self.torreg(t5)})"
            elif regtype==0b0010:
                if (maj>>1)&1==0b0:
                    u2=(dword>>5)&3
                    self.pushreg(d5, 2)
                    return f"{self.torreg(d5)}=valignb({self.torreg(t5)},{self.torreg(s5)},{self.topreg(u2)})"
                if maj==0b10:
                    if bit21==0b0:
                        self.pushreg(d5, 2)
                        u2=(dword>>5)&3
                        return f"{self.torreg(d5)}=vspliceb({self.torreg(s5)},{self.torreg(t5)},{self.topreg(u2)})"
                if maj==0b11:
                    if bit21==0b0:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)},{self.topreg(x2)}):carry"
                    elif bit21==0b1:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=sub({self.toreg(s5)},{self.toreg(t5)},{self.topreg(x2)}):carry"
            elif regtype==0b0011:
                mmin = (dword >> 6) & 3
                if maj==0b00:
                    if mmin==0b00:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vasrw({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vlsrw({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vaslw({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b11:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vlslw({self.torreg(s5)},{self.toreg(t5)})"
                elif maj==0b01:
                    if mmin==0b00:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vasrh({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vlsrh({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vaslh({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b11:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vlslh({self.torreg(s5)},{self.toreg(t5)})"
                elif maj==0b10:
                    if mmin==0b00:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=asr({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=lsr({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=asl({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b11:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=lsl({self.torreg(s5)},{self.toreg(t5)})"
                elif maj==0b11:
                    if mmin==0b00:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vcrotate({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vcnegh({self.torreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b11:
                        self.pushreg(d5,2)
                        i=(((dword>>13)&1)<<1)+((dword>>5)&1)
                        return f"{self.torreg(d5)}=vrcrotate({self.torreg(s5)},{self.toreg(t5)},#{self.tou(i,2)})"
            elif regtype==0b0100:
                if maj==0b00:
                    if bit21==0b0:
                        bit13=(dword>>13)&1
                        if bit13==0b0:
                            i=(dword>>5)&7
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=addasl({self.toreg(t5)},{self.toreg(s5)},#{self.tou(i, 3)})"
            elif regtype==0b0101:
                #11000101---sssssPP-ttttt100ddddd
                s5=(dword>>16)&0x1F
                t5=(dword>>8)&0x1F
                mmin=(dword>>6)&3
                bit5=(dword>>5)&1
                if mmin==0b01:
                    if bit5==0b0:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=vasrw({self.torreg(s5)},{self.toreg(t5)})"
                if mmin==0b10:
                    if bit5==0b0:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=cmpyiwh({self.torreg(s5)},{self.toreg(t5)}):<<1:rnd:sat"
                    elif bit5==0b1:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=cmpyiwh({self.torreg(s5)},{self.toreg(t5)}*):<<1:rnd:sat"
                elif mmin==0b11:
                    if bit5==0b0:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=cmpyrwh({self.torreg(s5)},{self.toreg(t5)}):<<1:rnd:sat"
                    elif bit5==0b1:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=cmpyrwh({self.torreg(s5)},{self.toreg(t5)}*):<<1:rnd:sat"
            elif regtype==0b0110:
                mmin = (dword >> 6) & 3
                if maj==0b00:
                    if mmin==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=asr({self.toreg(s5)},{self.toreg(t5)}):sat"
                    elif mmin==0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=asl({self.toreg(s5)},{self.toreg(t5)}):sat"
                elif maj==0b01:
                    if mmin==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=asr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=lsr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=asl({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=lsl({self.toreg(s5)},{self.toreg(t5)})"
                elif maj==0b10:
                    if mmin==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=setbit({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=clrbit({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=togglebit({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b11:
                        i=(((dword>>16)&0x1f)<<1)+((dword>>5)&1)
                        t5=(dword>>8)&0x1F
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=lsl({self.tos(i,6)},{self.toreg(t5)})"
                elif maj==0b11:
                    if mmin==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=cround({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=cround({self.torreg(s5)},{self.torreg(t5)})"
                    elif mmin==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=round({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin==0b11:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=round({self.toreg(s5)},{self.toreg(t5)}):sat"
            elif regtype==0b0111:
                mmin = (dword >> 6) & 3
                bit21=(dword>>21)&1
                d2=dword&3
                if maj==0b00:
                    if bit21==0b0:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=tstbit({self.toreg(s5)},{self.toreg(t5)})"
                    elif bit21==0b1:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=!tstbit({self.toreg(s5)},{self.toreg(t5)})"
                if maj==0b01:
                    #11000111010sssssPP-ttttt------dd
                    if bit21==0b0:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=bitset({self.toreg(s5)},{self.toreg(t5)})"
                    elif bit21==0b1:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=!bitset({self.toreg(s5)},{self.toreg(t5)})"
                elif maj==0b10:
                    #11000111010sssssPP-ttttt------dd
                    if bit21==0b0:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=bitclr({self.toreg(s5)},{self.toreg(t5)})"
                    elif bit21==0b1:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=!bitclr({self.toreg(s5)},{self.toreg(t5)})"
                elif maj==0b11:
                    bit5 = (dword >> 5) & 1
                    if bit21==0b0:
                        if mmin==0b01:
                            if bit5==0b0:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=cmpb.gt({self.toreg(s5)},{self.toreg(t5)})"
                            elif bit5==0b1:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=cmph.eq({self.toreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b10:
                            if bit5==0b0:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=cmph.gt({self.toreg(s5)},{self.toreg(t5)})"
                            elif bit5==0b1:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=cmpb.gtu({self.toreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b11:
                            if bit5==0b0:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=cmpb.eq({self.toreg(s5)},{self.toreg(t5)})"
                            elif bit5==0b1:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=cmpb.gtu({self.toreg(s5)},{self.toreg(t5)})"
                    if bit21==0b1:
                        if mmin==0b00:
                            if bit5==0b0:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=sfcmp.ge({self.toreg(s5)},{self.toreg(t5)})"
                            elif bit5==0b1:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=sfcmp.uo({self.toreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b01:
                            if bit5==0b1:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=sfcmp.eq({self.toreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b10:
                            if bit5==0b0:
                                self.pushreg(d2)
                                return f"{self.toreg(d2)}=sfcmp.gt({self.toreg(s5)},{self.toreg(t5)})"
            elif regtype==0b1000:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=insert({self.toreg(s5)},{self.torreg(t5)})"
            elif regtype==0b1001:
                mmin = (dword >> 6) & 3
                if maj==0b00:
                    if mmin==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=extractu({self.toreg(s5)},{self.torreg(t5)})"
                    elif mmin==0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=extract({self.toreg(s5)},{self.torreg(t5)})"
            elif regtype==0b1010:
                mmin = (dword>>6)&3
                x5=dword&0x1F
                if maj>>1==0b0:
                    self.pushreg(x5, 2)
                    return f"{self.torreg(x5)}^=xor({self.torreg(s5)},{self.torreg(t5)})"
                if maj==0b10:
                    bit13=(dword>>13)&1
                    bit5=(dword>>5)&1
                    if bit13==0 and bit5==0:
                        if mmin==0b00:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}^=xor({self.torreg(s5)},{self.torreg(t5)})"
            elif regtype==0b1011:
                mmin = (dword>>6)&3
                u5=dword&0x1F
                x5=(dword>>8)&0x1F
                bit21=(dword>>21)&1
                if bit21==1:
                    if maj==0b00:
                        bit13=(dword>>13)&1
                        bit5=(dword>>5)&1
                        if bit5==1:
                            if bit13==0:
                                if mmin==0b00:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrmaxh({self.torreg(s5)},{self.toreg(u5)})"
                                elif mmin==0b10:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrminh({self.torreg(s5)},{self.toreg(u5)})"
                            elif bit13==1:
                                if mmin==0b00:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrmaxuh({self.torreg(s5)},{self.toreg(u5)})"
                                elif mmin==0b10:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrminuh({self.torreg(s5)},{self.toreg(u5)})"
                                elif mmin==0b11:
                                    t5 = (dword >> 8) & 0x1F
                                    x5 = dword & 0x1F
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}+=vrcnegh({self.torreg(s5)},{self.toreg(t5)})"
                        elif bit5==0:
                            if bit13==0:
                                if mmin==0b01:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrmaxw({self.torreg(s5)},{self.toreg(u5)})"
                                elif mmin==0b11:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrminw({self.torreg(s5)},{self.toreg(u5)})"
                            elif bit13==1:
                                if mmin==0b01:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrmaxuw({self.torreg(s5)},{self.toreg(u5)})"
                                elif mmin==0b11:
                                    self.pushreg(x5,2)
                                    return f"{self.torreg(x5)}=vrminuw({self.torreg(s5)},{self.toreg(u5)})"
                    elif maj==0b01:
                        t5 = (dword >> 8) & 0x1F
                        s5 = (dword >> 16) & 0x1F
                        x5 = dword & 0x1F
                        if mmin==0b00:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}^=asr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b01:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}^=lsr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b10:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}^=asl({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b11:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}^=lsl({self.torreg(s5)},{self.toreg(t5)})"
                    elif maj==0b10:
                        self.pushreg(x5, 2)
                        i = (((dword >> 13) & 1) << 1) + ((dword >> 5) & 1)
                        return f"{self.torreg(d5)}+=vrcrotate({self.torreg(s5)},{self.toreg(t5)},#{self.tou(i, 2)})"
                elif bit21==0b0:
                    t5=(dword>>8)&0x1F
                    s5=(dword>>16)&0x1F
                    x5=dword&0x1F
                    if maj==0b00:
                        if mmin==0b00:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}|=asr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b01:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}|=lsr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b10:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}|=asl({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b11:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}|=lsl({self.torreg(s5)},{self.toreg(t5)})"
                    elif maj==0b01:
                        if mmin==0b00:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}&=asr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b01:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}&=lsr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b10:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}&=asl({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b11:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}&=lsl({self.torreg(s5)},{self.toreg(t5)})"
                    elif maj==0b10:
                        if mmin==0b00:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=asr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b01:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=lsr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b10:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=asl({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b11:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=lsl({self.torreg(s5)},{self.toreg(t5)})"
                    elif maj==0b11:
                        if mmin==0b00:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=asr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b01:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=lsr({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b10:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=asl({self.torreg(s5)},{self.toreg(t5)})"
                        elif mmin==0b11:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=lsl({self.torreg(s5)},{self.toreg(t5)})"
            elif regtype==0b1100:
                maj = (dword>>22)&3
                mmin=(dword>>6)&3
                t5 = (dword >> 8) & 0x1F
                s5 = (dword >> 16) & 0x1F
                x5=dword&0x1F
                if maj == 0b00:
                    if mmin == 0b00:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}|=asr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b01:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}|=lsr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b10:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}|=asl({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b11:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}|=lsl({self.toreg(s5)},{self.toreg(t5)})"
                elif maj == 0b01:
                    if mmin == 0b00:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}&=asr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b01:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}&=lsr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b10:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}&=asl({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b11:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}&=lsl({self.toreg(s5)},{self.toreg(t5)})"
                elif maj == 0b10:
                    if mmin == 0b00:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}-=asr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b01:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}-=lsr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b10:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}-=asl({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b11:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}-=lsl({self.toreg(s5)},{self.toreg(t5)})"
                elif maj == 0b11:
                    if mmin == 0b00:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}+=asr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b01:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}+=lsr({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b10:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}+=asl({self.toreg(s5)},{self.toreg(t5)})"
                    elif mmin == 0b11:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}+=lsl({self.toreg(s5)},{self.toreg(t5)})"

            elif regtype==0b1111:
                majop=(dword>>21)&7
                bit13=(dword>>13)&1
                minop=(dword>>5)&7
                if bit13==0:
                    if majop==0b000:
                        if minop==0b011:
                            x5=dword&0x1F
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=sub({self.toreg(t5)},{self.toreg(s5)})"
        elif iclass==0b1101:
            #110110110iisssssPPidddddiiiuuuuu
            regtype = (dword >> 24) & 0xF
            majop = (dword >> 22) & 3
            bit23 = (dword>>23)&1
            bit13 = (dword >> 13) & 1
            s5 = (dword >> 16) & 0x1F
            minop = (dword >> 5) & 7
            d5 = (dword>>8) & 0x1F
            if regtype==0b0000:
                t5 = (dword >> 8) & 0x1F
                self.pushreg(d5)
                return f"{self.toreg(d5)}=parity({self.torreg(s5)},{self.torreg(t5)})"
            elif regtype==0b0001:
                t5 = (dword >> 8) & 0x1F
                u2= (dword>>5)&3
                d5=dword&0x1f
                s5=(dword>>16)&0x1F
                self.pushreg(d5,2)
                return f"{self.torreg(d5)}=vmux({self.topreg(u2)},{self.torreg(s5)},{self.torreg(t5)})"
            elif regtype==0b0010:
                bits21 = (dword >> 21) & 0x7
                t5 = (dword >> 8) & 0x1F
                d2 = dword&3
                if bit23==0b0:
                    if bit13==0b1:
                        if minop==0b000:
                            self.pushreg(d2,3)
                            return f"{self.topreg(d2)}=any8(vcmpb.eq({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(d2,3)
                            return f"{self.topreg(d2)}=any8(vcmpb.eq({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(d2,3)
                            return f"{self.topreg(d2)}=vcmpb.gt({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(d2,3)
                            return f"{self.topreg(d2)}=tlbmatch({self.torreg(s5)},{self.toreg(t5)})"
                        elif minop==0b100:
                            #110100100--sssssPP1ttttt100---dd
                            self.pushreg(d2,3)
                            return f"{self.topreg(d2)}=boundscheck({self.torreg(s5)},{self.torreg(t5)}):raw:lo"
                        elif minop==0b101:
                            #110100100--sssssPP1ttttt100---dd
                            self.pushreg(d2,3)
                            return f"{self.topreg(d2)}=boundscheck({self.torreg(s5)},{self.torreg(t5)}):raw:hi"
                    elif bit13==0b0:
                        if minop==0b000:
                            self.pushreg(d2, 3)
                            return f"{self.topreg(d2)}=vcmpw.eq({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(d2, 3)
                            return f"{self.topreg(d2)}=vcmpw.gt({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(d2, 3)
                            return f"{self.topreg(d2)}=vcmpw.gtu({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b110:
                            self.pushreg(d2, 3)
                            return f"{self.topreg(d2)}=vcmpb.eq({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b111:
                            self.pushreg(d2, 3)
                            return f"{self.topreg(d2)}=vcmpb.gtu({self.torreg(s5)},{self.torreg(t5)})"
                if bits21==0b000:
                    bits3=(dword>>3)&3
                    i=(dword>>5)&0xFF
                    if bits3==0b01:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=vcmph.eq({self.torreg(s5)},{self.tos(i,8)})"
                elif bits21==0b001:
                    bits3=(dword>>3)&3
                    i=(dword>>5)&0xFF
                    if bits3==0b01:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=vcmph.gt({self.torreg(s5)},{self.tos(i,8)})"
                elif bits21==0b010:
                    bits3=(dword>>3)&3
                    bit12=(dword>>12)&1
                    if bits3==0b01:
                        if bit12==0b0:
                            self.pushreg(d2,3)
                            i=(dword>>5)&0x7F
                            return f"{self.topreg(d2)}=vcmph.gtu({self.torreg(s5)},{self.tou(i,7)})"
                elif bits21==0b100:
                    if minop==0b000:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=cmp.eq({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b010:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=cmp.gt({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b100:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=cmp.gtu({self.torreg(s5)},{self.torreg(t5)})"
                elif bits21==0b111:
                    if minop==0b000:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=dfcmp.eq({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b001:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=dfcmp.gt({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b010:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=dfcmp.ge({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b011:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=dfcmp.uo({self.torreg(s5)},{self.torreg(t5)})"
            elif regtype==0b0011: #doublewords
                bits21=(dword>>21)&0x7
                minop=(dword>>5)&0x7
                t5=(dword>>8)&0x1F
                if bits21==0b000:
                    if minop==0b000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vaddub({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b001:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vaddub({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif minop==0b010:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vaddh({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b011:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vaddh({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif minop==0b100:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vadduh({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif minop==0b101:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vaddw({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b110:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vaddw({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif minop==0b111:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=add({self.torreg(s5)},{self.torreg(t5)})"
                elif bits21==0b001:
                    if minop==0b000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vsubub({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b001:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vsubub({self.torreg(t5)},{self.torreg(s5)}):sat"
                    elif minop==0b010:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vsubh({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b011:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vsubh({self.torreg(t5)},{self.torreg(s5)}):sat"
                    elif minop==0b100:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vsubuh({self.torreg(t5)},{self.torreg(s5)}):sat"
                    elif minop==0b101:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vsubw({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b110:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vsubw({self.torreg(t5)},{self.torreg(s5)}):sat"
                    elif minop==0b111:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=sub({self.torreg(t5)},{self.torreg(s5)})"
                elif bits21 == 0b010:
                    if minop==0b000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgub({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b001:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgub({self.torreg(s5)},{self.torreg(t5)}):rnd"
                    elif minop==0b010:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgh({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b011:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgh({self.torreg(s5)},{self.torreg(t5)}):rnd"
                    elif minop==0b100:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgh({self.torreg(s5)},{self.torreg(t5)}):crnd"
                    elif minop==0b101:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavguh({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop>>1==0b11:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vavguh({self.torreg(s5)},{self.torreg(t5)}):rnd"
                elif bits21==0b011:
                    if minop==0b000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgw({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b001:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgw({self.torreg(s5)},{self.torreg(t5)}):rnd"
                    elif minop==0b010:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgw({self.torreg(s5)},{self.torreg(t5)}):cmd"
                    elif minop==0b011:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavguw({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b100:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavguw({self.torreg(s5)},{self.torreg(t5)}):rnd"
                    elif minop==0b101:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=add({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif minop==0b110:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=add({self.torreg(s5)},{self.torreg(t5)}):raw:lo"
                    elif minop==0b111:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.toreg(s5)},{self.toreg(t5)}):raw:hi"
                elif bits21 == 0b100:
                    if minop==0b000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgh({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b001:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgh({self.torreg(t5)},{self.torreg(s5)}):rnd:sat"
                    elif minop==0b010:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vavgh({self.torreg(t5)},{self.torreg(s5)}):cmd:sat"
                    elif minop==0b011:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vnavgw({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop>>1==0b10:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vnavgw({self.torreg(t5)},{self.torreg(s5)}):rnd:sat"
                    elif minop>>1==0b11:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vnavgw({self.torreg(t5)},{self.torreg(s5)}):cmd:sat"
                elif bits21 == 0b101:
                    if minop==0b000:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vminub({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b001:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vminh({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b010:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vminuh({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b011:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=vminw({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b100:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vminuw({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b101:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vmaxuw({self.torreg(t5)},{self.torreg(s5)})"
                elif bits21==0b110:
                    if minop==0b000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vmaxub({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b001:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vmaxh({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b010:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vmaxuh({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b011:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vmaxw({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b110:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vmaxb({self.torreg(t5)},{self.torreg(s5)})"
                    elif minop==0b111:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=vminb({self.torreg(t5)},{self.torreg(s5)})"
                elif bits21==0b111:
                    if minop==0b000:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=and({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b001:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=and({self.torreg(t5)},~{self.torreg(s5)})"
                    elif minop==0b010:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=or({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b011:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=or({self.torreg(t5)},~{self.torreg(s5)})"
                    elif minop==0b100:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=xor({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b111:
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=modwrap({self.torreg(s5)},{self.torreg(t5)})"
                elif bits21==0b101:
                    if minop==0b110:
                        #11010011110sssssPP-ttttt100ddddd
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=min({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b111:
                        #11010011110sssssPP-ttttt101ddddd
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=minu({self.torreg(s5)},{self.torreg(t5)})"
                elif bits21==0b110:
                    if minop==0b100:
                        #11010011110sssssPP-ttttt100ddddd
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=max({self.torreg(s5)},{self.torreg(t5)})"
                    elif minop==0b101:
                        #11010011110sssssPP-ttttt101ddddd
                        self.pushreg(d5,2)
                        return f"{self.torreg(d5)}=maxu({self.torreg(s5)},{self.torreg(t5)})"
            elif regtype==0b0100:
                #11010100--1sssssPP-ttttt---ddddd
                bit21=(dword>>21)&1
                t5=(dword>>8)&0x1F
                if bit21==0b1:
                    self.pushreg(d5, 2)
                    return f"{self.torreg(d5)}=bitsplit({self.toreg(s5)},{self.toreg(t5)})"
            elif regtype==0b0101: #words
                bits21=(dword>>21)&0x7
                minop=(dword>>5)&0x7
                t5=(dword>>8)&0x1F
                if bits21==0b000:
                    if (minop>>1)==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.L)"
                    elif (minop>>1)==0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.H)"
                    elif (minop>>1)==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.L):sat"
                    elif (minop>>1)==0b11:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.H):sat"
                elif bits21==0b001:
                    if (minop>>1)==0b00:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.L)"
                    elif (minop>>1)==0b01:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.H)"
                    elif (minop>>1)==0b10:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.L):sat"
                    elif (minop>>1)==0b11:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.H):sat"
                elif bits21==0b010:
                    if minop==0b000:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.L):<<16"
                    elif minop==0b001:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.H):<<16"
                    elif minop==0b010:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.H,{self.torreg(s5)}.L):<<16"
                    elif minop==0b011:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.H,{self.torreg(s5)}.H):<<16"
                    elif minop==0b100:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.L):sat:<<16"
                    elif minop==0b101:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.L,{self.torreg(s5)}.H):sat:<<16"
                    elif minop==0b110:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.H,{self.torreg(s5)}.L):sat:<<16"
                    elif minop==0b111:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=add({self.torreg(t5)}.H,{self.torreg(s5)}.H):sat:<<16"
                elif bits21==0b011:
                    if minop==0b000:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.L):<<16"
                    elif minop==0b001:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.H):<<16"
                    elif minop==0b010:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.H,{self.torreg(s5)}.L):<<16"
                    elif minop==0b011:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.H,{self.torreg(s5)}.H):<<16"
                    elif minop==0b100:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.L):sat:<<16"
                    elif minop==0b101:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.L,{self.torreg(s5)}.H):sat:<<16"
                    elif minop==0b110:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.H,{self.torreg(s5)}.L):sat:<<16"
                    elif minop==0b111:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.torreg(t5)}.H,{self.torreg(s5)}.H):sat:<<16"
                elif bits21==0b100:
                    if (minop>>2)==0:
                        self.pushreg(d5)
                        return f"{self.torreg(d5)}=add({self.torreg(s5)},{self.torreg(t5)}):sat:deprecated"
                    elif (minop>>2)==0b1:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=sub({self.toreg(t5)},{self.toreg(s5)}):sat:deprecated"
                elif bits21==0b101:
                    if (minop>>2)==0b0:
                        #11010101110sssssPP-ttttt0--ddddd
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=min({self.toreg(s5)},{self.toreg(t5)})"
                    elif (minop>>2)==0b1:
                        #11010101110sssssPP-ttttt1--ddddd
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=minu({self.toreg(s5)},{self.toreg(t5)})"
                elif bits21==0b110:
                    if (minop>>2)==0b0:
                        #11010101110sssssPP-ttttt0--ddddd
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=max({self.toreg(s5)},{self.toreg(t5)})"
                    elif (minop>>2)==0b1:
                        #11010101110sssssPP-ttttt1--ddddd
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=maxu({self.toreg(s5)},{self.toreg(t5)})"
                elif bits21==0b111:
                    self.pushreg(d5)
                    t5 = (dword >> 8) & 0x1F
                    return f"{self.toreg(d5)}=parity({self.toreg(s5)},{self.toreg(t5)})"
            elif regtype==0b0110:
                #11010100--1sssssPP-ttttt---ddddd
                bits22 = (dword >> 22) & 3
                i = (((dword >> 21) & 1) << 9) + ((dword >> 5) & 0x1FF)
                if bits22==0b00:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=sfmake(#{self.tou(i,10)}):pos"
                elif bits22==0b01:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=sfmake(#{self.tou(i,10)}):neg"
            elif regtype==0b0111:
                #110101110iissssPPittttiiiddddd
                bit23=(dword>>23)&1
                s5=(dword>>16)&0x1F
                t5=(dword>>8)&0x1F
                if bit23==0b0:
                    i=(((dword>>21)&0x3)<<4)+(((dword>>13)&1)<<3)+((dword>>5)&7)
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=add(#{self.tou(i,6)},mpyi({self.toreg(s5)},{self.toreg(t5)}))"
            elif regtype==0b1000:
                #11010111iiissssPPittttiiilllll
                bit23=(dword>>23)&1
                s5=(dword>>16)&0x1F
                d5=(dword>>8)&0x1F
                l6=(bit23<<5)+(dword&0x1F)
                i=(((dword>>21)&0x7)<<4)+(((dword>>13)&1)<<3)+((dword>>5)&7)
                self.pushreg(d5)
                return f"{self.toreg(d5)}=add(#{self.tou(i,6)},mpyi({self.toreg(s5)},#{self.tou(l6,6)}))"
            elif regtype==0b1001:
                bits22 = (dword >> 22) & 3
                i = (((dword >> 21) & 1) << 9) + (dword >> 5) & 0x1FF
                if bits22==0b00:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=dfmake(#{self.tou(i,10)}):pos"
                elif bits22==0b01:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=dfmake(#{self.tou(i,10)}):neg"
                bits21=(dword>>21)&3
                if bits21==0b00:
                    self.pushreg(d5)
                    s2=(dword>>16)&3
                    t2=(dword>>8)&3
                    return f"{self.toreg(d5)}=vitpack({self.topreg(s2)},{self.topreg(t2)})"
            elif regtype==0b1010:
                #1101101000isssssPPiiiiiiiiixxxxx
                bits22=(dword>>22)&3
                i=(((dword>>21)&1)<<9)+((dword>>5)&0x1FF)
                if bits22==0b00:
                    s5=(dword>>16)&0x1F
                    x5=dword&0x1F
                    self.pushreg(x5)
                    return f"{self.toreg(x5)}|=and({self.toreg(s5)},#{self.tos(i,10)})"
                elif bits22==0b01:
                    x5=(dword>>16)&0x1F
                    u5=dword&0x1F
                    self.pushreg(x5)
                    return f"{self.toreg(x5)}|=or({self.toreg(u5)},and({self.toreg(x5)},#{self.tos(i,10)})"
                elif bits22==0b10:
                    s5=(dword>>16)&0x1F
                    x5=dword&0x1F
                    self.pushreg(x5)
                    return f"{self.toreg(x5)}|=or({self.toreg(s5)},#{self.tos(i,10)})"
            elif regtype==0b1011:
                bit23=(dword>>23)&1
                s5=(dword>>16)&0x1F
                d5=(dword>>8)&0x1F
                i = (((dword >> 21) & 0x7) << 4) + (((dword >> 13) & 1) << 3) + ((dword >> 5) & 7)
                if bit23==0:
                    u5=dword & 0x1F
                    i=(((dword>>21)&3)<<4) + (bit13<<3) + ((dword>>5)&7) #6bit
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=add({self.toreg(s5)},add({self.toreg(u5)},#{self.tos(i,6)}))"
                elif bit23==1:
                    u5=dword & 0x1F
                    i=(((dword>>21)&3)<<4) + (bit13<<3) + ((dword>>5)&7) #6bit
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=add({self.toreg(s5)},sub(#{self.tos(i,6)},{self.toreg(u5)}))"
            elif regtype==0b1100:
                #10001100111sssssPP0iiiii00-ddddd
                majop=(dword>>22)&3
                bits21=(dword>>21)&7
                s5=(dword>>16)&0x1F
                minop=(dword>>5)&7
                d5=dword&0x1F
                if bits21==0b000:
                    bit3=(dword>>3)&3
                    if bit3==0b00:
                        i=(dword>>5)&0xFF
                        d2=dword&0x3
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=vcmpb.eq({self.torreg(s5)},#{self.tou(i, 8)})"
                    elif bit3==0b10:
                        i=(dword>>5)&0xFF
                        d2=dword&0x3
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=vcmpw.eq({self.torreg(s5)},#{self.tos(i, 8)})"
                elif bits21==0b001:
                    bit3=(dword>>3)&3
                    if bit3==0b00:
                        i=(dword>>5)&0xFF
                        d2=dword&0x3
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=vcmpb.gt({self.torreg(s5)},#{self.tos(i, 8)})"
                    elif bit3==0b10:
                        i=(dword>>5)&0xFF
                        d2=dword&0x3
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=vcmpw.gt({self.torreg(s5)},#{self.tos(i, 8)})"
                elif bits21==0b111:
                        bit13=(dword>>13)&1
                        if bit13==0b0:
                            i=(dword>>8)&0x1F
                            if (minop>>1)==0b00:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=cround({self.toreg(s5)},#{self.tou(i,5)})"
                            elif (minop>>1)==0b01:
                                i=(dword>>8)&0x3F
                                self.pushreg(d5)
                                return f"{self.torreg(d5)}=cround({self.toreg(s5)},#{self.tou(i,6)})"
                            elif (minop>>1)==0b10:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=round({self.toreg(s5)},#{self.tou(i,5)})"
                            elif (minop>>1)==0b11:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=round({self.toreg(s5)},#{self.tou(i,5)}):sat"
                elif bits21==0b010:
                        bit10=(dword>>10)&7
                        d2=dword&3
                        bit3 = (dword >> 3) & 3
                        bit12 = (dword>>12)&1
                        if bit12==0b0:
                            if bit3==0b00:
                                i = (dword >> 5) & 0x7F
                                d2 = dword & 0x3
                                self.pushreg(d2, 3)
                                return f"{self.topreg(d2)}=vcmpb.gtu({self.torreg(s5)},#{self.tou(i, 7)})"
                            elif bit3==0b10:
                                i = (dword >> 5) & 0x7F
                                d2 = dword & 0x3
                                self.pushreg(d2, 3)
                                return f"{self.topreg(d2)}=vcmpw.gtu({self.torreg(s5)},#{self.tou(i, 7)})"
                        if bit10==0b000:
                            bits3=(dword>>3)&3
                            if bits3==0b10:
                                self.pushreg(d2)
                                i=(dword>>5)&0x1F
                                return f"{self.toreg(d2)}=dfclass({self.torreg(s5)},#{self.tou(i, 5)}):sat"
            elif regtype==0b1101:
                #11011101-00sssssPP-iiiiiiii00-dd
                bits21=(dword>>21)&3
                s5=(dword>>16)&0x1F
                minop=(dword>>5)&7
                d2=dword&0x3
                bits3 = (dword >> 3) & 3
                i = (dword >> 5) & 0xFF
                if bits21==0b00:
                    if bits3==0b00:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmpb.eq({self.toreg(s5)},#{self.tou(i, 8)})"
                    elif bits3==0b01:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmph.eq({self.toreg(s5)},#{self.tou(i, 8)})"
                elif bits21==0b01:
                    if bits3==0b00:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmpb.gt({self.toreg(s5)},#{self.tou(i, 8)})"
                    elif bits3==0b01:
                        self.pushreg(d2)
                        return f"{self.toreg(d2)}=cmph.gt({self.toreg(s5)},#{self.tou(i, 8)})"
                elif bits21==0b10:
                    bit12 = (dword >> 12) & 1
                    i = (dword >> 5) & 0x7F
                    if bits3==0b00:
                        if bit12==0b0:
                            self.pushreg(d2)
                            return f"{self.toreg(d2)}=cmpb.gtu({self.toreg(s5)},#{self.tou(i, 7)})"
                    elif bits3==0b01:
                        if bit12==0b0:
                            self.pushreg(d2)
                            return f"{self.toreg(d2)}=cmph.gtu({self.toreg(s5)},#{self.tou(i, 7)})"
            elif regtype==0b1110:
                #11011110iiixxxxxPPillllliii0i10-
                i8=(((dword>>21)&7)<<5)+(((dword>>13)&1)<<4)+(((dword>>5)&7)<<1)+((dword>>3)&1) #8bit
                l5=(dword>>8)&0x1F
                x5=(dword>>16)&0x1F
                bit4=(dword>>4)&1
                bits1=(dword>>1)&3
                if bit4==0b0:
                    if bits1==0b00:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=and({self.tou(i8,8)},asl({self.toreg(x5)},#{self.tou(l5,5)}))"
                    elif bits1==0b01:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=or({self.tou(i8,8)},asl({self.toreg(x5)},#{self.tou(l5,5)}))"
                    elif bits1==0b10:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=add({self.tou(i8,8)},asl({self.toreg(x5)},#{self.tou(l5,5)}))"
                    elif bits1==0b11:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=sub({self.tou(i8,8)},asl({self.toreg(x5)},#{self.tou(l5,5)}))"
                elif bit4==0b1:
                    if bits1==0b00:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=and({self.tou(i8,8)},lsr({self.toreg(x5)},#{self.tou(l5,5)}))"
                    elif bits1==0b01:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=or({self.tou(i8,8)},lsr({self.toreg(x5)},#{self.tou(l5,5)}))"
                    elif bits1==0b10:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=add({self.tou(i8,8)},lsr({self.toreg(x5)},#{self.tou(l5,5)}))"
                    elif bits1==0b11:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}=sub({self.tou(i8,8)},lsr({self.toreg(x5)},#{self.tou(l5,5)}))"
            elif regtype==0b1111:
                #110111110iisssssPPidddddiiiuuuuu
                bit23=(dword>>23)&1
                u5=dword&0x1F
                i=(((dword>>21)&3)<<4)+(((dword>>13)&1)<<3)+((dword>>5)&7) #6bit
                d5=(dword>>8)&0x1F
                s5=(dword>>16)&0x1F
                if bit23==0b0:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=add({self.toreg(u5)},mpyi(#{self.tou(i, 6)}:2,{self.toreg(s5)}))"
                elif bit23==0b1:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=add({self.toreg(u5)},mpyi({self.toreg(s5)},#{self.tou(i, 6)}))"
        elif iclass==0b1110:
            #111000100--sssssPP0iiiiiiiixxxxx
            regtype = (dword >> 24) & 0xF
            bit23 = (dword >> 23) & 1
            bit13 = (dword >> 13) & 1
            s5 = (dword >> 16) & 0x1F
            x5=dword&0x1F
            i=(dword>>5)&0xFF
            majop = (dword >> 21) & 3
            minop=(dword>>5)&7
            if regtype==0b0000:
                d5 = dword & 0x1F
                s5 = (dword >> 16) & 0x1F
                i = (dword >> 5) & 0xFF
                if bit13==0:
                    if (majop >> 2) == 0:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}+=mpyi({self.toreg(s5)},{self.tos(i, 8)})"
                    elif (majop >> 2) == 1:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}-=mpyi({self.toreg(s5)},{self.tos(i, 8)})"
            elif regtype==0b0001:
                x5 = dword & 0x1F
                s5 = (dword >> 16) & 0x1F
                i = (dword >> 5) & 0xFF
                if bit13==0:
                    if (majop >> 2) == 0:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}+=mpyi({self.toreg(s5)},{self.tos(i, 8)})"
                    elif (majop >> 2) == 1:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}-=mpyi({self.toreg(s5)},{self.tos(i, 8)})"
            elif regtype==0b0010:
                if bit13 == 0:
                    if (majop>>2)==0:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}+=add({self.toreg(s5)},{self.tos(i, 8)})"
                    elif (majop>>2)==1:
                        self.pushreg(x5)
                        return f"{self.toreg(x5)}-=add({self.toreg(s5)},{self.tos(i, 8)})"
            elif regtype==0b0011:
                if majop==0b000:
                    y5=(dword>>8)&0x1F
                    u5=dword&0x1F
                    s5=(dword>>16)&0x1F
                    self.pushreg(y5)
                    return f"{self.toreg(y5)}=add({self.toreg(u5)},mpyi({self.toreg(y5)},{self.toreg(s5)})"
            elif regtype==0b0100:
                #11100100N00sssssPP-ttttt-00ddddd
                N=(dword>>23)&1
                s5=(dword>>16)&0x1F
                t5=(dword>>8)&0x1F
                sH=(dword>>6)&1
                tH=(dword>>5)&1
                d5=dword&0x1F
                majop=(dword>>21)&3
                if majop==0b00:
                    if sH==0b0:
                        if tH==0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                        elif tH==0b1:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif sH==0b1:
                        if tH==0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                        elif tH==0b1:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                elif majop==0b01:
                    if sH==0b0:
                        if tH==0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]:rnd"
                        elif tH==0b1:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]:rnd"
                    elif sH==0b1:
                        if tH==0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]:rnd"
                        elif tH==0b1:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]:rnd"
                elif majop==0b10:
                    if sH==0b0:
                        if tH==0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                        elif tH==0b1:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif sH==0b1:
                        if tH==0b0:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                        elif tH==0b1:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
            elif regtype==0b0101:
                #11100101N00sssssPP0ttttt110ddddd
                N=(dword>>23)&1
                majop=(dword>>21)&7
                s5=(dword>>16)&0x1F
                bit13=(dword>>13)&1
                t5=(dword>>8)&0x1F
                minop=(dword>>5)&7
                d5=dword&0x1F
                if bit13 == 0b0:
                    if majop & 3 == 0b00:
                        if majop == 0b000:
                            if minop == 0b000:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)})"
                            elif minop == 0b001:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=cmpyi({self.toreg(s5)},{self.toreg(t5)})"
                            elif minop == 0b010:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=cmpyr({self.toreg(s5)},{self.toreg(t5)})"
                            elif minop == 0b101:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=vmpyh({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:sat"
                            elif minop==0b110:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=cmpy({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:sat"
                            elif minop==0b111:
                                self.pushreg(d5,2)
                                return f"{self.torreg(d5)}=vmpyhsu({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:sat"
                    elif majop&3==0b10:
                        if minop==0b110:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=cmpy({self.toreg(s5)},{self.toreg(t5)}*)[:<<{str(N)}]:sat"
                    if majop==0b010:
                        if minop == 0b000:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=mpyu({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop == 0b001:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpybsu({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b111:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=pmpyw({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b100:
                        if minop == 0b001:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpybu({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b110:
                        if minop == 0b111:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vpmpyh({self.toreg(s5)},{self.toreg(t5)})"
            elif regtype==0b0110:
                #11100100N00sssssPP-ttttt000ddddd
                N=(dword>>23)&1
                bit7=(dword>>7)&1
                s5=(dword>>16)&0x1F
                t5=(dword>>8)&0x1F
                sH=(dword>>6)&1
                tH=(dword>>5)&1
                x5=dword&0x1F
                majop=(dword>>21)&3
                if bit7==0b0:
                    if majop==0b00:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif majop==0b01:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif majop==0b10:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}+=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif majop==0b11:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.torreg(x5)}-=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
            elif regtype==0b0111:
                #11100101N00sssssPP0ttttt110xxxxx
                N=(dword>>23)&1
                majop=(dword>>21)&3
                s5=(dword>>16)&0x1F
                bit13=(dword>>13)&1
                t5=(dword>>8)&0x1F
                minop=(dword>>5)&7
                x5=dword&0x1F
                if bit13 == 0b0:
                    if majop & 3 == 0b00:
                        if minop == 0b101:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyh({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:sat"
                        elif minop == 0b110:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=cmpy({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:sat"
                        elif minop == 0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=cmpy({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:sat"
                    elif majop & 3 == 0b10:
                        if minop == 0b110:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=cmpy({self.toreg(s5)},{self.toreg(t5)}*)[:<<{str(N)}]:sat"
                        elif minop == 0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=cmpy({self.toreg(s5)},{self.toreg(t5)}*)[:<<{str(N)}]:sat"
                    elif majop & 3 == 0b11:
                        if minop == 0b101:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyhsu({self.toreg(s5)},{self.toreg(t5)}*)[:<<{str(N)}]:sat"
                    if majop==0b000:
                        if minop == 0b000:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=mpy({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop == 0b001:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=cmpyi({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop == 0b010:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=cmpyr({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b001:
                        if minop == 0b000:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=mpy({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop == 0b001:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyh({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}^=pmpyw({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b010:
                        if minop == 0b000:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=mpyu({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b011:
                        if minop == 0b000:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}-=mpyu({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b100:
                        if minop == 0b001:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpybu({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b101:
                        if minop == 0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}^=vpmpyh({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b110:
                        if minop == 0b001:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpybsu({self.toreg(s5)},{self.toreg(t5)})"
            elif regtype==0b1000:
                d5 = dword & 0x1F
                t5=(dword>>8)&0x1F
                if bit13==0b0:
                    if majop==0b000:
                        if minop==0b000:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrcmpyi({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrcmpyr({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrmpyh({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=dfadd({self.torreg(s5)},{self.torreg(t5)})"
                    elif majop==0b001:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vabsdiffw({self.torreg(t5)},{self.torreg(s5)})"
                        elif minop==0b011:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=dfmax({self.torreg(s5)},{self.torreg(t5)})"
                    elif majop==0b010:
                        if minop==0b000:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vrcmpyi({self.torreg(s5)},{self.torreg(t5)}*)"
                        elif minop==0b001:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vraddub({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrsadub({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=dfmpyfix({self.torreg(s5)},{self.torreg(t5)})"
                    elif majop==0b011:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vabsdiffh({self.torreg(t5)},{self.torreg(s5)})"
                        elif minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vrcmpyr({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=cmpyiw({self.torreg(t5)},{self.torreg(s5)})"
                    elif majop==0b100:
                        if minop==0b001:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrmpybu({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=cmpyrw({self.torreg(t5)},{self.torreg(s5)})"
                        elif minop==0b011:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=dfsub({self.torreg(s5)},{self.torreg(t5)})"
                    elif majop==0b101:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vabsdiffub({self.torreg(t5)},{self.torreg(s5)})"
                        elif minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vdmpybsu({self.torreg(s5)},{self.torreg(t5)}):sat"
                        elif minop==0b011:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=dfmpyll({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b100:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrcmpys({self.torreg(s5)},{self.torreg(t5)}):<<1:sat:raw:hi"
                    elif majop==0b110:
                        if minop==0b001:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrmpybsu({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=cmpyrw({self.torreg(t5)},{self.torreg(s5)}*)"
                        elif minop==0b011:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=dfmin({self.torreg(s5)},{self.torreg(t5)})"
                    elif majop==0b111:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vabsdiffb({self.torreg(t5)},{self.torreg(s5)})"
                        elif minop==0b010:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=cmpyiw({self.torreg(t5)},{self.torreg(s5)}*)"
                        elif minop==0b100:
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)}=vrcmpys({self.torreg(s5)},{self.torreg(t5)}):<<1:sat:raw:lo"
                    if majop & 3 == 0b00:
                        # 11101000N01sssssPP0ttttt110ddddd
                        N = (dword >> 23) & 1
                        if minop==0b100:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vdmpy({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b101:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpyweh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b110:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpyeh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b111:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpywoh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                    elif majop & 3 == 0b01:
                        # 11101000N01sssssPP0ttttt110ddddd
                        N = (dword >> 23) & 1
                        if minop==0b010:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vrmpywoh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]"
                        elif minop==0b101:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpyweh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
                        elif minop==0b110:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vcmpyr({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b111:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpywoh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
                    elif majop & 3 == 0b10:
                        # 11101000N01sssssPP0ttttt110ddddd
                        N = (dword >> 23) & 1
                        if minop==0b100:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vrmpyweh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]"
                        elif minop==0b101:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpyweuh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b110:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vcmpyi({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b111:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpywouh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                    elif majop & 3 == 0b11:
                        # 11101000N01sssssPP0ttttt110ddddd
                        N = (dword >> 23) & 1
                        if minop==0b101:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpyweuh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
                        elif minop==0b111:
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vmpywouh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
            elif regtype==0b1001:
                d5 = dword & 0x1F
                t5=(dword>>8)&0x1F
                if bit13==0b0:
                    if (majop>>2)==0b0:
                        if majop==0b000:
                            if minop==0b100:
                                self.pushreg(d5, 2)
                                return f"{self.torreg(d5)}=cmpyiw({self.torreg(t5)},{self.torreg(s5)}*):<<1:sat"
                        if (minop&3)==0b01:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vradduh({self.torreg(s5)},{self.torreg(t5)})"
                        elif (dword>>21)&1==1:
                            if minop==0b111:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=vraddh({self.torreg(s5)},{self.torreg(t5)})"
                    if majop==0b001:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyiw({self.torreg(s5)},{self.torreg(t5)}):<<1:sat"
                    elif majop==0b010:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyrw({self.torreg(s5)},{self.torreg(t5)}):<<1:sat"
                    elif majop==0b011:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyrw({self.torreg(s5)},{self.torreg(t5)}*):<<1:sat"
                    elif majop==0b100:
                        if minop==0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyiw({self.torreg(s5)},{self.torreg(t5)}*):<<1:sat"
                    elif majop==0b101:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyiw({self.torreg(s5)},{self.torreg(t5)}):<<1:sat"
                    elif majop==0b110:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyrw({self.torreg(s5)},{self.torreg(t5)}):<<1:rnd:sat"
                    elif majop==0b111:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyrw({self.torreg(s5)},{self.torreg(t5)}*):<<1:rnd:sat"
                    if (majop>>2)&1==0b1 and (majop&1)==0b1:
                        if minop==0b110:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vrcmpys({self.torreg(s5)},{self.torreg(t5)}*):<<1:rnd:sat:hi"
                        elif minop==0b111:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vrcmpys({self.torreg(s5)},{self.torreg(t5)}*):<<1:rnd:sat:lo"
                    if (majop&3==0b00):
                        N = (dword >> 23) & 1
                        if minop==0b000:
                            #11101001N00sssssPP0ttttt000ddddd
                            self.pushreg(d5, 2)
                            return f"{self.torreg(d5)}=vdmpy({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
            elif regtype==0b1010:
                t5=(dword>>8)&0x1F
                if bit13==0b0:
                    if majop==0b000:
                        if minop==0b000:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrcmpyi({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrcmpyr({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrmpyh({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=dfmpylh({self.torreg(s5)},{self.torreg(t5)})"
                    if majop==0b001:
                        if minop==0b001:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vdmpybsu({self.torreg(s5)},{self.torreg(t5)}):sat"
                        elif minop==0b010:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyeh({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b100:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vcmpyr({self.torreg(s5)},{self.torreg(t5)}):sat"
                    elif majop==0b010:
                        if minop==0b000:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=vrcmpyi({self.torreg(s5)},{self.torreg(t5)}*)"
                        elif minop==0b001:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=vraddub({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=vrsadub({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b100:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=vcmpyi({self.torreg(s5)},{self.torreg(t5)}):sat"
                        elif minop==0b110:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=cmpyiw({self.torreg(s5)},{self.torreg(t5)}*)"
                    elif majop==0b011:
                        if minop==0b001:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrcmpyr({self.torreg(s5)},{self.torreg(t5)}*)"
                        elif minop==0b010:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=cmpyiw({self.torreg(s5)},{self.torreg(t5)})"
                    elif majop==0b100:
                        if minop==0b001:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=vrmpybu({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=cmpyrw({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=dfmpyhh({self.torreg(s5)},{self.torreg(t5)})"
                    elif majop==0b101:
                        bit7=(dword>>7)&1
                        minop=(dword>>5)&7
                        if bit7==0:
                            #11101010101sssssPP0ttttt0eexxxxx
                            x5=dword&0x1F
                            t5=(dword>>8)&0x1F
                            e2=(dword>>5)&3
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)},{self.topreg(e2)}=vacsh({self.torreg(s5)},{self.torreg(t5)})"
                        if minop==0b100:
                            x5 = dword & 0x1F
                            t5 = (dword >> 8) & 0x1F
                            s5 = (dword>>16) & 0x1F
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrcmpys({self.torreg(s5)},{self.torreg(t5)})<<1:sat:raw:hi"
                    elif majop==0b110:
                        if minop==0b001:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=vrmpybsu({self.torreg(s5)},{self.torreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(x5,2)
                            return f"{self.torreg(x5)}+=cmpyrw({self.torreg(s5)},{self.torreg(t5)}*)"
                    elif majop==0b111:
                        bit7=(dword>>7)&1
                        if bit7==0:
                            #11101010101sssssPP0ttttt0eexxxxx
                            d5=dword&0x1F
                            t5=(dword>>8)&0x1F
                            e2=(dword>>5)&3
                            self.pushreg(d5,2)
                            return f"{self.torreg(d5)},{self.topreg(e2)}=vminub({self.torreg(t5)},{self.torreg(s5)})"
                        if minop==0b100:
                            x5 = dword & 0x1F
                            t5 = (dword >> 8) & 0x1F
                            s5 = (dword>>16) & 0x1F
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrcmpys({self.torreg(s5)},{self.torreg(t5)})<<1:sat:raw:lo"
                    if majop&0x3==0b00:
                        N=(dword>>23)&1
                        x5=dword&0x1F
                        if minop==0b100:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vdmpy({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b101:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyweh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop==0b110:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyeh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop == 0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpywoh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                    elif majop&0x3==0b01:
                        N=(dword>>23)&1
                        x5=dword&0x1F
                        if minop==0b101:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyweh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
                        elif minop == 0b110:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrmpyweh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]"
                        elif minop == 0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpywoh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
                    elif majop&0x3==0b10:
                        N=(dword>>23)&1
                        x5=dword&0x1F
                        if minop==0b101:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyweuh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                        elif minop == 0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpywouh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:sat"
                    elif majop&0x3==0b11:
                        N=(dword>>23)&1
                        x5=dword&0x1F
                        if minop==0b101:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpyweuh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
                        elif minop == 0b110:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vrmpywoh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]"
                        elif minop == 0b111:
                            self.pushreg(x5, 2)
                            return f"{self.torreg(x5)}+=vmpywouh({self.torreg(s5)},{self.torreg(t5)})[:<<{(str(N))}]:rnd:sat"
            elif regtype==0b1011:
                d5 = dword & 0x1F
                t5 = (dword >> 8) & 0x1F
                majop=(dword>>21)&0x7
                if bit13==0b0:
                    if majop==0b000:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sfadd({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sfsub({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b010:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sfmpy({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b100:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sfmax({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sfmin({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b110:
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sffixupn({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=sffixupd({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b111:
                        bit7=(dword>>7)&1
                        if bit7==0b1:
                            e2=(dword>>5)&3
                            d5=dword&0x1f
                            t5=(dword>>8)&0x1F
                            s5=(dword>>16)&0x1f
                            self.pushreg(d5)
                            return f"{self.toreg(d5)},{self.topreg(e2)}=sfrecipa({self.toreg(s5)},{self.toreg(t5)})"
            elif regtype==0b1100:
                #11100100N00sssssPP-ttttt000ddddd
                N=(dword>>23)&1
                bit7=(dword>>7)&1
                s5=(dword>>16)&0x1F
                t5=(dword>>8)&0x1F
                sH=(dword>>6)&1
                tH=(dword>>5)&1
                d5=dword&0x1F
                majop=(dword>>21)&3
                if majop==0b00:
                    if bit7 == 0b0:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif bit7 == 0b1:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]:rnd"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]:rnd"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]:rnd"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]:rnd"
                elif majop==0b01:
                    if bit7 == 0b0:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]:sat"
                            elif tH==0b1:
                                self.pushreg(x5,2)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]:sat"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]:sat"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]:sat"
                    elif bit7 == 0b1:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]:rnd:sat"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]:rnd:sat"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]:rnd:sat"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]:rnd:sat"
                elif majop==0b10:
                    if bit7 == 0b0:
                        if sH==0b0:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH==0b1:
                            if tH==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH==0b1:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
            elif regtype==0b1101:
                # 11100101N00sssssPP0ttttt110xxxxx
                N = (dword >> 23) & 1
                majop = (dword >> 21) & 3
                s5 = (dword >> 16) & 0x1F
                bit13 = (dword >> 13) & 1
                bit7=(dword>>7)&1
                bit22=(dword>>22)&1
                t5 = (dword >> 8) & 0x1F
                minop = (dword >> 5) & 7
                d5 = dword & 0x1F
                if bit13 == 0b0:
                    if majop & 3 == 0b01:
                        if minop == 0b110:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyi({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:rnd:sat"
                        elif minop == 0b111:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=vmpyh({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]:rnd:sat"
                    elif majop &3 == 0b11:
                        if minop == 0b110:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=cmpyi({self.toreg(s5)},{self.toreg(t5)}*)[:<<{str(N)}]:rnd:sat"
                    if majop==0b000:
                        d5=dword&0x1F
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpyi({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b001:
                        d5=dword&0x1F
                        if minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)}):rnd"
                    elif majop==0b010:
                        d5=dword&0x1F
                        if minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpyu({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b011:
                        d5=dword&0x1F
                        if minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpysu({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b101:
                        d5=dword&0x1F
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)}.H):<<1:sat"
                        elif minop==0b001:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)}.L):<<1:sat"
                        elif minop==0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)}.L):<<1:rnd:sat"
                    elif majop==0b111:
                        d5=dword&0x1F
                        if minop==0b000:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)}):<<1:sat"
                        elif minop==0b100:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)}.L):<<1:rnd:sat"
                    if bit7==0b0 and bit22==0b0:
                        N=(((dword>>23)&1)<<3)+(((dword>>21)&1)<<2)+((dword>>5)&3)
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=mpy({self.toreg(s5)},{self.toreg(t5)})[:<<{str(N)}]"
            elif regtype==0b1110:
                # 11100100N00sssssPP-ttttt000ddddd
                N = (dword >> 23) & 1
                bit7 = (dword >> 7) & 1
                s5 = (dword >> 16) & 0x1F
                t5 = (dword >> 8) & 0x1F
                sH = (dword >> 6) & 1
                tH = (dword >> 5) & 1
                x5 = dword & 0x1F
                majop = (dword >> 21) & 3
                if majop == 0b00:
                    if bit7 == 0b0:
                        if sH == 0b0:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH == 0b1:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif bit7 == 0b1:
                        if sH == 0b0:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]:sat"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]:sat"
                        elif sH == 0b1:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]:sat"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]:sat"
                elif majop == 0b01:
                    if bit7==0b0:
                        if sH == 0b0:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}-=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5, 2)
                                return f"{self.toreg(x5)}-=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH == 0b1:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}-=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}-=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                    elif bit7==0b1:
                        if sH == 0b0:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]:sat"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]:sat"
                        elif sH == 0b1:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]:sat"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}=mpy({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]:sat"
                elif majop == 0b10:
                    if bit7 == 0b0:
                        if sH == 0b0:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH == 0b1:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}+=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
                elif majop == 0b11:
                    if bit7==0b0:
                        if sH == 0b0:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}-=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5, 2)
                                return f"{self.toreg(x5)}-=mpyu({self.toreg(s5)}.L,{self.toreg(t5)}.H[:<<{str(N)}]"
                        elif sH == 0b1:
                            if tH == 0b0:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}-=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.L[:<<{str(N)}]"
                            elif tH == 0b1:
                                self.pushreg(x5)
                                return f"{self.toreg(x5)}-=mpyu({self.toreg(s5)}.H,{self.toreg(t5)}.H[:<<{str(N)}]"
            elif regtype==0b1111:
                minop = (dword >> 5) & 7
                t5=(dword>>8)&0x1F
                if bit13==0:
                    if majop==0b000:
                        if minop == 0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=mpyi({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=add({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b100:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=sfmpy({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b101:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=sfmpy({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b110:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=sfmpy({self.toreg(s5)},{self.toreg(t5)}):lib"
                        elif minop==0b111:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=sfmpy({self.toreg(s5)},{self.toreg(t5)}):lib"
                    elif majop==0b001:
                        if minop==0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=and({self.toreg(s5)},~{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=and({self.toreg(s5)},~{self.toreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}^=and({self.toreg(s5)},~{self.toreg(t5)})"
                    elif majop==0b010:
                        if minop==0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=and({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=or({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}&=xor({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=and({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b011:
                        bit7=(dword>>7)&1
                        if bit7==0b1:
                            u2=(dword>>5)&3
                            x5=dword&0x1F
                            t5=(dword>>8)&0x1F
                            s5=(dword>>16)&0x1F
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=sfmpy({self.toreg(s5)},{self.toreg(t5)},{self.topreg(u2)}):scale"
                        if minop==0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}+=mpy({self.toreg(s5)},{self.toreg(t5)}):<<1:sat"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=mpy({self.toreg(s5)},{self.toreg(t5)}):<<1:sat"
                    elif majop==0b100:
                        if minop == 0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=mpyi({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}-=add({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}^=xor({self.toreg(s5)},{self.toreg(t5)})"
                    elif majop==0b110:
                        if minop==0b000:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=or({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b001:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}|=xor({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b010:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}^=and({self.toreg(s5)},{self.toreg(t5)})"
                        elif minop==0b011:
                            self.pushreg(x5)
                            return f"{self.toreg(x5)}^=or({self.toreg(s5)},{self.toreg(t5)})"

        return "Error"

    def system(self, iclass, dword):
        if iclass==0b0101:
            bits21=(dword>>21)&0x7F
            d5=dword&0x1F
            s5=(dword>>16)&0x1F
            bits11=(dword>>11)&0x7
            if bits21==0b0101101:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=icdatar({self.toreg(s5)})"
            elif bits21 == 0b0101111:
                self.pushreg(d5)
                return f"{self.toreg(d5)}=ictagr({self.toreg(s5)})"
            elif bits21 == 0b0101110:
                bit13=(dword>>13)&1
                t5 = (dword >> 8) & 0x1F
                if bit13==0b0:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=ictagw({self.toreg(s5)},{self.toreg(t5)})"
                elif bit13==0b1:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=icdataw({self.toreg(s5)},{self.toreg(t5)})"
            elif bits21 == 0b0110110:
                if bits11==0b000:
                    self.pushreg(None)
                    return f"icinva({self.toreg(s5)})"
                if bits11==0b001:
                    self.pushreg(d5)
                    return f"{self.toreg(d5)}=icinvidx({self.toreg(s5)})"
                elif bits11 == 0b010:
                    return f"ickill"
            elif bits21==0b0111111:
                bits12=(dword>>12)&3
                bits16=(dword>>16)&0x3F
                if bits12==0b00:
                    bits5=(dword>>5)&7
                    if bits5==0b000:
                        self.pushreg(None)
                        return f"rte"
                if bits16==0b000000:
                    bits13=(dword>>13)&1
                    if bits13==0b0:
                        bits0=dword&0x3FF
                        if bits0==0b0000000010:
                            self.pushreg(None)
                            return f"isync"
            if (bits21 >> 1) == 0b010000:
                i=(((dword>>8)&0x1F)<<3)+((dword>>2)&7)
                self.pushreg(None)
                return f"trap0({self.tou(i,8)})"
            elif (bits21 >> 1) == 0b010001:
                i=(((dword>>8)&0x1F)<<3)+((dword>>2)&7)
                self.pushreg(None)
                return f"pause({self.tou(i,8)})"
            elif (bits21 >> 1) == 0b010010:
                i=(((dword>>8)&0x1F)<<3)+((dword>>2)&7)
                x5=(dword>>16)&0x1F
                self.pushreg(None)
                return f"trap1({self.toreg(x5)},#{self.tou(i,8)})"
        elif iclass==0b0110:
            bit27=(dword>>27)&1
            sm=(dword>>26)&1
            bits21=(dword>>21)&0x1F
            s5=(dword>>16)&0x1F
            d5=dword&0x1F
            bits5 = (dword >> 5) & 0x7

            if bit27==0b0:
                if sm == 0b0:
                    if bits21==0b10000:
                        self.pushreg(d5, 4)
                        return f"{self.togreg(d5)}={self.toreg(s5)}"
                    elif bits21==0b10010:
                        if bits5==0b000:
                            self.pushreg(None)
                            return f"trace({self.toreg(s5)})"
                        elif bits5==0b001:
                            self.pushreg(None)
                            return f"diag({self.toreg(s5)})"
                        elif bits5==0b010:
                            self.pushreg(None)
                            return f"diag0({self.toreg(s5)})"
                        elif bits5==0b011:
                            self.pushreg(None)
                            return f"diag1({self.toreg(s5)})"
                    elif bits21==0b11000:
                        self.pushreg(d5, 5)
                        return f"{self.togrreg(d5)}={self.torreg(s5)}"
                elif sm == 0b1:
                    if bits21==0b00000:
                        if bits5==0b000:
                            self.pushreg(None)
                            return f"swi({self.toreg(s5)})"
                        elif bits5==0b001:
                            self.pushreg(None)
                            return f"cswi({self.toreg(s5)})"
                        elif bits5==0b010:
                            self.pushreg(None)
                            return f"iassignw({self.toreg(s5)})"
                        elif bits5==0b011:
                            self.pushreg(None)
                            return f"ciad({self.toreg(s5)})"
                    elif bits21==0b00001:
                        if bits5==0b001:
                            self.pushreg(None)
                            return f"tlblock"
                        elif bits5==0b010:
                            self.pushreg(None)
                            return f"tlbunlock"
                        elif bits5==0b011:
                            self.pushreg(None)
                            return f"k0lock"
                        elif bits5==0b100:
                            self.pushreg(None)
                            return f"k0unlock"
                    elif bits21==0b00010:
                        if bits5 == 0b000:
                            self.pushreg(None)
                            return f"wait({self.toreg(s5)})"
                        elif bits5==0b001:
                            self.pushreg(None)
                            return f"resume({self.toreg(s5)})"
                    elif bits21==0b00011:
                        if bits5 == 0b000:
                            self.pushreg(None)
                            return f"stop({self.toreg(s5)})"
                        elif bits5 == 0b001:
                            self.pushreg(None)
                            return f"start({self.toreg(s5)})"
                        elif bits5==0b010:
                            self.pushreg(None)
                            return f"nmi({self.toreg(s5)})"
                    elif bits21==0b00100:
                        t2 = (dword >> 8) & 3
                        if bits5==0b000:
                            self.pushreg(None)
                            return f"setimask({self.topreg(t2)},{self.toreg(s5)})"
                        elif bits5==0b001:
                            self.pushreg(None)
                            return f"setprio({self.topreg(t2)},{self.toreg(s5)})"
                        elif bits5==0b011:
                            self.pushreg(None)
                            return f"siad({self.toreg(s5)})"
                    elif bits21==0b01000:
                        x5=(dword>>16)&0x1F
                        self.pushreg(None)
                        return f"crswap({self.toreg(x5)},sgp0)"
                    elif bits21==0b01001:
                        x5=(dword>>16)&0x1F
                        self.pushreg(None)
                        return f"crswap({self.toreg(x5)},sgp1)"
                    elif bits21==0b10000:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=getimask({self.torreg(s5)})"
                    elif bits21==0b10011:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=iassignr({self.torreg(s5)})"
                    if (bits21>>1)==0b0110:
                        x5=(dword>>16)&0x1F
                        v=dword&0x1F
                        if v==0b00000:
                            self.pushreg(None)
                            return f"crswap({self.torreg(x5)},sgp1:0)"
                    elif (bits21>>1)==0b1100:
                        d7 = dword & 0x7F
                        self.pushreg(d7,5)
                        return f"{self.tosreg(d7)}={self.toreg(s5)}"
                    elif (bits21>>1)==0b0100:
                        d7 = dword & 0x7F
                        self.pushreg(d7,6)
                        return f"{self.tosrreg(d7)}={self.torreg(s5)}"
            elif bit27==0b1:
                if sm == 0b0:
                    if bits21==0b00001:
                        self.pushreg(d5, 4)
                        return f"{self.torreg(s5)}={self.togrreg(d5)}"
                    elif bits21==0b10001:
                        self.pushreg(d5, 5)
                        return f"{self.toreg(s5)}={self.togreg(d5)}"
                elif sm == 0b1:
                    bit13 = (dword >> 13) & 1
                    t5 = (dword >> 8) & 0x1F
                    d5 = dword & 0x1F
                    s5 = (dword >> 16) & 0x1F
                    if bits21 == 0b00000:
                        if bit13 == 0:
                            self.pushreg(None)
                            return f"tlbw({self.torreg(s5)},{self.toreg(t5)})"
                    elif bits21 == 0b00001:
                        if bits5==0b000:
                            self.pushreg(None)
                            return f"brkpt"
                    elif bits21 == 0b00010:
                        self.pushreg(d5, 2)
                        return f"{self.torreg(d5)}=tlbr({self.toreg(s5)})"
                    elif bits21 == 0b00100:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=tlbp({self.toreg(s5)})"
                    elif bits21 == 0b00101:
                        self.pushreg(None)
                        return f"tlbinvasid({self.toreg(s5)})"
                    elif bits21 == 0b00110:
                        if bit13 == 0b0:
                            self.pushreg(d5)
                            return f"{self.toreg(d5)}=ctlbw({self.torreg(s5)},{self.toreg(t5)})"
                    elif bits21 == 0b00111:
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=tlboc({self.torreg(s5)})"
                    if (bits21 >> 2) == 0b101:
                        s7 = (dword >> 16) & 0x7F
                        self.pushreg(d5, 5)
                        return f"{self.tosreg(d5)}={self.toreg(s7)}"
                    elif (bits21 >> 2) == 0b110:
                        s7 = (dword >> 16) & 0x7F
                        self.pushreg(d5, 6)
                        return f"{self.tosrreg(d5)}={self.torreg(s7)}"
        elif iclass==0b1001:
            amode=(dword>>25)&0x7
            atype=(dword>>22)&0x7
            UN=(dword>>21)&1
            s5=(dword>>16)&0x1F
            t5=(dword>>8)&0x1F
            d5=dword&0x1F
            bits5=(dword>>5)&3
            bit13=(dword >> 13) & 1
            if amode==0b001:
                if atype==0b000:
                    if bit13==0b0:
                        if bits5==0b00:
                            if UN==0b0:
                                bits12 = (dword >> 12) & 3
                                if bits12==0b00:
                                    self.pushreg(d5)
                                    return f"{self.toreg(d5)}=memw_locked({self.toreg(s5)})"
                                elif bits12==0b01:
                                    self.pushreg(d5,2)
                                    return f"{self.torreg(d5)}=memd_locked({self.toreg(s5)})"

                    elif bit13==0b1:
                        if bits5==0b00:
                            if UN==0b0:
                                self.pushreg(d5)
                                return f"{self.toreg(d5)}=memw_phys({self.toreg(s5)},{self.toreg(t5)})"
            elif amode==0b010:
                if atype == 0b000:
                    if UN==0b0:
                        if bit13==0b0:
                            i=dword&0x7FF
                            self.pushreg(None)
                            return f"dcfetch({self.toreg(s5)}+#{self.tou(i,11)}:3)"
        elif iclass==0b1010:
            amode=(dword>>25)&0x7
            atype=(dword>>22)&0x7
            UN=(dword>>21)&1
            s5=(dword>>16)&0x1F
            t5=(dword>>8)&0x1F
            if amode==0b000:
                d2 = dword & 3
                if atype==0b000:
                  if UN==0b0:
                      self.pushreg(None)
                      return f"dccleana({self.toreg(s5)})"
                  elif UN==0b1:
                      self.pushreg(None)
                      return f"dcinva({self.toreg(s5)})"
                elif atype==0b001:
                  if UN==0b0:
                      self.pushreg(None)
                      return f"dccleaninva({self.toreg(s5)})"
                elif atype==0b010:
                    if UN==0b1:
                        self.pushreg(None)
                        return f"memw_locked({self.toreg(s5)},{self.topreg(d2)})={self.toreg(t5)}"
                elif atype==0b011:
                    bit13 = (dword >> 13) & 1
                    if UN==0b0:
                        if bit13 == 0b0:
                            self.pushreg(None)
                            return f"dczeroa({self.toreg(s5)})"
                    elif UN==0b1:
                        if bit13==0b0:
                            self.pushreg(None)
                            return f"memd_locked({self.toreg(s5)},{self.topreg(d2)})={self.torreg(t5)}"
                elif atype==0b111:
                    if UN==0b1:
                        self.pushreg(d2,3)
                        return f"{self.topreg(d2)}=l2locka({self.toreg(s5)})"
            if amode==0b001:
                if atype==0b000:
                    if UN==0b0:
                        self.pushreg(None)
                        return f"dckill"
                    elif UN==0b1:
                        self.pushreg(None)
                        return f"dccleanidx({self.toreg(s5)})"
                elif atype==0b001:
                    if UN == 0b0:
                        self.pushreg(None)
                        return f"dcinvidx({self.toreg(s5)})"
                    elif UN == 0b1:
                        self.pushreg(None)
                        return f"dccleaninvidx({self.toreg(s5)})"
            elif amode==0b010:
                if atype==0b000:
                    if UN==0b0:
                        self.pushreg(None)
                        return f"dctagw({self.toreg(s5)},{self.toreg(t5)})"
                    elif UN==0b1:
                        self.pushreg(None)
                        return f"dctagr({self.toreg(s5)})"
                elif atype==0b001:
                    if UN==0b0:
                        bit13=(dword>>13)&1
                        if bit13==0b0:
                            self.pushreg(None)
                            return f"l2tagw({self.toreg(s5)},{self.toreg(t5)})"
                    elif UN==0b1:
                        d5=dword&0x1F
                        self.pushreg(d5)
                        return f"{self.toreg(d5)}=l2tagr({self.toreg(t5)})"
            elif amode==0b011:
                if atype==0b000:
                    if UN==0b0:
                        bits5=(dword>>5)&0x7
                        if bits5==0b000:
                            self.pushreg(None)
                            return f"l2fetch({self.toreg(s5)},{self.toreg(t5)})"
                    elif UN==0b1:
                        self.pushreg(None)
                        return f"l2cleanidx({self.toreg(s5)})"
                elif atype==0b001:
                    if UN==0b0:
                        self.pushreg(None)
                        return f"l2invidx({self.toreg(s5)})"
                    elif UN==0b1:
                        self.pushreg(None)
                        return f"l2unlocka({self.toreg(s5)})"
                elif atype==0b010:
                    if UN==0b0:
                        self.pushreg(None)
                        return f"l2fetch({self.toreg(s5)},{self.torreg(t5)})"
                    elif UN==0b1:
                        self.pushreg(None)
                        return f"l2gclean({self.torreg(t5)})"
                elif atype==0b011:
                    if UN==0b0:
                        self.pushreg(None)
                        return f"l2gcleaninv({self.torreg(t5)})"
            elif amode==0b100:
                if atype==0b000:
                    bits10=(dword>>10)&0x7
                    if UN==0b0:
                        bits5=(dword>>5)&0x7
                        if bits5==0b000:
                            self.pushreg(None)
                            return f"barrier"
                    if UN==0b1:
                        if bits10==0b000:
                            self.pushreg(None)
                            return f"l2kill"
                        elif bits10==0b010:
                            self.pushreg(None)
                            return f"l2gunlock"
                        elif bits10==0b100:
                            self.pushreg(None)
                            return f"l2gclean"
                        elif bits10==0b110:
                            self.pushreg(None)
                            return f"l2gcleaninv"
                elif atype==0b001:
                    if UN==0b0:
                        self.pushreg(None)
                        return f"syncht"
                    elif UN==0b1:
                        self.pushreg(None)
                        return f"l2cleaninvidx({self.toreg(s5)})"
        return "Error"

    def duplex(self,dword):
        lowinsn = dword & 0x1FFF
        highinsn = (dword >> 16) & 0x1FFF
        iclass = (((dword >> 29) & 7) << 1) + ((dword >> 13) & 1)

        def decode_l1(l1):
            l1_rd = l1 & 0xF
            l1_rs = (l1 >> 4) & 0xF
            l1_i = (l1 >> 8) & 0xF
            l1_mode = (l1 >> 13) & 0x1
            if l1_mode==0:
                self.pushreg(l1_rd,7)
                return f"{self.toduplexreg(l1_rd)}=memw({self.toreg(l1_rs)}+#{self.tou(l1_i,4,2)})"
            else:
                self.pushreg(l1_rd,7)
                return f"{self.toduplexreg(l1_rd)}=memub({self.toreg(l1_rs)}+#{self.tou(l1_i, 4, 0)})"

        def decode_s1(s1):
            #01iiiisssstttt     memb (Rs + #u4:0) = Rt
            #00iiiisssstttt     memw (Rs + #u4:2) = Rt
            s1_mode = (s1>>12)&0x3
            s1_t=s1&0xF
            s1_s=(s1>>4)&0xF
            s1_i=(s1>>8)&0xF
            if s1_mode==0b00:
                self.pushreg(None)
                return f"memw({self.toduplexreg(s1_s)}+#{self.tou(s1_i, 4, 2)})={self.toduplexreg(s1_t)}"
            elif s1_mode==0b01:
                self.pushreg(None)
                return f"memb({self.toduplexreg(s1_s)}+#{self.tou(s1_i, 4)})={self.toduplexreg(s1_t)}"

        def decode_s2(s2):
            #100iiisssstttt     memh (Rs + #u3:1) = Rt
            #10100iiiiitttt     memw (SP + #u5:2) = Rt
            #10101iiiiiittt     memd (SP + #s6:3) = Rtt
            #11000lssssiiii     memw (Rs + #u4:2) = #l1
            #11001lssssiiii     memb (Rs + #u4:0) = #l1
            #11110iiiii----     allocframe (#u5:3)
            s2_mode = (s2>>9)&0x1F
            if (s2_mode>>2)==0b100:
                s2_t=s2&0xF
                s2_s=(s2>>4)&0xF
                s2_i=(s2>>8)&0x7
                self.pushreg(None)
                return f"memh({self.toduplexreg(s2_s)}+#{self.tou(s2_i, 3, 1)})={self.toduplexreg(s2_t)}"
            elif s2_mode==0b10100:
                s2_t=s2&0xF
                s2_i=(s2>>4)&0x1F
                self.pushreg(None)
                return f"memw(SP+#{self.tou(s2_i, 5, 2)})={self.toduplexreg(s2_t)}"
            elif s2_mode==0b10101:
                s2_t=s2&0x7
                s2_i=(s2>>3)&0x3F
                self.pushreg(None)
                return f"memw(SP+#{self.tos(s2_i, 6, 3)})={self.toduplexrreg(s2_t)}"
            elif s2_mode==0b11000:
                s2_i=s2&0xF
                s2_s=(s2>>4)&0xF
                s2_l=(s2>>8)&0x1
                self.pushreg(None)
                return f"memw({self.toduplexrreg(s2_s)}+#{self.tou(s2_i, 4, 2)})={self.tou(s2_l,1)}"
            elif s2_mode==0b11001:
                s2_i=s2&0xF
                s2_s=(s2>>4)&0xF
                s2_l=(s2>>8)&0x1
                self.pushreg(None)
                return f"memb({self.toduplexrreg(s2_s)}+#{self.tou(s2_i, 4, 0)})={self.tou(s2_l,1)}"
            elif s2_mode==0b11110:
                s2_i=(s2>>4)&0x1F
                self.pushreg(None)
                return f"allocframe(#{self.tou(s2_i, 5, 3)})"

        def decode_l2(l2):
            l2_mode=(l2>>6)&0xFF
            #00iiiissssdddd     Rd = memw (Rs + #u4:2)
            #100iiissssdddd     Rd = memh (Rs + #u3:1)
            #101iiissssdddd     Rd = memuh (Rs + #u3:1)
            #110iiissssdddd     Rd = memb (Rs + #u3:0)
            #11110iiiiidddd     Rd = memw (Sp + #u5:2)
            #111110iiiiiddd     Rdd = memd (Sp + #u5:3)
            #11111100---0--     deallocframe
            #11111101---0--     dealloc_return
            #11111101---100     if (p0) dealloc_return
            #11111101---101     if (! p0) dealloc_return
            #11111101---110     if (p0.new) dealloc_return:nt
            #11111101---111     if (!p0.new) dealloc_return:nt
            #11111111---0--     jumpr R31
            #11111111---100     if (p0) jumpr R31
            #11111111---101     if (! p0) jumpr R31
            #11111111---110     if (p0.new) jumpr:nt R31
            #11111111---111     if (! p0.new) jumpr:nt R31
            if (l2_mode>>6)==0b00:
                l2_d = l2 & 0xF
                l2_s = (l2 >> 4) & 0xF
                l2_i = (l2 >> 8) & 0xF
                self.pushreg(l2_d, 7)
                return f"{self.toduplexreg(l2_d)}=memw({self.toreg(l2_s)}+#{self.tou(l2_i, 4, 1)})"
            if (l2_mode>>5)==0b100:
                l2_d=l2&0xF
                l2_s=(l2>>4)&0xF
                l2_i=(l2>>8)&7
                self.pushreg(l2_d, 7)
                return f"{self.toduplexreg(l2_d)}=memh({self.toreg(l2_s)}+#{self.tou(l2_i, 3, 1)})"
            elif (l2_mode>>5)==0b101:
                l2_d = l2 & 0xF
                l2_s = (l2 >> 4) & 0xF
                l2_i = (l2 >> 8) & 7
                self.pushreg(l2_d, 7)
                return f"{self.toduplexreg(l2_d)}=memuh({self.toreg(l2_s)}+#{self.tou(l2_i, 3, 1)})"
            elif (l2_mode >> 5)==0b110:
                l2_d = l2 & 0xF
                l2_s = (l2 >> 4) & 0xF
                l2_i = (l2 >> 8) & 7
                self.pushreg(l2_d, 7)
                return f"{self.toduplexreg(l2_d)}=memb({self.toreg(l2_s)}+#{self.tou(l2_i, 3)})"
            elif (l2_mode >> 3)==0b11110:
                l2_d = l2 & 0xF
                l2_i = (l2 >> 4) & 0x1F
                self.pushreg(l2_d, 7)
                return f"{self.toduplexreg(l2_d)}=memw(SP+#{self.tou(l2_i, 5,2)})"
            elif (l2_mode >> 2)==0b111110:
                l2_d = l2 & 0x7
                l2_i = (l2 >> 3) & 0x1F
                self.pushreg(l2_d, 8)
                return f"{self.toduplexrreg(l2_d)}=memd(SP+#{self.tou(l2_i, 5,3)})"
            elif l2_mode==0b11111100:
                return f"deallocframe"
            elif l2_mode==0b11111101:
                l2_d = l2 & 0x7
                if (l2_d>>2)==0:
                    return f"dealloc_return"
                elif l2_d>>2==0b100:
                    return f"if (p0) dealloc_return"
                elif l2_d>>2==0b101:
                    return f"if (!p0) dealloc_return"
                elif l2_d>>2==0b110:
                    return f"if (p0.new) dealloc_return:nt"
                elif l2_d>>2==0b111:
                    return f"if (!p0.new) dealloc_return:nt"
            elif l2_mode==0b11111111:
                l2_d = l2 & 0x7
                if (l2_d>>2)==0:
                    return f"jumpr R31"
                elif l2_d>>2==0b100:
                    return f"if (p0) jumpr R31"
                elif l2_d>>2==0b101:
                    return f"if (!p0) jumpr R31"
                elif l2_d>>2==0b110:
                    return f"if (p0.new) jumpr R31:nt"
                elif l2_d>>2==0b111:
                    return f"if (!p0.new) jumpr R31:nt"

        def decode_a(a):
            a_mode = (a>>8)&0x1F
            if (a_mode>>3)==0b00: #40:
                #00IIIIIIIxxxx
                a_x = a & 0xF  # 4bit
                a_i = (a >> 4) & 0x7F  # 7bit
                self.pushreg(a_x, 7)
                return f"{self.toduplexreg(a_x)}=add({self.toduplexreg(a_x)},{self.tos(a_i,7)})"
            elif (a_mode>>2)==0b010: #48
                #010010IIIIIIeeee
                a_e = a & 0xF  # 4bit
                a_i = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=#{self.tou(a_i,6)}"
            elif (a_mode>>2) == 0b011: #4c
                #010011IIIIIIeeee
                a_e = a & 0xF  # 4bit
                a_i = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=add(SP, #{self.tou(a_i,6,2)})"
            elif a_mode == 0b10000: #50
                #01010000uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}={self.toduplexreg(a_u)}"
            elif a_mode == 0b10001:
                #01010001uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=add({self.toduplexreg(a_u)},#1)"
            elif a_mode == 0b10010: #52
                #01010010uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=and({self.toduplexreg(a_u)},#1)"
            elif a_mode == 0b10011: #53
                #01010011uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=add({self.toduplexreg(a_u)},#-1)"
            elif a_mode == 0b10100: #54
                #01010100uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=sxth({self.toduplexreg(a_u)})"
            elif a_mode == 0b10101: #55
                #01010101uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=sxtb({self.toduplexreg(a_u)})"
            elif a_mode == 0b10110: #55
                #01010110uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=zxth({self.toduplexreg(a_u)})"
            elif a_mode == 0b10111: #57
                #01010111uuuueeee
                a_e = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_e, 7)
                return f"{self.toduplexreg(a_e)}=and({self.toduplexreg(a_u)},#0xFF)"
            elif a_mode == 0b11000: #58
                #01011000uuuuxxxx
                a_x = a & 0xF  # 4bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(a_x, 7)
                return f"{self.toduplexreg(a_x)}=add({self.toduplexreg(a_u)},{self.toduplexreg(a_x)})"
            elif a_mode == 0b11001: #59
                #01011001uuuu--II
                a_i = a & 0x3  # 2bit
                a_u = (a >> 4) & 0x3F  # 6bit
                self.pushreg(None)
                return f"p0=cmp.eq({self.toduplexreg(a_u)},{self.tou(a_i,2)})"
            elif (a_mode>>1)==0b1101: #5a
                #0101101--0--eeee Re = #-1
                #0101101--111eeee if (!p0) Re = #0
                #0101101--101eeee if (!p0.new) Re = #0
                #0101101--110eeee if (p0) Re = #0
                #0101101--100eeee if (p0.new) Re = #0
                a_e = a & 0xF  # 4bit
                a_m = (a>>4)&7
                if (a_m>>2)==0:
                    self.pushreg(a_e, 7)
                    return f"{self.toduplexreg(a_e)}=#-1)"
                elif a_m==0b100:
                    self.pushreg(a_e, 7)
                    return f"if (p0.new) {self.toduplexreg(a_e)}=#0)"
                elif a_m==0b101:
                    self.pushreg(a_e, 7)
                    return f"if (!p0.new) {self.toduplexreg(a_e)}=#0)"
                elif a_m==0b110:
                    self.pushreg(a_e, 7)
                    return f"if (p0) {self.toduplexreg(a_e)}=#0)"
                elif a_m==0b111:
                    self.pushreg(a_e, 7)
                    return f"if (!p0) {self.toduplexreg(a_e)}=#0)"
            elif (a_mode>>2)==0b111: #5c
                #010111-0-II00eee
                #010111-0-II01eee
                a_e = a & 0x7  # 3bit
                a_U = (a >> 3) & 0x3  # 2bit
                a_u = (a >> 5) & 0x3  # 2bit
                self.pushreg(a_e, 8)
                return f"{self.toduplexrreg(a_e)}=combine(#{self.tou(a_U,2)},#{self.tou(a_u,2)})"
            elif (a_mode>>2)==0b111: #5d
                #010111-1uuuu0eee
                #010111-1uuuu1eee
                a_e = a & 0x7  # 3bit
                a_bit4=(a>>4)&1
                a_u = (a >> 5) & 0xF  # 4bit
                if a_bit4==0:
                    self.pushreg(a_e, 8)
                    return f"{self.toduplexrreg(a_e)}=combine(#0,{self.toduplexreg(a_u)})"
                elif a_bit4==1:
                    self.pushreg(a_e, 8)
                    return f"{self.toduplexrreg(a_e)}=combine({self.toduplexreg(a_u)},#0)"
        if iclass == 0x0:
            disasm = decode_l1(highinsn) + "; "
            disasm += decode_l1(lowinsn) + "; "
        elif iclass == 0x1:
            disasm = decode_l1(highinsn) + "; "
            disasm += decode_l2(lowinsn) + "; "
        elif iclass == 0x2:
            disasm = decode_l2(highinsn) + "; "
            disasm += decode_l2(lowinsn) + "; "
        elif iclass == 0x3:
            disasm = decode_a(highinsn) + "; "
            disasm += decode_a(lowinsn) + "; "
        elif iclass == 0x4:
            disasm = decode_a(highinsn)+"; "
            disasm += decode_l1(lowinsn) + "; "
        elif iclass == 0x5:
            disasm = decode_a(highinsn) + "; "
            disasm += decode_l2(lowinsn) + "; "
        elif iclass == 0x6:
            disasm = decode_a(highinsn) + "; "
            disasm += decode_s1(lowinsn) + "; "
        elif iclass == 0x7:
            disasm = decode_a(highinsn) + "; "
            disasm += decode_s2(lowinsn) + "; "
        elif iclass == 0x8:
            disasm = decode_l1(highinsn) + "; "
            disasm += decode_s1(lowinsn) + "; "
        elif iclass == 0x9:
            disasm = decode_l2(highinsn) + "; "
            disasm += decode_s2(lowinsn) + "; "
        elif iclass == 0xA:
            disasm = decode_s1(highinsn) + "; "
            disasm += decode_s1(lowinsn) + "; "
        elif iclass == 0xB:
            disasm = decode_s1(highinsn) + "; "
            disasm += decode_s2(lowinsn) + "; "
        elif iclass == 0xC:
            disasm = decode_l1(highinsn) + "; "
            disasm += decode_s2(lowinsn) + "; "
        elif iclass == 0xD:
            disasm = decode_l2(highinsn) + "; "
            disasm += decode_s2(lowinsn) + "; "
        elif iclass == 0xE:
            disasm = decode_s2(highinsn) + "; "
            disasm += decode_s2(lowinsn) + "; "
        elif iclass == 0xF:
            disasm="Reserved"
            print("Reserved,Reserved")
        return disasm

def main():
    print ("\nHexagon V67 disassembler PoC (c) B.Kerler 2019\n")
    if len(sys.argv)<3:
        print("Usage: ./hexagon_disasm.py [filename] [startoffseŧ in hex] [endoffset in hex]")
        exit(0)
    filename=sys.argv[1]
    addr=int(sys.argv[2],16)
    length=((int(sys.argv[3],16)-addr)//4*4) + 4
    data=b""

    with open(filename,'rb') as rf:
        if ".elf" in filename:
            rdata=rf.read(0x1000)
            elfheader=elf(rdata)
            header,pentry=elfheader.parse()
            offset=elfheader.getfileoffset(addr)
        rf.seek(offset)
        data=rf.read(length)
    
    dwords=[]
    state=0
    hg=hexagon()
    loopcount=0

    for i in range(0,len(data),4):
        dwords.append(unpack("<I",data[i:i+4])[0])

    for pos in range(0,len(dwords)):
        dword=dwords[pos]

        curins=pack("<I",dword)
        hexstr=hexlify(curins).decode('utf-8') + "\t"
        pp=(dword>>14) & 3
        if state==0:
            disasm = hex(addr+(pos*4))+"\t"+"{\t"
            hg.offset = addr+(pos*4)
            state=1
        else:
            disasm += hex(addr+(pos*4))+"\t" + "\t"

        if pp==0:   #Duplex
            tmp=hg.duplex(dword)
        else:
            iclass=(dword>>28) & 0xF

            if iclass in hg.iclasses:
                if iclass == 0:
                    ll=dword&0x3FFF
                    hh=(dword>>16)&0x3FFF
                    immext=((hh<<14)+ll)<<6
                    tmp=f"immext (#{hex(immext)})"
                    hg.immext=immext
                elif iclass == 0b1011 or iclass == 0b1111 or iclass == 0b0111:
                    tmp=hg.alu32(iclass,dword)
                elif iclass == 0b0110:
                    tmp=hg.cr(iclass,dword)
                    if tmp=="Error":
                        tmp=hg.jclass(iclass,dword)
                    if tmp=="Error":
                        tmp=hg.system(iclass,dword)
                    if "loop" in tmp:
                        loopcount+=1
                elif iclass == 0b0101:
                    tmp=hg.jrclass(iclass,dword)
                    if tmp=="Error":
                        tmp=hg.jclass(iclass, dword)
                elif iclass == 0b0001:
                    tmp=hg.jclass(iclass,dword)
                elif iclass == 0b0011 or iclass == 0b0100 or iclass==0b1001 or iclass==0b1010:
                    tmp=hg.ld(iclass,dword)
                    if tmp=="Error":
                        tmp=hg.memop(iclass,dword)
                    if tmp=="Error":
                        tmp=hg.st(iclass, dword)
                    if tmp=="Error":
                        tmp=hg.nv_st(iclass, dword)
                elif iclass == 0b0010:
                    tmp = hg.nv(iclass,dword)
                elif iclass == 0b1000 or iclass == 0b1100 or iclass == 0b1101 or iclass == 0b1110:
                    tmp= hg.xtype(iclass,dword)
                if tmp=="Error":
                    hg.pushreg(None)
            else:
                print("Unsupported instruction. Aborting")
                exit(0)

        #disasm+=hexstr+"\t"+tmp+f"\t{pp}\t"
        disasm += hexstr + "\t" + tmp + "\t"

        if iclass == 0:
            disasm+=("[Constant extender]")
        if pp==0b11 or pp==0b00:
            if pp==0b00:
                disasm+=("[Duplex]")
            if state==2:
                if loopcount==1:
                    disasm += "\t}:endloop0\n"
                else:
                    disasm += "\t}:endloop1\n"
                loopcount=0
            else:
                disasm += "\t}\n"
            print(disasm)
            disasm=""
            state=0
        elif pp==0b10:
            state=2
            disasm+="\n"
        else:
            disasm+="\n"

    if disasm!="":
        print(disasm)

if __name__ == "__main__":
    main()