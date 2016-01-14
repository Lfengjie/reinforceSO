# -*- coding: utf-8 -*-
import struct
import os, sys

defaultKey = "encryLinuxSokey"
defaultencrySection="hackme"
class SO_Header:
    def __init__(self):
        self.e_ident = ""
        self.e_type = 0
        self.e_machine = ""
        self.e_version = ""
        self.e_entry = 0 #对so而言无用 (偏移24，4字节)
        self.e_phoff = 0 
        self.e_shoff = 0 #section header table的偏移( 偏移32，4字节 )
        self.e_flags = ""
        self.e_ehsize = 0 #elf头部大小(偏移40，2字节)
        self.e_phentsize = 0 
        self.e_phnum = 0
        self.e_shentsize = 0 #section header table中每个表项的大小 （偏移46，2字节）
        self.e_shnum = 0 #section header table表项数目 （偏移48，2字节）
        self.e_shstrndx = 0 #name section的索引 (偏移50，2字节)


#每个item为40字节，其中每个字段都为4字节
class SectionTableItem:
    def __init__(self):
        self.sh_name = "" #section的名字（索引） 
        self.sh_type = ""
        self.sh_flags = ""
        self.sh_addr = 0 #在内存中的偏移
        self.sh_offset = 0 #该section相对于elf文件头的偏移
        self.sh_size = 0 #该section的总大小
        self.sh_link = 0
        self.sh_info = ""
        self.sh_addralign = 0
        self.sh_entsize = 0
        

class SO:
    def __init__(self,path):
        self.so = open(path,'r+')#不能用rw ，同时读写要用r+
        self.elf64_ELFHeader = SO_Header()
        self.section_header_table = []
        self.section_name_table = ""
        
        self.ReadELFHeader()
        self.ReadSectionTable()
        
    
    #只读出与加壳有关的关键数据
    def ReadELFHeader(self):
        self.so.seek(40)  
        self.elf64_ELFHeader.e_shoff = struct.unpack("Q",self.so.read(8))[0]
        self.so.seek(52)
        self.elf64_ELFHeader.e_ehsize = struct.unpack("h",self.so.read(2))[0]
        self.so.seek(58)  
        self.elf64_ELFHeader.e_shentsize = struct.unpack("h",self.so.read(2))[0]
        self.elf64_ELFHeader.e_shnum = struct.unpack("h",self.so.read(2))[0]
        self.elf64_ELFHeader.e_shstrndx = struct.unpack("h",self.so.read(2))[0]  


    #读取section table 只读与加壳有关的数据
    def ReadSectionTable(self):
        self.so.seek(self.elf64_ELFHeader.e_shoff)
        num = self.elf64_ELFHeader.e_shnum
        
        for i in xrange(num):
            sectionitem = SectionTableItem()
            sectionitem.sh_name = struct.unpack("I",self.so.read(4))[0]
            self.so.seek(12,1)
            sectionitem.sh_addr = struct.unpack("Q",self.so.read(8))[0]
            sectionitem.sh_offset = struct.unpack("Q",self.so.read(8))[0]
            sectionitem.sh_size = struct.unpack("Q",self.so.read(8))[0]
            self.section_header_table.append(sectionitem)
            self.so.seek(24,1)            
        
        
    def EncrySection(self,key, sname):
        
        num = self.elf64_ELFHeader.e_shnum
        name_section_offset = self.section_header_table[self.elf64_ELFHeader.e_shstrndx].sh_offset        
        self.so.seek(name_section_offset)
        l = self.section_header_table[self.elf64_ELFHeader.e_shstrndx].sh_size
        self.section_name_table = self.so.read(l)

        #读取所有section名
        for i in xrange(num):
            idx = self.section_header_table[i].sh_name
            name = []
            while True:
                if self.section_name_table[idx] != '\0':
                    name.append(self.section_name_table[idx])
                else:
                    break
                idx+=1
            #找到特定的section
	    #print "".join(name),"  ",sname
            if "".join(name) == sname:
                break
    
    
        print i
        offset = self.section_header_table[i].sh_offset
        size = self.section_header_table[i].sh_size
        print offset,size
        
        ###########################
        # 将elf header中的e_shoff,e_entry修改为要被
        # 加密的section的sh_offset,sh_size
        # 因为在so加载时linker只关心segment，修改section
        # 相关内容不会影响运行
        ###########################
        
        self.so.seek(24)
        self.so.write(struct.pack("Q",size))
        self.so.seek(40)
        self.so.write(struct.pack("Q",offset))
        
        #加密section
        self.so.seek(offset)
        data = self.so.read(size)
	print data
        new_data = encryALG(data, key)
            
        print "len:",len(new_data)
        self.so.seek(offset)
        self.so.write("".join(new_data))
        
    
    def Close(self):
        self.so.close()
        
 
def decrypString(path, key):
    so = open(path,'r+')#不能用rw ，同时读写要用r+

    so.seek(24)
    encrySize = struct.unpack("Q",so.read(8))[0]
    so.seek(40)
    encryOffset = struct.unpack("Q",so.read(8))[0]

    print "encryOffset  ", encryOffset
    print "encrySize  ", encrySize
    so.seek(encryOffset)
    data = so.read(encrySize)
    new_data = decrypALG(data, key)
    so.seek(encryOffset)
    so.write("".join(new_data))
    so.close()

#加密算法
def encryALG(mingwen, key):
    '''
    明文与密文相加取余
    '''
    miwen = []
    keySize = len(key)
    curKeyIndex = 0
    for i in mingwen:
        miwen.append(chr((ord(i) + ord(key[curKeyIndex])) % 255))
        curKeyIndex += 1
        if curKeyIndex == keySize:
            curKeyIndex = 0
    return miwen

#解密算法
def decrypALG(miwen, key):
    '''
    解密算法
    '''
    mingwen = []
    keySize = len(key)
    curKeyIndex = 0
    for i in miwen:
        i_true = ord(i)
	#charstr = "char "+ str(i) + " "+ str(i_true)
        #print charstr
        if(ord(i) <= key[curKeyIndex]):
            i_true = i_true + 255
         
        mingwen.append(chr((i_true - ord(key[curKeyIndex])) % 255))

        charstr = "char "+ str(i) + " "+ str((i_true - ord(key[curKeyIndex])) % 255)
        print charstr
        curKeyIndex = curKeyIndex + 1
        if curKeyIndex == keySize:
            curKeyIndex = 0
    print mingwen
    return mingwen


if __name__ == "__main__":
    '''
    第一个参数：  为1代表加密，为2代表解密
    第二个参数：  要加密或者解密的文件名
    第三个参数：  加密或者解密的密钥
    第四个参数：  加密的section
    '''
    if len(sys.argv) >= 3:
        if sys.argv[1] == "1":
            df = SO(sys.argv[2])
            if len(sys.argv) >= 5:
                df.EncrySection(sys.argv[3], sys.argv[4])
            elif len(sys.argv) == 4:
                df.EncrySection(sys.argv[3], defaultencrySection)
            else:
                df.EncrySection(defaultKey, defaultencrySection)
            df.Close()
        else:
            if len(sys.argv) >= 4:
                decrypString(sys.argv[2], sys.argv[3])
            else:
                decrypString(sys.argv[2], defaultKey)
