#!/usr/bin/env python


#-------------------------------------------------------------------------------
# Name:        pypcpc
# Purpose:     a port control protocol(RFC6887) client/lib
#
# Author:      hujun
#
# Created:     8/Feb/2015
# Copyright:   (c) hujun 2015
# Licence:     MIT
#-------------------------------------------------------------------------------
import struct
import socket
import random
import asyncore
import time
import pprint
import threading
import sys
import argparse
import cmd
import shlex
import traceback

import ctypes
import os


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_short),
                ("__pad1", ctypes.c_ushort),
                ("ipv4_addr", ctypes.c_byte * 4),
                ("ipv6_addr", ctypes.c_byte * 16),
                ("__pad2", ctypes.c_ulong)]

if hasattr(ctypes, 'windll'):
    WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
    WSAAddressToStringA = ctypes.windll.ws2_32.WSAAddressToStringA
else:
    def not_windows():
        raise SystemError(
            "Invalid platform. ctypes.windll must be available."
        )
    WSAStringToAddressA = not_windows
    WSAAddressToStringA = not_windows


def inet_pton(address_family, ip_string):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))

    if WSAStringToAddressA(
            ip_string,
            address_family,
            None,
            ctypes.byref(addr),
            ctypes.byref(addr_size)
    ) != 0:
        raise socket.error(ctypes.FormatError())

    if address_family == socket.AF_INET:
        return ctypes.string_at(addr.ipv4_addr, 4)
    if address_family == socket.AF_INET6:
        return ctypes.string_at(addr.ipv6_addr, 16)

    raise socket.error('unknown address family')


def inet_ntop(address_family, packed_ip):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))
    ip_string = ctypes.create_string_buffer(128)
    ip_string_size = ctypes.c_int(ctypes.sizeof(ip_string))

    if address_family == socket.AF_INET:
        if len(packed_ip) != ctypes.sizeof(addr.ipv4_addr):
            raise socket.error('packed IP wrong length for inet_ntoa')
        ctypes.memmove(addr.ipv4_addr, packed_ip, 4)
    elif address_family == socket.AF_INET6:
        if len(packed_ip) != ctypes.sizeof(addr.ipv6_addr):
            raise socket.error('packed IP wrong length for inet_ntoa')
        ctypes.memmove(addr.ipv6_addr, packed_ip, 16)
    else:
        raise socket.error('unknown address family')

    if WSAAddressToStringA(
            ctypes.byref(addr),
            addr_size,
            None,
            ip_string,
            ctypes.byref(ip_string_size)
    ) != 0:
        raise socket.error(ctypes.FormatError())

    return ip_string[:ip_string_size.value - 1]

# update socket function in windows
if os.name == 'nt':
    socket.inet_pton = inet_pton
    socket.inet_ntop = inet_ntop


PCP_RESULT_CODE = {
0:'SUCCESS',
1:'UNSUPP_VERSION',
2:'NOT_AUTHORIZED',
3:'MALFORMED_REQUEST',
4:'UNSUPP_OPCODE',
5:'UNSUPP_OPTION',
6:'MALFORMED_OPTION',
7:'NETWORK_FAILURE',
8:'NO_RESOURCES',
9:'UNSUPP_PROTOCOL',
10:'USER_EX_QUOTA',
11:'CANNOT_PROVIDE_EXTERNAL',
12:'ADDRESS_MISMATCH',
13:'EXCESSIVE_REMOTE_PEERS',
130:'NON_EXIST_MAPPING',#draft-boucadair-pcp-failure-06
131:'AMBIGUOUS',#draft-boucadair-pcp-failure-06
}





class PCPParseError(Exception):
    pass

class PCPProtocolError(Exception):
    pass

class PCPResponseError(Exception):
    def __init__(self, result_code):
        self.result_code=result_code
    def __str__(self):
        global PCP_RESULT_CODE
        return "PCP Result code:"+str(self.result_code)+", "+\
                PCP_RESULT_CODE.get(self.result_code,"unknown result code")



class PCPClient:
    """
    PCPClient provide PCP protocol encapsualtion/parse support
    """
    def __init__(self,src_addr):
        self.version=2
        self.src_addr=src_addr
        self.mapping_nonce=''
        self.supported_options= {#supported PCP options
        1:self.parseTHIRD_PARTYOption,#rfc6887
        2:self.parsePREFER_FAILUREOption,#rfc6887
        3:self.parseFILTEROption,#rfc6887
        64:self.parseDESCRIPTIONOption,#draft-boucadair-pcp-extensions-03
        132:self.parsePORT_RESRVOption,#draft-boucadair-pcp-rtp-rtcp-05
        131:self.parseNEXTv2Option, #draft-boucadair-pcp-failure-06
        255:self.parsePORT_SETOption, #255 as place holder,draft-ietf-pcp-port-set-07, untested
        }
        self.supported_ops = { #supported PCP op
        1:(self.parseMapInfo,36), #rfc6887
        2:(self.parsePeerInfo,56),#rfc6887
        0:(self.parseANNOUNCEInfo,0),#rfc6887
        98:(self.parseGETInfo,40), #draft-boucadair-pcp-failure-06
        }

        for i in range(12):
            self.mapping_nonce+=chr(random.randint(0,255))

    def toPCPAddrFormat(self,addr_str):
        """
        Convert an IPv4 or IPv6 text reprsentated address to PCP format
        """
        if ":" in addr_str or addr_str.count(".")>3: #v6 address
            addrs=socket.inet_pton(socket.AF_INET6,addr_str)
        else:#v4 address, encoded into v4-maped v6 address
            hexs=""
            for x in addr_str.split("."):
                hexs+="{n:02x}".format(n=int(x))
            rs="::ffff:"+hexs[:4]+":"+hexs[4:]
            addrs=socket.inet_pton(socket.AF_INET6,rs)
        return addrs

    def toNormalIPFormat(self,pcp_addr_str):
        """
        Convert PCP encoded address back to an text formatted IPv4 or IPv6 addr
        """
        if pcp_addr_str[0:12] == "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff":
            return socket.inet_ntop(socket.AF_INET,pcp_addr_str[12:16])
        else:
            return socket.inet_ntop(socket.AF_INET6,pcp_addr_str)

    def createReqHeader(self,opcode,lifetime):
        """
        Contruct a PCP request header string
        """
        if not opcode in range(128):
            raise ValueError("opcode not in range 0..127")
        vers=chr(self.version)
        opcs=chr(opcode)
        resvrs="\x00\x00"
        lifetimes=struct.pack("!I",lifetime)
        return vers+opcs+resvrs+lifetimes+self.toPCPAddrFormat(self.src_addr)

    def createOption(self,option_code,option_value=""):
        """
        Construct a PCP option string
        """
        if not option_code in range(256):
            raise ValueError("option code not in range 0..255")
        codes=chr(option_code)
        reservs="\x00"
        lens=struct.pack("!H",len(option_value))
        pad_len=0
        if (len(option_value) % 4) !=0:
            pad_len = 4 - (len(option_value) % 4)
        values=option_value
        for i in range(pad_len):
            values+="\x00"
        return codes+reservs+lens+values

    def createMAPRequestInfo(self,protocol,intPort,extPort,extIP):
        if not protocol in range(256):
            raise ValueError("protocol not in range 0..255")
        if not intPort in range(65536):
            raise ValueError("internal port not in range 0..65535")
        if not extPort in range(65536):
            raise ValueError("external port not in range 0..65535")
        reservs="\x00\x00\x00"
        intports=struct.pack("!H",intPort)
        extports=struct.pack("!H",extPort)
        return self.mapping_nonce+chr(protocol)+reservs+intports+extports\
                +self.toPCPAddrFormat(extIP)

    def createPEERRequestInfo(self,protocol,intPort,extPort,extIP,rPort,rIP):
        if not protocol in range(256):
            raise ValueError("protocol not in range 0..255")
        if not intPort in range(65536):
            raise ValueError("internal port not in range 0..65535")
        if not extPort in range(65536):
            raise ValueError("external port not in range 0..65535")
        if not rPort in range(65536):
            raise ValueError("remote port not in range 0..65535")
        reservs_1="\x00\x00\x00"
        reservs_2="\x00\x00"
        intports=struct.pack("!H",intPort)
        extports=struct.pack("!H",extPort)
        rports=struct.pack("!H",rPort)
        return self.mapping_nonce+chr(protocol)+reservs_1+intports+extports\
                +self.toPCPAddrFormat(extIP)+rports+reservs_2\
                +self.toPCPAddrFormat(rIP)

    def createGETRequestInfo(self,protocol,intIP,extIP,intPort,extPort):
        if not protocol in range(256):
            raise ValueError("protocol not in range 0..255")
        if not intPort in range(65536):
            raise ValueError("internal port not in range 0..65535")
        if not extPort in range(65536):
            raise ValueError("external port not in range 0..65535")
        reservs="\x00\x00\x00"
        intports=struct.pack("!H",intPort)
        extports=struct.pack("!H",extPort)
        return chr(protocol)+reservs+self.toPCPAddrFormat(intIP)\
                +self.toPCPAddrFormat(extIP)+intports+extports


    def createPEERRequest(self,lifetime,protocol,intPort,extPort,extIP,rPort,
                            rIP,ops_list=[]):

        headers=self.createReqHeader(2,lifetime)
        infos=self.createPEERRequestInfo(protocol,intPort,extPort,extIP,rPort,rIP)
        return headers+infos+"".join(ops_list)

    def createANNOUNCERequest(self):
        headers=self.createReqHeader(0,0)
        return headers

    def createGETRequest(self,lifetime,protocol,intPort,extPort,intIP,extIP,ops_list=[]):
        headers=self.createReqHeader(98,lifetime)
        infos=self.createGETRequestInfo(protocol,intIP,extIP,intPort,extPort)
        return headers+infos+"".join(ops_list)

    def createTHIRD_PARTYOption(self,intIP):
        return self.createOption(1,self.toPCPAddrFormat(intIP))

    def createPREFER_FAILUREOption(self):
        return self.createOption(2)

    def createPORT_RESRVOption(self):
        return self.createOption(132)


    def createFILTEROption(self,plen,rPort,rIP):
        if not plen in range(256):
            raise ValueError("prefix len not in range 0..255")
        if not rPort in range(65536):
            raise ValueError("remote port not in range 0..65535")
        reservs=chr(0)
        plens=chr(plen)
        rports=struct.pack("!H",rPort)
        return self.createOption(3,reservs+plens+rports+self.toPCPAddrFormat(rIP))


    def createNEXTv2Option(self,proto,moreand,intIP,extIP,intPort,
                                extPort,nonce,ops_list=[]):
        if not proto in range(256):
            raise ValueError("protocol not in range 0..255")
        if not intPort in range(65536):
            raise ValueError("internal port not in range 0..65535")
        if not extPort in range(65536):
            raise ValueError("external port not in range 0..65535")
        if len(nonce) != 12:
            raise ValueError("nonce is not 12 bytes long")
        reservs="\x00\x00"
        protos=chr(proto)
        moreands=chr(moreand)
        lifetimes="\x00\x00\x00\x00"
        intports=struct.pack("!H",intPort)
        extports=struct.pack("!H",extPort)
        return self.createOption(131,nonce+protos+reservs+moreands+\
                self.toPCPAddrFormat(intIP)+self.toPCPAddrFormat(extIP)+\
                lifetimes+intports+extports+"".join(ops_list))



    def createPORT_SETOption(self,set_size,first_port,pbit):
        """
        defined in draft-ietf-pcp-port-set, however option number is not
        assinged yet, use 255 as place holder
        """
        if not first_port in range(65536):
            raise ValueError("first port not in range 0..65535")
        ports=struct.pack("!H",first_port)
        sets=struct.pack("!H",set_size)
        pbits=chr(int(pbit))
        return self.createOption(255,sets+ports+pbits)


    def createDESCRIPTIONOption(self,desc):
        return self.createOption(64,desc)

    def createMAPRequest(self,lifetime,protocol,intPort,extPort,extIP,
                            ops_list=[]):

        headers=self.createReqHeader(1,lifetime)
        infos=self.createMAPRequestInfo(protocol,intPort,extPort,extIP)
        return headers+infos+"".join(ops_list)

    def parseResponseHeader(self,inheader):
        if len(inheader) != 24:
            raise PCPParseError("response header length is not 24 bytes")
        if inheader[0] != chr(self.version):
            raise PCPParseError("response version is not "+self.version)
        if ord(inheader[1])<128:
            raise PCPParseError("R bit is not 1")
        r={}
        r['version']=ord(inheader[0])
        r['opcode']=ord(inheader[1])-128
        r['result_code']=ord(inheader[3])
        r['lifetime']=struct.unpack('!I',inheader[4:8])[0]
        r['epoch_time']=struct.unpack('!I',inheader[8:12])[0]
        return r


    def parseMapInfo(self,ininfo):
        if len(ininfo) != 36:
            raise PCPParseError("MAP response info length is not 36 bytes")
        r={}
        r['nonce']=ininfo[0:12]
        if r['nonce'] != self.mapping_nonce:
            raise PCPParseError("mapping nonce dosn't match")
        r['protocol']=ord(ininfo[12:13])
        r['internal_port']=struct.unpack("!H",ininfo[16:18])[0]
        r['external_port']=struct.unpack("!H",ininfo[18:20])[0]
        r['external_address']=self.toNormalIPFormat(ininfo[20:36])
        return r

    def parseGETInfo(self,ininfo):
        if len(ininfo) != 40:
            raise PCPParseError("GET response info length is not 40 bytes")
        r={}
        r['protocol']=ord(ininfo[0])
        r['internal_address']=self.toNormalIPFormat(ininfo[4:20])
        r['external_address']=self.toNormalIPFormat(ininfo[20:36])
        r['internal_port']=struct.unpack("!H",ininfo[36:38])[0]
        r['external_port']=struct.unpack("!H",ininfo[38:40])[0]
        return r

    def parsePeerInfo(self,ininfo):
        if len(ininfo) != 56:
            raise PCPParseError("PEER response info length is not 56 bytes")
        r={}
        r['nonce']=ininfo[0:12]
        if r['nonce'] != self.mapping_nonce:
            raise PCPParseError("mapping nonce dosn't match")
        r['protocol']=ord(ininfo[12:13])
        r['internal_port']=struct.unpack("!H",ininfo[16:18])[0]
        r['assinged_external_port']=struct.unpack("!H",ininfo[18:20])[0]
        r['assinged_external_address']=self.toNormalIPFormat(ininfo[20:36])
        r['remote_port']=struct.unpack("!H",ininfo[36:38])[0]
        r['remote_address']=self.toNormalIPFormat(ininfo[40:56])
        return r

    def parseANNOUNCEInfo(self,ininfo):
        return {}

    def parseOptions(self,options):
        if len(options)<4:
            raise PCPParseError("option length less than 4 bytes")
        op_list=[]
        cursor=0
        total_len=len(options)
        while cursor<total_len:
            op_len=struct.unpack("!H",options[cursor+2:cursor+4])[0]
            pad_len=0
            if op_len % 4 !=0:
                pad_len = 4 - (op_len % 4)
            if ord(options[cursor]) in self.supported_options:
                op_list.append(self.supported_options[ord(options[cursor])](options[cursor+4:cursor+op_len+4]))
            else:
                op_list.append({'code':ord(options[cursor]),'value':options[cursor+4:cursor+4+op_len]})
            cursor+=op_len+pad_len+4
        return op_list

    def parseTHIRD_PARTYOption(self,ops):
        return {'code':1,'3rd_party_address':self.toNormalIPFormat(ops)}

    def parsePREFER_FAILUREOption(self,ops):
        return {'code':2,"prefer_failure":True}

    def parsePORT_RESRVOption(self,ops):
        return {'code':132,"port_reservation":True}

    def parseFILTEROption(self,ops):
        plen=ord(ops[1])
        remote_port=struct.unpack("!H",ops[2:4])[0]
        remote_ip=self.toNormalIPFormat(ops[4:20])
        return {
        'code':3,
        "filter_prefix_length":plen,
        "filter_remote_port":remote_port,
        "filter_remote_ip":remote_ip,
        }

    def parseNEXTv2Option(self,ops):
        ops_list=[]
        nonce=ops[:12]
        proto=ord(ops[12])
        moreand=ord(ops[15])
        intIP=self.toNormalIPFormat(ops[16:32])
        extIP=self.toNormalIPFormat(ops[32:48])
        lifetime=struct.unpack("!I",ops[48:52])[0]
        intPort=struct.unpack("!H",ops[52:54])[0]
        extPort=struct.unpack("!H",ops[54:56])[0]
        if len(ops)>56:
            ops_list=self.parseOptions(ops[56:])

        return {
        'code':131,
        'nonce':"0x"+nonce.encode('hex'),
        "protocol":proto,
        "more_end":moreand,
        "internal_ip":intIP,
        "external_ip":extIP,
        "remaining_lifetime":lifetime,
        "internal_port":intPort,
        "external_port":extPort,
        "mapping_options":ops_list,
        }

    def parsePORT_SETOption(self,ops):
        set_size=struct.unpack("!H",ops[0:2])[0]
        first_port=struct.unpack("!H",ops[2:4])[0]
        pbit=bool(ord(ops[4]) & 1)
        return {
        'code':255,
        "port_set_size":set_size,
        "first_internal_port":first_port,
        "p_bit":pbit,
        }

    def parseDESCRIPTIONOption(self,ops):
        return {
        "description":ops
        }
    def parseMAPResponse(self,packet):
        r={}
        r['header']=self.parseResponseHeader(packet[:24])
        r['info']=self.parseMapResponseInfo(packet[24:60])
        if len(packet)>60:
            r['option_list']=self.parseOptions(packet[60:])
        return r

    def parsePEERResponse(self,packet):
        r={}
        r['header']=self.parseResponseHeader(packet[:24])
        r['info']=self.parsePeerResponseInfo(packet[24:80])
        if len(packet)>80:
            r['option_list']=self.parseOptions(packet[80:])
        return r

    def parseANNOUNCEResponse(self,packet):
        r={}
        r['header']=self.parseResponseHeader(packet[:24])
        return r

    def parseGETResponse(self,packet):
        r={}
        r['header']=self.parseResponseHeader(packet[:24])
        r['info']=self.parseGETResponseInfo(packet[24:64])
        if len(packet)>64:
            r['option_list']=self.parseOptions(packet[64:])
        return r

    def parseResponse(self,resp_packet):
        """
        return a parsed response packet as a dict
        """
        if len(resp_packet)<24:
            raise PCPParseError("Response packet need to be bigger than 24 bytes")
        if len(resp_packet)>1100:
            raise PCPParseError("Response packet need to be smaller than 1100 bytes")
        r={}
        r['header']=self.parseResponseHeader(resp_packet[:24])
        op_code=ord(resp_packet[1])-128

        if op_code in self.supported_ops:
            r['op_specific_info']=self.supported_ops[op_code][0](resp_packet[24:24+self.supported_ops[op_code][1]])
        else:
            raise PCPParseError("unsupported PCP opcode "+str(op_code))
        if len(resp_packet)>24+self.supported_ops[op_code][1]:
            r['option_list']=self.parseOptions(resp_packet[24+self.supported_ops[op_code][1]:])
        return r

    def parseRequest(self,req_packet):
        """
        return a parsed request packet as a dict
        """
        if len(req_packet)<24:
            raise PCPParseError("Request packet need to be bigger than 24 bytes")
        if len(req_packet)>1100:
            raise PCPParseError("Request packet need to be smaller than 1100 bytes")

        r={}
        r['header']=self.parseRequestHeader(req_packet[:24])
        op_code=ord(req_packet[1])

        if op_code in self.supported_ops:
            r['op_specific_info']=self.supported_ops[op_code][0](req_packet[24:24+self.supported_ops[op_code][1]])
        else:
            raise PCPParseError("unsupported PCP opcode "+str(op_code))
        if len(req_packet)>24+self.supported_ops[op_code][1]:
            r['option_list']=self.parseOptions(req_packet[24+self.supported_ops[op_code][1]:])
        return r

    def parseRequestHeader(self,inheader):
        if len(inheader) != 24:
            raise PCPParseError("request header length is not 24 bytes")
        if ord(inheader[1])>=128:
            raise PCPParseError("R bit is not 0")
        r={}
        r['version']=ord(inheader[0])
        r['opcode']=ord(inheader[1])
        r['request_lifetime']=struct.unpack('!I',inheader[4:8])[0]
        r['client_address']=self.toNormalIPFormat(inheader[8:24])
        return r



class requestQueue:
    """
    requestQueue is a queue used by asyncPCPClient, to facilitate re-transmission
    """
    def __init__(self,max_size):
        self.max_size=max_size
        self.Q={}

    def add(self,request_packet):
        """
        request_id should be the op_code
        """
        request_id=ord(request_packet[1])
        if request_id in self.Q:
            raise PCPProtocolError("there is exisiting outstand opcode {id}"\
                                        " request".format(id=request_id))
        current_time=time.time()
        self.Q[request_id]={'packet':request_packet,
                            'init_time':current_time,
                            'send_time':current_time,
                            'send_count':0,
                            }


    def remove(self,request_id):
        self.Q.pop(request_id,None)


    def update(self,request_id,new_time):
        if not request_id in self.Q:
            raise PCPProtocolError("there is no exisiting outstand opcode {id}"\
                                        " request".format(id=request_id))

        self.Q[request_id]['send_time']=new_time
        self.Q[request_id]['send_count']+=1



class asyncPCPClient(asyncore.dispatcher):

    def __init__(self,src_addr,svr_addr,recv_callback=pprint.pprint,debug=False):
        """
        asyncPCPClient send and receives PCP packet and use PCPClient for protocol encapsualtion/parse
        - recv_callback is a function to be called when a valid response is rcvd
        - if debug is True, print out some debug info
        """
        asyncore.dispatcher.__init__(self)
        if src_addr.count(".") >3 or ":" in src_addr:
            self.create_socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind((src_addr,5350))
        self.pcpc = PCPClient(src_addr)
        self.svr_addr=svr_addr
        self.reqQ = requestQueue(len(self.pcpc.supported_ops.keys())) # request Q
        self.RT=3.0
        self.MRC=3
        self.MRD=2048.0
        self.write_ready=False
        self.epoch_time=0
        self.prev_client_time=0
        self.recv_callback=recv_callback
        self.debug=debug



    def handle_write(self):
        for r in self.reqQ.Q:
            current_time=time.time()
            if current_time>=self.reqQ.Q[r]['send_time']:
                if self.reqQ.Q[r]['send_count'] < self.MRC-1 and \
                          current_time-self.reqQ.Q[r]['init_time']<self.MRD:
                    packet = self.reqQ.Q[r]['packet']
                    self.sendto(packet,(self.svr_addr,5351))
                    self.reqQ.update(r,time.time()+self.RT)
                    if self.debug:
                        print "\n--- Seding PCP Request  @ {t} ---\n".format(t=time.strftime('%Y-%m-%d %H:%M:%S'))
                        pprint.pprint(self.pcpc.parseRequest(packet))
                        print "\n--- end of request ---\n"
                    self.RT = (1+random.uniform(-0.1,0.1))*min(2*self.RT,1024)
                else:
                    self.reqQ.remove(r)
                    raise PCPProtocolError("Retransmission of opcode {id} request failed".format(id=r))



    def handle_read(self):
        global PCP_RESULT_CODE
        data, addr = self.recvfrom(2000)
        resp_packet=self.pcpc.parseResponse(data)
        self.reqQ.remove(resp_packet['header']['opcode'])
        if self.reqQ.Q == {}:
            self.write_ready=False
        self.recv_callback(resp_packet)
        if resp_packet['header']['result_code'] !=0:
            print "warning: PCP result code {c}, {cstr}".format(
                c=resp_packet['header']['result_code'],
                cstr=PCP_RESULT_CODE[resp_packet['header']['result_code']])
        if not self.checkEpoch(resp_packet['header']['epoch_time']):
            raise PCPProtocolError("epoch time check failed, server might lost its states")


    def sendMAPRequest(self,lifetime,protocol,intPort,
                            extPort,extIP,ops_list=[]):
        request_packet=self.pcpc.createMAPRequest(lifetime,protocol,intPort,
                            extPort,extIP,ops_list)
        self.reqQ.add(request_packet)
        self.write_ready=True

    def sendPEERRequest(self,lifetime,protocol,intPort,
                            extPort,extIP,rPort,rIP,ops_list=[]):
        request_packet=self.pcpc.createPEERRequest(lifetime,protocol,intPort,
                            extPort,extIP,rPort,rIP,ops_list)
        self.reqQ.add(request_packet)
        self.write_ready=True

    def sendGETRequest(self,lifetime,protocol,intPort,extPort,intIP,extIP,
                            ops_list=[]):
        request_packet=self.pcpc.createGETRequest(lifetime,protocol,intPort,
                                extPort,intIP,extIP,ops_list)
        self.reqQ.add(request_packet)
        self.write_ready=True

    def sendANNOUNCERequest(self):
        request_packet=self.pcpc.createANNOUNCERequest()
        self.reqQ.add(request_packet)
        self.write_ready=True

    def writable(self):
        return self.write_ready

    def handle_error(self):
        err=sys.exc_info()
        print err[0]," : ",err[1]
##        print traceback.format_exc()


    def checkEpoch(self,new_epoch):
        if self.epoch_time==0:
            r=True
        elif self.epoch_time-new_epoch>1:
            r=False
        else:
            client_delta=time.time()-self.prev_client_time
            server_delta=new_epoch-self.epoch_time
            if client_delta+2<server_delta-server_delta/16 or server_delta+2 < client_delta - client_delta/16:
                r=False
            else:
                r=True
        self.epoch_time=new_epoch
        self.prev_client_time=time.time()
        return r

    def enableDebug(self,e):
        self.debug=e



class CLIPCPClient(cmd.Cmd):
    """
    CLIPCPClient is a interactive CLI shell based PCP client, it uses
    asyncPCPClient underneath
    """
    def __init__(self, src_addr,svr_addr,debug=False):
        cmd.Cmd.__init__(self)
        self.doc_header=""
        self.misc_header="Command Topics (help topicX or topicX -h see detail)"
        self.client=asyncPCPClient(src_addr,svr_addr,self.printResponse,debug)
        self.prompt="PCPc>"
        self.parser = argparse.ArgumentParser(prog="")
        self.subparsers = self.parser.add_subparsers()

        self.map_parser = self.subparsers.add_parser("map",help='send map request')
        self.map_parser.add_argument("intPort",type=int,
                            help="Internal Port")
        self.map_parser.add_argument("extPort",type=int,
                            help="External Port")
        self.map_parser.add_argument("proto",type=int,
                            help="Protocol number,udp=17,tcp=6")
        self.map_parser.add_argument("-eIP","--extIP",default="0.0.0.0",
                            help="suggested external IP")
        self.map_parser.add_argument("-lt","--lifetime",type=int,default=3600,
                            help="lifetime")
        self.map_parser.add_argument("-des","--description",
                            help="Description option ")
        self.map_parser.add_argument("-tp","--thirdparty",
                            help="Third Party address option ")
        self.map_parser.add_argument("-pf","--preferfailure",action='store_true',
                            help="Prefer Failure option")
        self.map_parser.add_argument("-f","--filter",nargs='+',
                            help="Filter option. format:prefix/prefix_len/port")
        self.map_parser.add_argument("-pr","--portreserv",action='store_true',
                            help="Port Reservation Option,draft-boucadair-pcp-rtp-rtcp-05")
        self.map_parser.set_defaults(func=self._do_map)


        self.peer_parser = self.subparsers.add_parser("peer",help='send peer request')
        self.peer_parser.add_argument("intPort",type=int,
                            help="Internal Port")
        self.peer_parser.add_argument("extPort",type=int,
                            help="External Port")
        self.peer_parser.add_argument("proto",type=int,
                            help="Protocol number,udp=17,tcp=6")
        self.peer_parser.add_argument("rPort",type=int,
                            help="remote port")
        self.peer_parser.add_argument("rIP",
                            help="remote IP address")
        self.peer_parser.add_argument("-eIP","--extIP",default="0.0.0.0",
                            help="suggested external IP")
        self.peer_parser.add_argument("-lt","--lifetime",type=int,default=3600,
                            help="lifetime")
        self.peer_parser.add_argument("-tp","--thirdparty",
                            help="Third Party address option.")
        self.peer_parser.set_defaults(func=self._do_peer)


        self.ann_parser = self.subparsers.add_parser("announce",help='send announce request')
        self.ann_parser.set_defaults(func=self._do_announce)


        self.get_parser = self.subparsers.add_parser("get",help='send get request')
        self.get_parser.add_argument("-proto","--proto",type=int,default=0,
                            help="Protocol number,udp=17,tcp=6")
        self.get_parser.add_argument("-intip","--intIP",default="0.0.0.0",
                            help="filter internal IP")
        self.get_parser.add_argument("-extip","--extIP",default="0.0.0.0",
                            help="filter external IP")
        self.get_parser.add_argument("-intport","--intPort",type=int,default=0,
                            help="Internal Port")
        self.get_parser.add_argument("-extport","--extPort",type=int,default=0,
                            help="External Port")
        self.get_parser.add_argument("-lt","--lifetime",type=int,default=3600,
                            help="lifetime")
        self.get_parser.add_argument("-next","--nextOption",nargs=argparse.REMAINDER,
                            help="next option. has to be last argument.  -next -h for further help")
        self.get_parser.set_defaults(func=self._do_get)

        self.next_parser=argparse.ArgumentParser(prog="-next")

        self.next_parser.add_argument("-proto","--proto",type=int,default=0,
                            help="Protocol number,udp=17,tcp=6")
        self.next_parser.add_argument("-me","--moreend",type=int,choices=[1,0],default=0,
                            help="more/end")
        self.next_parser.add_argument("-intip","--intIP",default="0.0.0.0",
                            help="filter internal IP")
        self.next_parser.add_argument("-extip","--extIP",default="0.0.0.0",
                            help="filter external IP")
        self.next_parser.add_argument("-intport","--intPort",type=int,default=0,
                            help="Internal Port")
        self.next_parser.add_argument("-extport","--extPort",type=int,default=0,
                            help="External Port")
        self.next_parser.add_argument("-no","--nonce",default="0x000000000000000000000000",
                            help="maping nonce, 12 byte hex str, 0x10abdf,default is all 0 ")
        self.next_parser.add_argument("-mo","--mapoptions",
                            help="maping options code-1/code-2/code-3...")
        self.next_parser.set_defaults(func=self._do_next)



        self.thread=threading.Thread(target=asyncore.loop,kwargs={'timeout':3})
        self.thread.start()

    def _do_map(self,args):
        option_list=[]
        try:
            if args.description != None:
                option_list.append(self.client.pcpc.createDESCRIPTIONOption(args.description))
            if args.thirdparty != None:
                option_list.append(self.client.pcpc.createTHIRD_PARTYOption(args.thirdparty))
            if args.preferfailure:
                option_list.append(self.client.pcpc.createPREFER_FAILUREOption())
            if args.filter != None:
                for f in args.filter:
                    filter_option=f.split("/")
                    filter_option[1]=int(filter_option[1])
                    filter_option[2]=int(filter_option[2])
                    option_list.append(self.client.pcpc.createFILTEROption(
                            filter_option[1],filter_option[2],filter_option[0]))
            if args.portreserv:
                option_list.append(self.client.pcpc.createPORT_RESRVOption())
            self.client.sendMAPRequest(args.lifetime,args.proto,args.intPort,
                                        args.extPort,args.extIP,option_list)
        except Exception as e:
            print e

    def _do_peer(self,args):
        option_list=[]
        try:
            if args.thirdparty != None:
                option_list.append(self.client.pcpc.createTHIRD_PARTYOption(args.thirdparty))
            self.client.sendPEERRequest(args.lifetime,args.proto,args.intPort,
                                        args.extPort,args.extIP,args.rPort,
                                        args.rIP,option_list)
        except Exception as e:
            print e

    def _do_announce(self,args):
        try:
            self.client.sendANNOUNCERequest()
        except Exception as e:
            print e

    def _do_next(self,args):
        option_list=[]
        try:
            if args.mapoptions != None:
                for m in args.mapoptions.split("/"):
                    option_list.append(chr(int(m)))
            return self.client.pcpc.createNEXTv2Option(args.proto,args.moreend,
                    args.intIP,args.extIP,args.intPort,args.extPort,
                    args.nonce[2:].decode('hex'),option_list)
        except Exception as e:
            print e
            return False

    def _do_get(self,args):
        option_list=[]
        if args.nextOption != None:
            try:
                next_args=self.next_parser.parse_args(args.nextOption)
            except:
                return
            nexts=next_args.func(next_args)
            if nexts == False:
                return False
            option_list.append(nexts)
        try:
            self.client.sendGETRequest(args.lifetime,args.proto,args.intPort,
                                args.extPort,args.intIP,args.extIP,option_list)
        except Exception as e:
            print e

    def default(self, line):
        try:
            args = self.parser.parse_args(shlex.split(line))
        except :
            return
        if hasattr(args, 'func'):
            args.func(args)
        else:
            print "unknow command"

    def help_map(self):
        self.map_parser.print_usage()

    def help_peer(self):
        self.peer_parser.print_usage()

    def help_get(self):
        self.get_parser.print_usage()

    def help_announce(self):
        self.ann_parser.print_usage()

    def emptyline(self):
        """Called when an empty line is entered in response to the prompt.
        If this method is not overridden, it repeats the last nonempty
        command entered.
        """
        if self.lastcmd:
            self.lastcmd = ""
            return self.onecmd('\n')

    def stop(self):
        print "\nclosing..."
        self.client.close()
        self.thread.join(5)

    def printResponse(self,resp):
        print "\n--- recvd PCP response @ {t} ---\n".format(t=time.strftime('%Y-%m-%d %H:%M:%S'))
        pprint.pprint(resp)
        print "\n--- end of response ---\n"

def getAddrFamlify(ipaddr):
    if ":" in ipaddr or ipaddr.count(".")>3:
        return socket.AF_INET6
    else:
        return socket.AF_INET

def main():
    parser = argparse.ArgumentParser(description="PCPv2 Client by Hu Jun")
    parser.add_argument("-d","--DEBUG",action='store_true',
                        help="enable DEBUG output")
    parser.add_argument("-i","--source",required=True,
                        help="source address of requests")
    parser.add_argument("-s","--server",required=True,
                        help="PCP server address")
    args=parser.parse_args()
    if  getAddrFamlify(args.source) != getAddrFamlify(args.server):
        print "Warning:source address and server address are not same IP version"
    cli=CLIPCPClient(args.source,args.server,args.DEBUG)
    try:
        cli.cmdloop("PCPv2 CLI Client by Hu Jun. Jan.2015\nCtrl+C to quit")
    except KeyboardInterrupt:
        cli.stop()




if __name__ == '__main__':
    main()
