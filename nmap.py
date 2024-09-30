#!/usr/bin/python3

# Copyright (C) 2024 strangebit
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2024, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@strangebit.io"
__status__ = "development"

# Import the needed libraries
# RE library
import re
# Sockets
import socket
import select
# Timing
import time
# Timing 
from time import time, sleep
# Network stuff
import socket
import packets
import argparse
# Utils 
from utils import Misc, Checksum
# Hex
from binascii import unhexlify, hexlify
# Packets
from packets import IPv4Packet, TCPPacket

parser = argparse.ArgumentParser(
                        prog='nc',
                        description='Scans for open ports on the remote machine')

parser.add_argument("--src", dest="src", required=True, help="Source address")
parser.add_argument("--dst", dest="dst", required=True, help="Destination address")
parser.add_argument("--source-port", dest="sport", required=True, help="Source port", type=int)
parser.add_argument("--destination-port", dest="dport", required=False, help="Destination port", type=int)
parser.add_argument("--timeout", dest="timeout", required=True, help="Wait timeout", type=int, default=1)
args = parser.parse_args()

args = parser.parse_args()

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, packets.TCP_PROTOCOL_NUMBER)
s.bind((args.src, 0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

if not args.dport:

    for dport in range(1, 2**16-1):
        tcp = packets.TCPPacket()
        tcp.set_source_port(args.sport)
        tcp.set_destination_port(dport)
        tcp.set_sequence_number(1)
        tcp.set_syn_bit(1)
        tcp.set_window(4096)
        tcp.set_data_offset(5)

        pseudo_header = Misc.make_pseudo_header(Misc.ipv4_address_to_bytes(args.src), \
                                                                        Misc.ipv4_address_to_bytes(args.dst), \
                                                                        Misc.int_to_bytes(len(tcp.get_buffer())))
        checksum = Checksum.checksum(pseudo_header + tcp.get_buffer()) & 0xFFFF



        tcp.set_checksum(checksum)

        ipv4 = IPv4Packet()
        ipv4.set_destination_address(Misc.ipv4_address_to_bytes(args.dst))
        ipv4.set_source_address(Misc.ipv4_address_to_bytes(args.src))
        ipv4.set_protocol(packets.TCP_PROTOCOL_NUMBER)
        ipv4.set_ttl(packets.IP_DEFAULT_TTL)
        ipv4.set_payload(tcp.get_buffer())

        s.sendto(ipv4.get_buffer(), (args.dst, 0))

        stime = time() + args.timeout
        while True:
            ready = select.select([s], [], [], args.timeout)
            if ready[0]:
                buf = s.recv(1522)
                
                ipv4 = IPv4Packet(buf)
                if ipv4.get_protocol() != packets.TCP_PROTOCOL_NUMBER:
                    continue
                    
                tcp = TCPPacket(ipv4.get_payload())
                
                if args.dst == Misc.ipv4_address_bytes_to_string(ipv4.get_source_address()) and \
                    args.src == Misc.ipv4_address_bytes_to_string(ipv4.get_destination_address()):

                    if args.sport == tcp.get_destination_port() and \
                        dport == tcp.get_source_port():
                        if tcp.get_syn_bit() and tcp.get_ack_bit():
                            print("Port is open %s" % dport)
                            break
            if stime <= time():
                print("Port %s is closed" % dport)
                break

else:
    tcp = packets.TCPPacket()
    tcp.set_source_port(args.sport)
    tcp.set_destination_port(args.dport)
    tcp.set_sequence_number(1)
    tcp.set_syn_bit(1)
    tcp.set_window(4096)
    tcp.set_data_offset(5)

    pseudo_header = Misc.make_pseudo_header(Misc.ipv4_address_to_bytes(args.src), \
                                                                    Misc.ipv4_address_to_bytes(args.dst), \
                                                                    Misc.int_to_bytes(len(tcp.get_buffer())))
    checksum = Checksum.checksum(pseudo_header + tcp.get_buffer()) & 0xFFFF



    tcp.set_checksum(checksum)

    ipv4 = IPv4Packet()
    ipv4.set_destination_address(Misc.ipv4_address_to_bytes(args.dst))
    ipv4.set_source_address(Misc.ipv4_address_to_bytes(args.src))
    ipv4.set_protocol(packets.TCP_PROTOCOL_NUMBER)
    ipv4.set_ttl(packets.IP_DEFAULT_TTL)
    ipv4.set_payload(tcp.get_buffer())

    s.sendto(ipv4.get_buffer(), (args.dst, 0))

    stime = time() + args.timeout
    while True:
        ready = select.select([s], [], [], args.timeout)
        if ready[0]:
            buf = s.recv(1522)
            
            ipv4 = IPv4Packet(buf)
            if ipv4.get_protocol() != packets.TCP_PROTOCOL_NUMBER:
                continue
                
            tcp = TCPPacket(ipv4.get_payload())
            
            if args.dst == Misc.ipv4_address_bytes_to_string(ipv4.get_source_address()) and \
                args.src == Misc.ipv4_address_bytes_to_string(ipv4.get_destination_address()):

                if args.sport == tcp.get_destination_port() and \
                    args.dport == tcp.get_source_port():
                    if tcp.get_syn_bit() and tcp.get_ack_bit():
                        print("Port is open %s" % args.dport)
                        break
        if stime <= time():
            print("Timeout... no response from server")
            break
