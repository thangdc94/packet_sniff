import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '
DATA_TAB_4 = '\t\t\t\t  '

ETH_P_ALL = 3		# To receive all Ethernet protocols

class PacketSniff:
    conn = None
    stopped = False

    def start(self):
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.ntohs(ETH_P_ALL))
        stopped = False
        while (not stopped):
            raw_data, addr = self.conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(
                TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

            # 8 for IPv4
            if eth_proto == 8:
                (version, header_length, ttl, proto,
                 src, target, data) = self.ipv4_packet(data)
                print(TAB_1 + 'IPv4 Packet:')
                print(
                    TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(
                    TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = self.icmp_packet(data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(
                        TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'Data:')
                    print(self.format_multi_line(DATA_TAB_3, data))

                # TCP
                # Video 7
                elif proto == 6:
                    # not sure, data ot data[offset] in next line
                    (src_port, dest_port, sequence, acknowledge, flag_urg, flag_ack,
                     flag_psh, flag_rst, flag_syn, flag_fin, data) = self.tcp_segment(data)
                    print(TAB_1 + 'TCP Segment:')
                    print(
                        TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(
                        TAB_2 + 'Sequence: {}, Acknowledge: {}'.format(sequence, acknowledge))
                    print(TAB_2 + 'Flags')
                    # not sure next line
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                        flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(TAB_2 + 'Data')
                    print(self.format_multi_line(DATA_TAB_3, data))

                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = self.udp_segment(data)
                    print(TAB_1 + 'UDP Segment:')
                    # not sure last length in next line
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, length: {}'.format(
                        src_port, dest_port, length))

                # other
                else:
                    print(TAB_1 + 'Data:')
                    print(self.format_multi_line(DATA_TAB_2, data))
            else:
                print('Data:')
                print(self.format_multi_line(DATA_TAB_1, data))
    
    def stop(self):
        self.stopped = True
        self.conn.close()

    # unpack ethernet frame

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # return properly formatted MAC address (ie AA:BB:CC:DD:EE:FF)

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    # unpacks IPv4 paket

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x b b 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    # Return properly formatted IPv4 address

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    # Unpack ICMP packet

    def icmp_packet(self, data):

        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    # unpack TCP segment

    def tcp_segment(self, data):
        (src_port, dest_port, sequence, acknowledgement,
         offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    # unpack UDP segment

    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    # format multi-line data

    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(chr(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
