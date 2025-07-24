from collections import defaultdict
import time
from enum import Enum
from typing import Optional

from scapy.layers.inet import IP, UDP, Ether, TCP, defragment
from scapy.layers.l2 import Dot1Q


class UDPPacket:
    def __init__(self):
        self.sPort = None
        self.dPort = None
        self.length = 0
        self.checksum = None
        self.payload = bytes()

class TCPPacket:
    def __init__(self):
        self.sPort = None
        self.dPort = None
        self.length = 0
        self.payload = bytes()


class IPPacket:
    def __init__(self):
        self.PacketType = 'Eth' # UDP,TCP,当前只识别这两种
        self.timestamp = 0
        self.sMAC = None
        self.dMAC = None
        self.vlan0ID = None
        self.vlan0CFI = None
        self.vlan0Priority = None
        self.vlan1ID = None
        self.vlan1CFI = None
        self.vlan1Priority = None
        self.eth_type = None # ipv4,ipv6,icmpv4...
        self.sIP: Optional[str] = None
        self.dIP: Optional[str] = None

        self.udp: Optional[UDPPacket] = None
        self.tcp: Optional[TCPPacket] = None
    def init(self):
        self.PacketType = 'Eth'  # UDP,TCP,当前只识别这两种
        self.timestamp = 0
        self.sMAC = None
        self.dMAC = None
        self.vlan0ID = None
        self.vlan0CFI = None
        self.vlan0Priority = None
        self.vlan1ID = None
        self.vlan1CFI = None
        self.vlan1Priority = None
        self.eth_type = None  # ipv4,ipv6,icmpv4...
        self.sIP = None
        self.dIP = None

        self.udp = None
        self.tcp = None




class PayloadType(Enum):
    ETHERNET = 'eth'
    IP = 'ip'

class IPFramProcessor:
    def __init__(self, timeout=1.0, cleanup_interval=5.0):
        self.frame_groups = defaultdict(list)
        self.last_timestamp = {}
        self.fragment_info = defaultdict(dict)
        self.timeout = timeout
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()


    def process_frame(self, timestamp, payload_bytes, payload_type: PayloadType, sMAC = None, dMAC = None, vlanID = None, vlanpcp = None):
        try:
            # 清理过期数据
            self._cleanup_old_fragments()
            # 验证payload_type参数
            if not isinstance(payload_type, PayloadType):
                raise TypeError("payload_type参数必须是PayloadType枚举值")

            if payload_type == PayloadType.IP: # 输入为ip包
                # 解析IP包
                eth_IP_packet = IP(payload_bytes)
                packet_id = eth_IP_packet.id

                # 更新时间戳
                self.last_timestamp[packet_id] = float(timestamp)

                # 检查是否是第一个分片
                if eth_IP_packet.frag == 0:
                    # 记录总长度信息（如果在flags中标记了MF-More Fragments）
                    self.fragment_info[packet_id]['sMAC'] = sMAC
                    self.fragment_info[packet_id]['dMAC'] = dMAC
                    self.fragment_info[packet_id]['vlanID'] = vlanID
                    self.fragment_info[packet_id]['vlanpcp'] = vlanpcp
                    self.fragment_info[packet_id]['total_length'] = eth_IP_packet.len
                    self.fragment_info[packet_id]['is_complete'] = not (eth_IP_packet.flags & 1)

                # 添加分片到组
                self.frame_groups[packet_id].append(eth_IP_packet)

                # 检查是否可以重组
                if self._can_reassemble(packet_id):
                    return self._reassemble_and_process(packet_id)
            elif payload_type == PayloadType.ETHERNET:  # 输入为eth包
                eth_packet = Ether(payload_bytes)
                if IP not in eth_packet:
                    return

                eth_IP_packet = eth_packet[IP]
                packet_id = eth_IP_packet.id

                # 更新时间戳
                self.last_timestamp[packet_id] = float(timestamp)

                # 检查是否是第一个分片
                if eth_IP_packet.frag == 0:
                    # 记录总长度信息（如果在flags中标记了MF-More Fragments）
                    self.fragment_info[packet_id]['sMAC'] = eth_packet.src
                    self.fragment_info[packet_id]['dMAC'] = eth_packet.dst
                    if eth_packet.type == 0x8100 and Dot1Q in eth_packet: # 带vlan
                        self.fragment_info[packet_id]['vlanID'] = eth_packet[Dot1Q].vlan
                        self.fragment_info[packet_id]['vlanpcp'] = eth_packet[Dot1Q].prio
                    else:
                        self.fragment_info[packet_id]['vlanID'] = vlanID
                        self.fragment_info[packet_id]['vlanpcp'] = vlanpcp
                    self.fragment_info[packet_id]['total_length'] = eth_IP_packet.len
                    self.fragment_info[packet_id]['is_complete'] = not (eth_IP_packet.flags & 1)

                # 添加分片到组
                self.frame_groups[packet_id].append(eth_IP_packet)

                # 检查是否可以重组
                if self._can_reassemble(packet_id):
                    return self._reassemble_and_process(packet_id)


        except Exception as e:
            print(f"处理帧时出错: {e}")
        return None

    def _can_reassemble(self, packet_id):
        """
        检查是否可以重组分片，基于以下条件：
        1. 最后一个分片已收到（flags中MF位为0）
        2. 所有分片都已收到（通过偏移量和长度检查）
        """
        if packet_id not in self.frame_groups:
            return False

        fragments = self.frame_groups[packet_id]
        if not fragments:
            return False

        # 排序分片
        fragments.sort(key=lambda x: x.frag)

        # 检查是否有最后一个分片（MF标志位为0）
        has_last_fragment = any(not (f.flags & 1) for f in fragments)
        if not has_last_fragment:
            return False

        # 检查分片是否连续
        expected_offset = 0
        for frag in fragments:
            if frag.frag != expected_offset:
                return False
            # 计算下一个预期偏移量（以8字节为单位）
            expected_offset = frag.frag + (len(frag.payload) // 8)

        return True

    def _reassemble_and_process(self, packet_id):
        """重组并处理完整的包"""
        try:
            fragments = self.frame_groups[packet_id]
            reassembled = defragment(fragments)
            # 处理重组后的包
            result = self._process_reassembled_packet(reassembled, packet_id)

            # 清理已处理的数据
            self._cleanup_packet_data(packet_id)

            return result

        except Exception as e:
            print(f"重组包时出错 (ID {packet_id}): {e}")
            self._cleanup_packet_data(packet_id)
            return None

    def _process_reassembled_packet(self, reassembled , packet_id) -> list[IPPacket]:
        """处理重组后的包，识别协议类型并相应处理"""
        results = []
        for packet in reassembled:
            ip_packet = IPPacket()
            ip_packet.timestamp = self.last_timestamp[packet_id]
            ip_packet.sIP = packet[IP].src
            ip_packet.dIP = packet[IP].dst
            ip_packet.sMAC = self.fragment_info[packet_id]['sMAC']
            ip_packet.dMAC = self.fragment_info[packet_id]['dMAC']
            ip_packet.vlan0ID = self.fragment_info[packet_id]['vlanID']
            ip_packet.vlan0Priority = self.fragment_info[packet_id]['vlanpcp']
            ip_packet.vlan0CFI = 0

            # UDP包处理
            if UDP in packet:
                ip_packet.PacketType = 'UDP'
                ip_packet.udp = UDPPacket()
                ip_packet.udp.sPort = packet[UDP].sport
                ip_packet.udp.dPort = packet[UDP].dport
                ip_packet.udp.length = len(packet[UDP].payload)
                ip_packet.udp.payload = bytes(packet[UDP].payload)

            elif TCP in packet:
                ip_packet.PacketType = 'TCP'
                ip_packet.tcp = TCPPacket()
                ip_packet.tcp.sPort = packet[TCP].sport
                ip_packet.tcp.dPort = packet[TCP].dport
                ip_packet.tcp.length = len(packet[TCP].payload)
                ip_packet.tcp.payload = bytes(packet[TCP].payload)

            results.append(ip_packet)

        return results

    def _cleanup_packet_data(self, packet_id):
        """清理特定包ID的所有相关数据"""
        self.frame_groups.pop(packet_id, None)
        self.last_timestamp.pop(packet_id, None)
        self.fragment_info.pop(packet_id, None)

    def _cleanup_old_fragments(self):
        """清理超时的分片"""
        current_time = time.time()

        # 检查是否需要执行清理
        if current_time - self.last_cleanup < self.cleanup_interval:
            return

        self.last_cleanup = current_time

        for packet_id in list(self.last_timestamp.keys()):
            if current_time - self.last_timestamp[packet_id] > self.timeout:
                print(f"清理超时的分片组 IP ID {packet_id}")
                self._cleanup_packet_data(packet_id)