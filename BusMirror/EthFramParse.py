from collections import defaultdict
import time
from scapy.layers.inet import IP, UDP, defragment

class IPFramProcessor:
    def __init__(self, timeout=1.0, cleanup_interval=5.0):
        self.frame_groups = defaultdict(list)
        self.last_timestamp = {}
        self.fragment_info = defaultdict(dict)
        self.timeout = timeout
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()

    def process_frame(self, timestamp, payload_bytes):
        try:
            # 清理过期数据
            self._cleanup_old_fragments()

            # 解析IP包
            ip_packet = IP(payload_bytes)
            packet_id = ip_packet.id

            # 更新时间戳
            self.last_timestamp[packet_id] = float(timestamp)

            # 检查是否是第一个分片
            if ip_packet.frag == 0:
                # 记录总长度信息（如果在flags中标记了MF-More Fragments）
                self.fragment_info[packet_id]['total_length'] = ip_packet.len
                self.fragment_info[packet_id]['is_complete'] = not (ip_packet.flags & 1)

            # 添加分片到组
            self.frame_groups[packet_id].append(ip_packet)

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
            result = self._process_reassembled_packet(reassembled)

            # 清理已处理的数据
            self._cleanup_packet_data(packet_id)

            return result

        except Exception as e:
            print(f"重组包时出错 (ID {packet_id}): {e}")
            self._cleanup_packet_data(packet_id)
            return None

    def _process_reassembled_packet(self, reassembled):
        """处理重组后的包，识别协议类型并相应处理"""
        results = []
        for packet in reassembled:
            packet_info = {
                'protocol': 'unknown',
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'length': len(packet),
                'data': {}
            }

            # UDP包处理
            if UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['data'] = {
                    'sport': packet[UDP].sport,
                    'dport': packet[UDP].dport,
                    'length': len(packet[UDP]),
                    'payload': bytes(packet[UDP].payload)
                }

            # 可以添加其他协议的处理（如TCP、ICMP等）
            # elif TCP in packet:
            #     packet_info['protocol'] = 'TCP'
            #     # TCP特定处理...

            results.append(packet_info)

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