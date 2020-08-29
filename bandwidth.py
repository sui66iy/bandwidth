
import collections
import time

from scapy.all import IP, sniff
from scapy.config import conf

import vendor

conf.use_pcap = True


class Packets:

    def __init__(self, incoming_only=True):
        self.incoming_only = incoming_only
        self.reset()

    def reset(self):
        self.packets = collections.defaultdict(list)

    def add_packet(self, pkt):
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst

            if self.incoming_only:
                if ip_src.startswith('10.'):
                    # discard packets originating within our network
                    return
                if not ip_dst.startswith('10.'):
                    # discard packets destined for outside our network
                    return

            self.packets[(ip_src, ip_dst)].append(pkt)

        return

    def get_bandwidth(self):
        bandwidth = []

        for ips in self.packets:
            ips_bytes = 0

            for pkt in self.packets[ips]:
                ips_bytes += len(pkt[IP])

            bandwidth.append((ips_bytes, ips))

        bandwidth.sort(reverse=True)

        return [(ips, bw) for (bw, ips) in bandwidth]

    def get_ip_to_vendor(self):
        mac2ip = collections.defaultdict(list)
        for pkt_list in self.packets.values():
            for pkt in pkt_list:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_mac = pkt.src
                dst_mac = pkt.dst
                mac2ip[src_mac].append(src_ip)
                mac2ip[dst_mac].append(dst_ip)

        ip2vendor = {}
        for mac in mac2ip:
            ips = mac2ip[mac]
            vend = vendor.get_mac_details(mac) or mac
            time.sleep(1)
            for ip in ips:
                ip2vendor[ip] = vend

        return ip2vendor

    def report_kbps(self, duration):
        bandwidth = self.get_bandwidth()

        ip2vendor = self.get_ip_to_vendor()

        for ((src, dst), bw) in bandwidth:
            bytes_per_second = bw / duration
            bps = bytes_per_second * 8
            src_vendor = ip2vendor[src]
            dst_vendor = ip2vendor[dst]
            print(f'{src} ({src_vendor}) -> {dst} ({dst_vendor}): {bps:.2f}')

        return


def main(timeout=10):
    packets = Packets()

    sniff(prn=packets.add_packet,
          timeout=timeout)

    packets.report_kbps(timeout)

    return packets


if __name__ == '__main__':
    main()
