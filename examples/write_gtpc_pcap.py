#!/usr/bin/env python
"""
Wrap every GTPv1-C and GTPv2-C factory message in Ethernet / IPv4 / UDP and
write the resulting frames to a pcap file.

The packets follow two realistic signalling flows:

  LTE (GTPv2-C)  — S11 interface between MME and SGW
    Echo, Attach (Create Session), eNB handover (Modify Bearer),
    dedicated bearer (Create/Delete Bearer), idle mode
    (Release Access Bearers + DL Data Notification), Detach (Delete Session)

  3G  (GTPv1-C)  — Gn interface between SGSN and GGSN
    Echo, Create/Update/Delete PDP Context

Output: examples/data/gtpc_example.pcap
"""
import os
import socket
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import dpkt
from dpkt.ethernet import Ethernet, ETH_TYPE_IP
from dpkt.ip import IP, IP_PROTO_UDP
from dpkt.udp import UDP
from dpkt.gtpc_factory import GTPv1CFactory, GTPv2CFactory

# ── constants ────────────────────────────────────────────────────────────────

GTP_C_PORT = 2123

# Node tuples: (label, MAC, IPv4)
MME  = ('MME',  '02:00:00:00:00:01', '10.10.10.1')
SGW  = ('SGW',  '02:00:00:00:00:02', '10.10.10.2')
SGSN = ('SGSN', '02:00:00:00:00:03', '10.20.20.1')
GGSN = ('GGSN', '02:00:00:00:00:04', '10.20.20.2')

# UE / subscriber identity
IMSI      = '001011234567890'
MSISDN    = '447700900001'
MEI       = '3569870129304757'
APN       = 'internet.epc.mnc001.mcc001.gprs'

# TEIDs allocated by each node's control plane
MME_CP_TEID  = 0x0000_1111
SGW_CP_TEID  = 0x0000_2222
SGW_UP_TEID  = 0x0000_3333
ENB_UP_TEID  = 0x0000_4444
PGW_UP_TEID  = 0x0000_5555

SGSN_CP_TEID = 0x0000_aaaa
SGSN_UP_TEID = 0x0000_bbbb
GGSN_CP_TEID = 0x0000_cccc
GGSN_UP_TEID = 0x0000_dddd

# ── frame builder ─────────────────────────────────────────────────────────────

_ip_id = 1  # incremented per frame so Wireshark can distinguish them


def make_frame(src, dst, gtp_pkt):
    """Wrap a GTP packet object in UDP / IPv4 / Ethernet bytes."""
    global _ip_id
    payload = bytes(gtp_pkt)
    udp = UDP(sport=GTP_C_PORT, dport=GTP_C_PORT, data=payload)
    udp.ulen = 8 + len(payload)
    ip = IP(
        src=socket.inet_aton(src[2]),
        dst=socket.inet_aton(dst[2]),
        p=IP_PROTO_UDP,
        data=udp,
        ttl=64,
        id=_ip_id,
    )
    _ip_id += 1
    eth = Ethernet(
        src=bytes.fromhex(src[1].replace(':', '')),
        dst=bytes.fromhex(dst[1].replace(':', '')),
        type=ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


# ── signalling flows ──────────────────────────────────────────────────────────

def lte_flow():
    """LTE attach / bearer management / detach on the S11 MME–SGW interface."""
    seq = 1
    pkts = []

    # ── path management ──────────────────────────────────────────────────────
    pkts.append((0.000, MME, SGW, 'Echo Request',
                 GTPv2CFactory.echo_req(seqnum=seq)))
    seq += 1

    pkts.append((0.010, SGW, MME, 'Echo Response',
                 GTPv2CFactory.echo_res(seqnum=seq - 1, recovery=0)))

    # ── initial attach ───────────────────────────────────────────────────────
    pkts.append((1.000, MME, SGW, 'Create Session Request',
                 GTPv2CFactory.create_session_req(
                     teid=0,
                     seqnum=seq,
                     imsi=IMSI,
                     msisdn=MSISDN,
                     mei=MEI,
                     rat_type=6,           # EUTRAN
                     apn=APN,
                     pdn_type=1,           # IPv4
                     sender_teid=MME_CP_TEID,
                     sender_ipv4=MME[2],
                     ebi=5,
                     qci=9,
                     ambr_ul=50_000,
                     ambr_dl=100_000,
                 )))
    seq += 1

    pkts.append((1.020, SGW, MME, 'Create Session Response',
                 GTPv2CFactory.create_session_res(
                     teid=MME_CP_TEID,
                     seqnum=seq - 1,
                     sender_teid=SGW_CP_TEID,
                     sender_ipv4=SGW[2],
                     ebi=5,
                     fteid_data_teid=SGW_UP_TEID,
                     fteid_data_ipv4=SGW[2],
                     ambr_ul=50_000,
                     ambr_dl=100_000,
                     recovery=0,
                 )))

    # ── eNB attached — update access-side data-plane F-TEID ─────────────────
    pkts.append((1.100, MME, SGW, 'Modify Bearer Request',
                 GTPv2CFactory.modify_bearer_req(
                     teid=SGW_CP_TEID,
                     seqnum=seq,
                     ebi=5,
                     rat_type=6,
                     fteid_data_teid=ENB_UP_TEID,
                     fteid_data_ipv4='192.168.100.1',
                 )))
    seq += 1

    pkts.append((1.110, SGW, MME, 'Modify Bearer Response',
                 GTPv2CFactory.modify_bearer_res(
                     teid=MME_CP_TEID,
                     seqnum=seq - 1,
                     ebi=5,
                 )))

    # ── PGW requests a dedicated bearer (e.g. for VoLTE) ────────────────────
    pkts.append((2.000, SGW, MME, 'Create Bearer Request',
                 GTPv2CFactory.create_bearer_req(
                     teid=MME_CP_TEID,
                     seqnum=seq,
                     linked_ebi=5,
                     ebi=6,
                     qci=1,               # conversational voice
                     pci=1,
                     pl=8,
                     mbr_ul=1_024,
                     mbr_dl=1_024,
                     gbr_ul=512,
                     gbr_dl=512,
                     fteid_data_teid=PGW_UP_TEID,
                     fteid_data_ipv4='10.30.30.1',
                 )))
    seq += 1

    pkts.append((2.030, MME, SGW, 'Create Bearer Response',
                 GTPv2CFactory.create_bearer_res(
                     teid=SGW_CP_TEID,
                     seqnum=seq - 1,
                     ebi=6,
                     fteid_data_teid=ENB_UP_TEID,
                     fteid_data_ipv4='192.168.100.1',
                 )))

    # ── UE moves to idle mode ────────────────────────────────────────────────
    pkts.append((3.000, MME, SGW, 'Release Access Bearers Request',
                 GTPv2CFactory.release_access_bearers_req(
                     teid=SGW_CP_TEID,
                     seqnum=seq,
                 )))
    seq += 1

    pkts.append((3.010, SGW, MME, 'Release Access Bearers Response',
                 GTPv2CFactory.release_access_bearers_res(
                     teid=MME_CP_TEID,
                     seqnum=seq - 1,
                 )))

    # ── downlink data wakes UE ───────────────────────────────────────────────
    pkts.append((4.000, SGW, MME, 'Downlink Data Notification',
                 GTPv2CFactory.dl_data_notification(
                     teid=MME_CP_TEID,
                     seqnum=seq,
                     ebi=5,
                     arp_pl=8,
                 )))
    seq += 1

    pkts.append((4.005, MME, SGW, 'Downlink Data Notification Ack',
                 GTPv2CFactory.dl_data_notification_ack(
                     teid=SGW_CP_TEID,
                     seqnum=seq - 1,
                 )))

    # ── tear down dedicated bearer ───────────────────────────────────────────
    pkts.append((5.000, SGW, MME, 'Delete Bearer Request',
                 GTPv2CFactory.delete_bearer_req(
                     teid=MME_CP_TEID,
                     seqnum=seq,
                     ebi=6,
                 )))
    seq += 1

    pkts.append((5.010, MME, SGW, 'Delete Bearer Response',
                 GTPv2CFactory.delete_bearer_res(
                     teid=SGW_CP_TEID,
                     seqnum=seq - 1,
                     ebi=6,
                 )))

    # ── detach ───────────────────────────────────────────────────────────────
    pkts.append((6.000, MME, SGW, 'Delete Session Request',
                 GTPv2CFactory.delete_session_req(
                     teid=SGW_CP_TEID,
                     seqnum=seq,
                     ebi=5,
                     sender_teid=MME_CP_TEID,
                     sender_ipv4=MME[2],
                 )))
    seq += 1

    pkts.append((6.020, SGW, MME, 'Delete Session Response',
                 GTPv2CFactory.delete_session_res(
                     teid=MME_CP_TEID,
                     seqnum=seq - 1,
                 )))

    return pkts


def gprs_flow():
    """3G GPRS PDP context lifecycle on the Gn SGSN–GGSN interface."""
    seq = 1
    # Timestamps offset from t=10 so they follow the LTE flow in the pcap
    pkts = []

    pkts.append((10.000, SGSN, GGSN, 'Echo Request',
                 GTPv1CFactory.echo_req(teid=0, seqnum=seq)))
    seq += 1

    pkts.append((10.010, GGSN, SGSN, 'Echo Response',
                 GTPv1CFactory.echo_res(teid=0, seqnum=seq - 1, recovery=0)))

    pkts.append((11.000, SGSN, GGSN, 'Create PDP Context Request',
                 GTPv1CFactory.create_pdp_ctx_req(
                     teid=0,
                     seqnum=seq,
                     imsi=IMSI,
                     nsapi=5,
                     teid_data=SGSN_UP_TEID,
                     teid_cplane=SGSN_CP_TEID,
                     selection_mode=0,
                     apn=APN,
                     msisdn=MSISDN,
                     recovery=0,
                 )))
    seq += 1

    pkts.append((11.020, GGSN, SGSN, 'Create PDP Context Response',
                 GTPv1CFactory.create_pdp_ctx_res(
                     teid=SGSN_CP_TEID,
                     seqnum=seq - 1,
                     teid_data=GGSN_UP_TEID,
                     teid_cplane=GGSN_CP_TEID,
                     charging_id=0xdeadbeef,
                     recovery=0,
                 )))

    pkts.append((12.000, SGSN, GGSN, 'Update PDP Context Request',
                 GTPv1CFactory.update_pdp_ctx_req(
                     teid=GGSN_CP_TEID,
                     seqnum=seq,
                     nsapi=5,
                     teid_data=SGSN_UP_TEID,
                     teid_cplane=SGSN_CP_TEID,
                 )))
    seq += 1

    pkts.append((12.010, GGSN, SGSN, 'Update PDP Context Response',
                 GTPv1CFactory.update_pdp_ctx_res(
                     teid=SGSN_CP_TEID,
                     seqnum=seq - 1,
                     teid_data=GGSN_UP_TEID,
                     teid_cplane=GGSN_CP_TEID,
                     charging_id=0xdeadbeef,
                 )))

    pkts.append((13.000, SGSN, GGSN, 'Delete PDP Context Request',
                 GTPv1CFactory.delete_pdp_ctx_req(
                     teid=GGSN_CP_TEID,
                     seqnum=seq,
                     nsapi=5,
                     teardown_ind=True,
                 )))
    seq += 1

    pkts.append((13.010, GGSN, SGSN, 'Delete PDP Context Response',
                 GTPv1CFactory.delete_pdp_ctx_res(
                     teid=SGSN_CP_TEID,
                     seqnum=seq - 1,
                 )))

    return pkts


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    out_path = os.path.join(os.path.dirname(__file__), 'data', 'gtpc_example.pcap')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    packets = lte_flow() + gprs_flow()

    with open(out_path, 'wb') as f:
        writer = dpkt.pcap.Writer(f)
        for ts, src, dst, desc, gtp_pkt in packets:
            frame = make_frame(src, dst, gtp_pkt)
            writer.writepkt(frame, ts=ts)
            raw_gtp = bytes(gtp_pkt)
            print(f't={ts:6.3f}  {src[0]:4s} -> {dst[0]:4s}  {desc}  ({len(frame)}B frame / {len(raw_gtp)}B GTP)')

    print(f'\nWrote {len(packets)} packets to {out_path}')


if __name__ == '__main__':
    main()
