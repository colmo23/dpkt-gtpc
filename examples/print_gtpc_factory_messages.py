#!/usr/bin/env python
"""
Generate one example of every GTPv1-C and GTPv2-C message type using the
factory and print each as a hex dump.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dpkt import hexdump
from dpkt.gtpc_factory import GTPv1CFactory, GTPv2CFactory

# ── shared test values ────────────────────────────────────────────────────────
IMSI      = '001011234567890'
MSISDN    = '447700900001'
MEI       = '3569870129304757'
APN       = 'internet.epc.mnc001.mcc001.gprs'
TEID_CP   = 0x0000_1234   # control-plane TEID
TEID_UP   = 0x0000_5678   # user-plane TEID
MME_IP    = '10.10.10.1'
SGW_CP_IP = '10.20.20.1'
SGW_UP_IP = '10.20.20.2'
ENB_UP_IP = '192.168.100.1'
PGW_UP_IP = '10.30.30.1'
SEQNUM    = 0x000001

# ── helpers ───────────────────────────────────────────────────────────────────

def show(title, pkt):
    raw = bytes(pkt)
    print(f'─── {title} ({len(raw)} bytes) ───')
    print(hexdump(raw))
    print()


# ── GTPv1-C messages ──────────────────────────────────────────────────────────

def v1_messages():
    print('═' * 60)
    print('  GTPv1-C messages')
    print('═' * 60)
    print()

    show('Echo Request',
         GTPv1CFactory.echo_req(
             teid=0,
             seqnum=SEQNUM,
         ))

    show('Echo Response',
         GTPv1CFactory.echo_res(
             teid=0,
             seqnum=SEQNUM,
             recovery=5,
         ))

    show('Create PDP Context Request',
         GTPv1CFactory.create_pdp_ctx_req(
             teid=0,
             seqnum=SEQNUM,
             imsi=IMSI,
             nsapi=5,
             teid_data=TEID_UP,
             teid_cplane=TEID_CP,
             selection_mode=0,
             charging_chars=0x0800,
             apn=APN,
             msisdn=MSISDN,
             recovery=0,
         ))

    show('Create PDP Context Response',
         GTPv1CFactory.create_pdp_ctx_res(
             teid=TEID_CP,
             seqnum=SEQNUM,
             nsapi=5,
             teid_data=TEID_UP,
             teid_cplane=TEID_CP,
             charging_id=0xdeadbeef,
             recovery=0,
         ))

    show('Update PDP Context Request',
         GTPv1CFactory.update_pdp_ctx_req(
             teid=TEID_CP,
             seqnum=SEQNUM + 1,
             nsapi=5,
             teid_data=TEID_UP,
             teid_cplane=TEID_CP,
         ))

    show('Update PDP Context Response',
         GTPv1CFactory.update_pdp_ctx_res(
             teid=TEID_CP,
             seqnum=SEQNUM + 1,
             teid_data=TEID_UP,
             teid_cplane=TEID_CP,
             charging_id=0xdeadbeef,
         ))

    show('Delete PDP Context Request  (with teardown)',
         GTPv1CFactory.delete_pdp_ctx_req(
             teid=TEID_CP,
             seqnum=SEQNUM + 2,
             nsapi=5,
             teardown_ind=True,
         ))

    show('Delete PDP Context Response',
         GTPv1CFactory.delete_pdp_ctx_res(
             teid=TEID_CP,
             seqnum=SEQNUM + 2,
         ))


# ── GTPv2-C messages ──────────────────────────────────────────────────────────

def v2_messages():
    print('═' * 60)
    print('  GTPv2-C messages')
    print('═' * 60)
    print()

    show('Echo Request',
         GTPv2CFactory.echo_req(
             seqnum=SEQNUM,
         ))

    show('Echo Response',
         GTPv2CFactory.echo_res(
             seqnum=SEQNUM,
             recovery=5,
         ))

    show('Create Session Request',
         GTPv2CFactory.create_session_req(
             teid=0,
             seqnum=SEQNUM,
             imsi=IMSI,
             msisdn=MSISDN,
             mei=MEI,
             rat_type=6,            # EUTRAN
             apn=APN,
             pdn_type=1,            # IPv4
             sender_teid=TEID_CP,
             sender_ipv4=MME_IP,
             ebi=5,
             qci=9,
             ambr_ul=50_000,
             ambr_dl=100_000,
         ))

    show('Create Session Response',
         GTPv2CFactory.create_session_res(
             teid=TEID_CP,
             seqnum=SEQNUM,
             sender_teid=TEID_CP,
             sender_ipv4=SGW_CP_IP,
             ebi=5,
             fteid_data_teid=TEID_UP,
             fteid_data_ipv4=SGW_UP_IP,
             ambr_ul=50_000,
             ambr_dl=100_000,
             recovery=0,
         ))

    show('Modify Bearer Request',
         GTPv2CFactory.modify_bearer_req(
             teid=TEID_CP,
             seqnum=SEQNUM + 1,
             ebi=5,
             rat_type=6,
             fteid_data_teid=TEID_UP,
             fteid_data_ipv4=ENB_UP_IP,
         ))

    show('Modify Bearer Response',
         GTPv2CFactory.modify_bearer_res(
             teid=TEID_CP,
             seqnum=SEQNUM + 1,
             ebi=5,
         ))

    show('Delete Session Request',
         GTPv2CFactory.delete_session_req(
             teid=TEID_CP,
             seqnum=SEQNUM + 2,
             ebi=5,
             sender_teid=TEID_CP,
             sender_ipv4=MME_IP,
         ))

    show('Delete Session Response',
         GTPv2CFactory.delete_session_res(
             teid=TEID_CP,
             seqnum=SEQNUM + 2,
         ))

    show('Create Bearer Request  (dedicated bearer, QCI-1 voice)',
         GTPv2CFactory.create_bearer_req(
             teid=TEID_CP,
             seqnum=SEQNUM + 3,
             linked_ebi=5,
             ebi=6,
             qci=1,
             pci=1,
             pl=8,
             mbr_ul=1_024,
             mbr_dl=1_024,
             gbr_ul=512,
             gbr_dl=512,
             fteid_data_teid=TEID_UP,
             fteid_data_ipv4=PGW_UP_IP,
         ))

    show('Create Bearer Response',
         GTPv2CFactory.create_bearer_res(
             teid=TEID_CP,
             seqnum=SEQNUM + 3,
             ebi=6,
             fteid_data_teid=TEID_UP,
             fteid_data_ipv4=ENB_UP_IP,
         ))

    show('Delete Bearer Request',
         GTPv2CFactory.delete_bearer_req(
             teid=TEID_CP,
             seqnum=SEQNUM + 4,
             ebi=6,
         ))

    show('Delete Bearer Response',
         GTPv2CFactory.delete_bearer_res(
             teid=TEID_CP,
             seqnum=SEQNUM + 4,
             ebi=6,
         ))

    show('Release Access Bearers Request',
         GTPv2CFactory.release_access_bearers_req(
             teid=TEID_CP,
             seqnum=SEQNUM + 5,
         ))

    show('Release Access Bearers Response',
         GTPv2CFactory.release_access_bearers_res(
             teid=TEID_CP,
             seqnum=SEQNUM + 5,
         ))

    show('Downlink Data Notification',
         GTPv2CFactory.dl_data_notification(
             teid=TEID_CP,
             seqnum=SEQNUM + 6,
             ebi=5,
             arp_pl=8,
         ))

    show('Downlink Data Notification Acknowledge',
         GTPv2CFactory.dl_data_notification_ack(
             teid=TEID_CP,
             seqnum=SEQNUM + 6,
         ))


if __name__ == '__main__':
    v1_messages()
    v2_messages()
