#!/usr/bin/env python
"""
Create and encode GTPv1-C and GTPv2-C control plane messages, then display
them as hex dumps.

GTPv1-C (3GPP TS 29.060) is used across the Gn/Gp interfaces between SGSN and GGSN.
GTPv2-C (3GPP TS 29.274) is used on the S5/S8/S11 interfaces in EPC (LTE).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dpkt.gtp_c import (
    GTPv1C, GTPv2C, IEv1, IEv2,
    V1_CREATE_PDP_CXT_REQ,
    V1_DELETE_PDP_CXT_REQ,
    V2_CREATE_SESSION_REQ,
    V2_DELETE_SESSION_REQ,
    V2_ECHO_REQ,
    TV_IMSI, TV_TEID_DATA_1, TV_TEID_C_PLANE, TV_NSAPI, TV_RECOVERY,
    GTPV2_IE_IMSI, GTPV2_IE_APN, GTPV2_IE_F_TEID, GTPV2_IE_RAT_TYPE,
    GTPV2_IE_PDN_TYPE, GTPV2_IE_CAUSE,
    FTEID_S11_MME, FTEID_S11S4_SGW,
    encode_fteid, decode_fteid,
)
from dpkt import hexdump


# ---------------------------------------------------------------------------
# Helper: encode an IMSI string as packed BCD bytes (semi-octet encoding)
# ---------------------------------------------------------------------------
def encode_imsi(imsi_str):
    """Encode a decimal IMSI string into packed BCD (semi-octet) bytes.

    Each byte holds two digits (low nibble first).  If the digit count is
    odd the final nibble is padded with 0xF.

    >>> encode_imsi('001011234567890').hex()
    '0010214365870900'
    """
    if len(imsi_str) % 2:
        imsi_str += 'F'
    return bytes(
        int(imsi_str[i + 1], 16) << 4 | int(imsi_str[i], 16)
        for i in range(0, len(imsi_str), 2)
    )


# ---------------------------------------------------------------------------
# Helper: encode an APN string into length-prefixed label bytes
# ---------------------------------------------------------------------------
def encode_apn(apn_str):
    """Encode a dotted APN string into length-prefixed label bytes.

    e.g. 'internet.operator.net' -> b'\\x08internet\\x08operator\\x03net'
    """
    out = b''
    for label in apn_str.split('.'):
        out += bytes([len(label)]) + label.encode()
    return out


# ---------------------------------------------------------------------------
# GTPv1-C: Create PDP Context Request
# ---------------------------------------------------------------------------
def make_v1_create_pdp_request():
    """Build a minimal GTPv1-C Create PDP Context Request.

    Fixed header: flags | type | len | TEID
    Optional fields: seqnum | N-PDU | next ext header type
    IEs (TV/TLV):
        IMSI       (type 2,    8 bytes, TV)
        TEID Data I (type 16,  4 bytes, TV)
        TEID C-Plane (type 17, 4 bytes, TV)
        NSAPI      (type 20,   1 byte,  TV)
        APN        (type 0x83, TLV)
    """
    pkt = GTPv1C(
        version=1,
        proto_type=1,
        e_flag=0,
        s_flag=1,       # sequence number present
        np_flag=0,
        type=V1_CREATE_PDP_CXT_REQ,
        teid=0x00001234,
        seqnum=0x0001,
        npdu=0x00,
        next_type=0x00,
    )

    imsi_bytes = encode_imsi('001011234567890')  # MCC=001 MNC=01 MSIN=1234567890

    pkt.data = [
        IEv1(type=TV_IMSI,        data=imsi_bytes),
        IEv1(type=TV_TEID_DATA_1, data=b'\x00\x00\x56\x78'),
        IEv1(type=TV_TEID_C_PLANE, data=b'\x00\x00\x12\x34'),
        IEv1(type=TV_NSAPI,       data=b'\x05'),               # NSAPI=5
        IEv1(type=0x83,           data=encode_apn('internet.operator.net')),
    ]

    return pkt


# ---------------------------------------------------------------------------
# GTPv1-C: Delete PDP Context Request
# ---------------------------------------------------------------------------
def make_v1_delete_pdp_request():
    """Build a GTPv1-C Delete PDP Context Request."""
    pkt = GTPv1C(
        version=1,
        proto_type=1,
        e_flag=0,
        s_flag=1,
        np_flag=0,
        type=V1_DELETE_PDP_CXT_REQ,
        teid=0x00001234,
        seqnum=0x0002,
        npdu=0x00,
        next_type=0x00,
    )

    pkt.data = [
        IEv1(type=TV_NSAPI,    data=b'\x05'),  # NSAPI=5
        IEv1(type=TV_RECOVERY, data=b'\x00'),  # Recovery counter
    ]

    return pkt


# ---------------------------------------------------------------------------
# GTPv2-C: Echo Request (no TEID)
# ---------------------------------------------------------------------------
def make_v2_echo_request():
    """Build a GTPv2-C Echo Request (simplest possible GTPv2 message)."""
    pkt = GTPv2C(
        version=2,
        p_flag=0,
        t_flag=0,       # no TEID field
        type=V2_ECHO_REQ,
        seqnum=0x000001,
    )
    pkt.data = []
    return pkt


# ---------------------------------------------------------------------------
# GTPv2-C: Create Session Request
# ---------------------------------------------------------------------------
def make_v2_create_session_request():
    """Build a minimal GTPv2-C Create Session Request.

    Fixed header: flags | type | len
    Optional TEID field (t_flag=1)
    Mandatory seqnum (3 bytes) + spare (1 byte)
    IEs (type | len(2) | flags(CR+instance) | value):
        IMSI         (type 1)
        RAT Type     (type 82) — 6 = EUTRAN
        APN          (type 71)
        PDN Type     (type 99) — 1 = IPv4
        F-TEID       (type 87) — S11 MME GTP-C interface, IPv4
    """
    pkt = GTPv2C(
        version=2,
        p_flag=0,
        t_flag=1,
        type=V2_CREATE_SESSION_REQ,
        teid=0x00000000,   # initial attach, peer TEID not yet known
        seqnum=0x000001,
    )

    imsi_bytes = encode_imsi('001011234567890')

    pkt.data = [
        IEv2(type=GTPV2_IE_IMSI,     instance=0, data=imsi_bytes),
        IEv2(type=GTPV2_IE_RAT_TYPE, instance=0, data=b'\x06'),     # EUTRAN
        IEv2(type=GTPV2_IE_APN,      instance=0, data=encode_apn('internet.operator.net')),
        IEv2(type=GTPV2_IE_PDN_TYPE, instance=0, data=b'\x01'),     # IPv4
        IEv2(type=GTPV2_IE_F_TEID,   instance=0,
             data=encode_fteid(teid=0x0000abcd,
                               interface_type=FTEID_S11_MME,
                               ipv4='10.0.0.1')),
    ]

    return pkt


# ---------------------------------------------------------------------------
# GTPv2-C: Delete Session Request
# ---------------------------------------------------------------------------
def make_v2_delete_session_request():
    """Build a GTPv2-C Delete Session Request."""
    pkt = GTPv2C(
        version=2,
        p_flag=0,
        t_flag=1,
        type=V2_DELETE_SESSION_REQ,
        teid=0x0000abcd,
        seqnum=0x000002,
    )
    pkt.data = [
        IEv2(type=GTPV2_IE_CAUSE, instance=0, data=b'\x10'),  # cause=16 (request accepted)
    ]
    return pkt


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    messages = [
        ('GTPv1-C  Create PDP Context Request', make_v1_create_pdp_request()),
        ('GTPv1-C  Delete PDP Context Request', make_v1_delete_pdp_request()),
        ('GTPv2-C  Echo Request',               make_v2_echo_request()),
        ('GTPv2-C  Create Session Request',     make_v2_create_session_request()),
        ('GTPv2-C  Delete Session Request',     make_v2_delete_session_request()),
    ]

    for title, pkt in messages:
        raw = bytes(pkt)
        print(f'=== {title} ({len(raw)} bytes) ===')
        print(hexdump(raw))
        print()

    # Demonstrate F-TEID encode/decode round-trip
    print('=== F-TEID encode/decode round-trip ===')
    for label, kwargs in [
        ('IPv4 only',       dict(teid=0xdeadbeef, interface_type=FTEID_S11_MME,   ipv4='192.168.1.1')),
        ('IPv6 only',       dict(teid=0x00001234, interface_type=FTEID_S11S4_SGW, ipv6='2001:db8::1')),
        ('dual-stack',      dict(teid=0xaabbccdd, interface_type=FTEID_S11_MME,
                                 ipv4='10.0.0.2', ipv6='2001:db8::2')),
    ]:
        raw = encode_fteid(**kwargs)
        parsed = decode_fteid(raw)
        print(f'  {label}: {raw.hex()}  ->  {parsed}')


if __name__ == '__main__':
    main()
