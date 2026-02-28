# -*- coding: utf-8 -*-
"""Unit tests for dpkt.gtp_c and dpkt.gtpc_factory."""
import struct
import pytest

from dpkt import dpkt as dpkt_base
from dpkt.gtp_c import (
    GTPv1C, GTPv2C, IEv1, IEv2,
    # v1 message types
    V1_ECHO_REQ, V1_ECHO_RES,
    V1_CREATE_PDP_CXT_REQ, V1_CREATE_PDP_CXT_RES,
    V1_UPDATE_PDP_CXT_REQ, V1_UPDATE_PDP_CXT_RES,
    V1_DELETE_PDP_CXT_REQ, V1_DELETE_PDP_CXT_RES,
    # v2 message types
    V2_ECHO_REQ, V2_ECHO_RES,
    V2_CREATE_SESSION_REQ, V2_CREATE_SESSION_RES,
    V2_MODIFY_BEARER_REQ, V2_MODIFY_BEARER_RES,
    V2_DELETE_SESSION_REQ, V2_DELETE_SESSION_RES,
    V2_CREATE_BEARER_REQ, V2_CREATE_BEARER_RES,
    V2_DELETE_BEARER_REQ, V2_DELETE_BEARER_RES,
    V2_RELEASE_ACCESS_BEARERS_REQ, V2_RELEASE_ACCESS_BEARERS_RES,
    V2_DL_DATA_NOTIFY, V2_DL_DATA_NOTIFY_ACK,
    # v1 TV IE type codes
    TV_CAUSE, TV_IMSI, TV_RECOVERY, TV_SELECTION_MODE,
    TV_TEID_DATA_1, TV_TEID_C_PLANE,
    TV_NSAPI, TV_CHARGING_CHARS, TV_CHARGING_ID, TV_TEARDOWN_IND,
    # v2 IE type codes
    GTPV2_IE_IMSI, GTPV2_IE_CAUSE, GTPV2_REC_REST_CNT,
    GTPV2_AMBR, GTPV2_EBI, GTPV2_IE_MEI, GTPV2_IE_MSISDN,
    GTPV2_BEARER_QOS, GTPV2_IE_RAT_TYPE,
    GTPV2_IE_F_TEID, GTPV2_IE_APN, GTPV2_IE_PDN_TYPE,
    GTPV2_IE_BEARER_CTX, GTPV2_IE_ARP,
    # F-TEID
    FTEID_S11_MME, FTEID_S11S4_SGW,
    encode_fteid, decode_fteid,
)
from dpkt.gtpc_factory import (
    GTPv1CFactory, GTPv2CFactory,
    V1_CAUSE_REQUEST_ACCEPTED, V2_CAUSE_REQUEST_ACCEPTED,
    _encode_imsi, _encode_apn, _encode_bearer_qos, _encode_ambr,
)

# ── shared test constants ─────────────────────────────────────────────────────

IMSI    = '001011234567890'
MSISDN  = '447700900001'
MEI     = '3569870129304757'
APN     = 'internet.epc'
TEID_CP = 0x00001234
TEID_UP = 0x00005678
MME_IP  = '10.10.10.1'
SGW_IP  = '10.20.20.1'
SEQ     = 0x000001

# ── helpers ───────────────────────────────────────────────────────────────────

def _ie_types(pkt):
    # pkt.data is the IE list both on factory packets and after unpack
    return [ie.type for ie in pkt.data]


def _find_ie(pkt, ie_type):
    # pkt.data is the IE list both on factory packets and after unpack
    return next((ie for ie in pkt.data if ie.type == ie_type), None)


# ── encoding helpers ──────────────────────────────────────────────────────────

def test_encode_imsi_length():
    # 15-digit IMSI is padded to 16 semi-octets → 8 bytes
    assert len(_encode_imsi(IMSI)) == 8


def test_encode_imsi_even_digits():
    # '12' → low=1 high=2 → 0x21
    assert _encode_imsi('12') == bytes([0x21])


def test_encode_imsi_odd_digits():
    # '1' padded to '1F' → low=1 high=F → 0xF1
    assert _encode_imsi('1') == bytes([0xF1])


def test_encode_imsi_known_vector():
    # '123456' → bytes 0x21, 0x43, 0x65
    assert _encode_imsi('123456') == bytes([0x21, 0x43, 0x65])


def test_encode_apn_single_label():
    assert _encode_apn('internet') == b'\x08internet'


def test_encode_apn_multiple_labels():
    assert _encode_apn('internet.epc') == b'\x08internet\x03epc'


def test_encode_apn_empty_label_not_present():
    result = _encode_apn('a.b')
    assert result == b'\x01a\x01b'


def test_encode_bearer_qos_length():
    assert len(_encode_bearer_qos()) == 22


def test_encode_bearer_qos_qci_byte():
    # QCI is always byte[1]
    assert _encode_bearer_qos(qci=9)[1] == 9
    assert _encode_bearer_qos(qci=1)[1] == 1


def test_encode_bearer_qos_flags_byte():
    # pci=1, pl=8, pvi=0 → flags = (1<<6)|(8<<2)|(0<<1) = 0x60
    assert _encode_bearer_qos(qci=1, pci=1, pl=8, pvi=0)[0] == 0x60
    # pci=0, pl=15, pvi=0 → (0<<6)|(15<<2)|(0<<1) = 0x3C
    assert _encode_bearer_qos(pci=0, pl=15, pvi=0)[0] == 0x3C


def test_encode_bearer_qos_bit_rates():
    qos = _encode_bearer_qos(mbr_ul=1024, mbr_dl=2048, gbr_ul=512, gbr_dl=256)
    # mbr_ul starts at byte[2], each rate is 5 bytes big-endian
    mbr_ul = int.from_bytes(qos[2:7], 'big')
    mbr_dl = int.from_bytes(qos[7:12], 'big')
    gbr_ul = int.from_bytes(qos[12:17], 'big')
    gbr_dl = int.from_bytes(qos[17:22], 'big')
    assert mbr_ul == 1024
    assert mbr_dl == 2048
    assert gbr_ul == 512
    assert gbr_dl == 256


def test_encode_ambr_length():
    assert len(_encode_ambr()) == 8


def test_encode_ambr_values():
    result = _encode_ambr(ambr_ul=50_000, ambr_dl=100_000)
    assert result == struct.pack('!II', 50_000, 100_000)


# ── IEv1 ──────────────────────────────────────────────────────────────────────

def test_iev1_tv_encode():
    ie = IEv1(type=TV_RECOVERY, data=b'\x05')
    assert bytes(ie) == b'\x0e\x05'
    assert len(ie) == 2


def test_iev1_tv_unpack():
    ie = IEv1(b'\x0e\x05')
    assert ie.type == TV_RECOVERY   # 14
    assert ie.data == b'\x05'
    assert ie.len == 1


def test_iev1_tv_imsi_length():
    ie = IEv1(type=TV_IMSI, data=b'\x00' * 8)
    assert len(ie) == 9             # 1B type + 8B data


def test_iev1_tlv_encode():
    ie = IEv1(type=0x83, data=b'internet')
    assert bytes(ie) == b'\x83\x00\x08internet'
    assert len(ie) == 11            # 1B type + 2B len field + 8B data


def test_iev1_tlv_unpack():
    ie = IEv1(b'\x83\x00\x08internet')
    assert ie.type == 0x83
    assert ie.len == 8
    assert ie.data == b'internet'


def test_iev1_tlv_roundtrip():
    ie = IEv1(type=0x83, data=b'some.apn')
    assert IEv1(bytes(ie)).data == b'some.apn'


def test_iev1_unknown_tv_type_raises():
    # 0x1e = 30 is not in TV_LEN_DICT (TV types only defined up to 29 and 127)
    with pytest.raises(dpkt_base.UnpackError):
        IEv1(b'\x1e\x00')


def test_iev1_encoding_property_tv():
    ie = IEv1(type=TV_RECOVERY, data=b'\x00')
    assert ie.encoding == 0         # MSB=0 → TV


def test_iev1_encoding_property_tlv():
    ie = IEv1(type=0x83, data=b'x')
    assert ie.encoding == 1         # MSB=1 → TLV


# ── IEv2 ──────────────────────────────────────────────────────────────────────

def test_iev2_encode_length():
    ie = IEv2(type=GTPV2_IE_IMSI, instance=0, data=b'\xAA' * 8)
    # type(1) + len(2) + flags(1) + data(8) = 12
    assert len(bytes(ie)) == 12


def test_iev2_encode_type_byte():
    ie = IEv2(type=GTPV2_IE_IMSI, instance=0, data=b'\x00')
    assert bytes(ie)[0] == GTPV2_IE_IMSI


def test_iev2_encode_len_field():
    data = b'\xBB' * 5
    ie = IEv2(type=1, instance=0, data=data)
    raw = bytes(ie)
    assert struct.unpack('!H', raw[1:3])[0] == len(data)


def test_iev2_unpack():
    raw = b'\x01\x00\x08\x00' + b'\xAA' * 8
    ie = IEv2(raw)
    assert ie.type == 1
    assert ie.len == 8
    assert ie.cr_flag == 0
    assert ie.instance == 0
    assert ie.data == b'\xAA' * 8


def test_iev2_cr_flag_setter():
    ie = IEv2(type=1, instance=0, data=b'\x00')
    ie.cr_flag = 3
    assert ie.cr_flag == 3
    assert ie.instance == 0         # unchanged


def test_iev2_instance_setter():
    ie = IEv2(type=1, instance=0, data=b'\x00')
    ie.instance = 5
    assert ie.instance == 5
    assert ie.cr_flag == 0          # unchanged


def test_iev2_flags_combined():
    ie = IEv2(type=1, data=b'\x00')
    ie.cr_flag = 0xA
    ie.instance = 0x3
    assert ie.flags == 0xA3


def test_iev2_pack_hdr_sets_len():
    ie = IEv2(type=1, instance=0, data=b'\x00' * 10)
    ie.pack_hdr()
    assert ie.len == 10


def test_iev2_roundtrip():
    ie = IEv2(type=GTPV2_IE_APN, instance=0, data=b'\x08internet')
    ie2 = IEv2(bytes(ie))
    assert ie2.type == GTPV2_IE_APN
    assert ie2.data == b'\x08internet'


# ── GTPv1C header properties ──────────────────────────────────────────────────

def test_gtpv1c_flag_setters():
    pkt = GTPv1C()
    pkt.version = 1
    pkt.proto_type = 1
    pkt.e_flag = 0
    pkt.s_flag = 1
    pkt.np_flag = 0
    assert pkt.version == 1
    assert pkt.proto_type == 1
    assert pkt.e_flag == 0
    assert pkt.s_flag == 1
    assert pkt.np_flag == 0
    # version=1→0x20, proto_type=1→0x10, s_flag=1→0x02 → 0x32
    assert pkt.flags == 0x32


def test_gtpv1c_flags_independent():
    pkt = GTPv1C()
    pkt.version = 1
    pkt.e_flag = 1
    pkt.s_flag = 1
    pkt.np_flag = 1
    # only lower 3 bits set for e/s/np plus version
    assert pkt.e_flag == 1
    assert pkt.s_flag == 1
    assert pkt.np_flag == 1


# ── GTPv2C header properties ──────────────────────────────────────────────────

def test_gtpv2c_flag_setters():
    pkt = GTPv2C()
    pkt.version = 2
    pkt.p_flag = 0
    pkt.t_flag = 1
    assert pkt.version == 2
    assert pkt.p_flag == 0
    assert pkt.t_flag == 1
    # version=2→0x40, t_flag=1→0x08 → 0x48
    assert pkt.flags == 0x48


def test_gtpv2c_version_isolated():
    pkt = GTPv2C()
    pkt.version = 2
    pkt.t_flag = 1
    pkt.version = 1
    assert pkt.version == 1
    assert pkt.t_flag == 1          # unchanged after version write


# ── F-TEID encode ─────────────────────────────────────────────────────────────

def test_encode_fteid_ipv4_only_length():
    raw = encode_fteid(0xDEADBEEF, FTEID_S11_MME, ipv4='10.0.0.1')
    assert len(raw) == 9            # 1B flags + 4B TEID + 4B IPv4


def test_encode_fteid_ipv4_only_flags():
    raw = encode_fteid(0xDEADBEEF, FTEID_S11_MME, ipv4='10.0.0.1')
    assert raw[0] == 0x80 | FTEID_S11_MME   # V4 bit set


def test_encode_fteid_ipv4_only_teid():
    raw = encode_fteid(0xDEADBEEF, FTEID_S11_MME, ipv4='10.0.0.1')
    assert struct.unpack('!I', raw[1:5])[0] == 0xDEADBEEF


def test_encode_fteid_ipv6_only_length():
    raw = encode_fteid(0x1234, FTEID_S11S4_SGW, ipv6='2001:db8::1')
    assert len(raw) == 21           # 1B flags + 4B TEID + 16B IPv6


def test_encode_fteid_ipv6_only_flags():
    raw = encode_fteid(0x1234, FTEID_S11S4_SGW, ipv6='2001:db8::1')
    assert raw[0] == 0x40 | FTEID_S11S4_SGW  # V6 bit set, V4 clear


def test_encode_fteid_dual_stack_length():
    raw = encode_fteid(0x1234, FTEID_S11_MME, ipv4='10.0.0.1', ipv6='2001:db8::1')
    assert len(raw) == 25           # 1B flags + 4B TEID + 4B IPv4 + 16B IPv6


def test_encode_fteid_dual_stack_flags():
    raw = encode_fteid(0x1234, FTEID_S11_MME, ipv4='10.0.0.1', ipv6='2001:db8::1')
    assert raw[0] & 0xC0 == 0xC0    # both V4 and V6 bits set


def test_encode_fteid_no_address_raises():
    with pytest.raises(ValueError):
        encode_fteid(0x1234, FTEID_S11_MME)


# ── F-TEID decode ─────────────────────────────────────────────────────────────

def test_decode_fteid_ipv4():
    raw = encode_fteid(0xDEADBEEF, FTEID_S11_MME, ipv4='10.0.0.1')
    r = decode_fteid(raw)
    assert r['interface_type'] == FTEID_S11_MME
    assert r['teid'] == 0xDEADBEEF
    assert r['ipv4'] == '10.0.0.1'
    assert 'ipv6' not in r


def test_decode_fteid_ipv6():
    raw = encode_fteid(0x1234, FTEID_S11S4_SGW, ipv6='2001:db8::1')
    r = decode_fteid(raw)
    assert r['interface_type'] == FTEID_S11S4_SGW
    assert r['teid'] == 0x1234
    assert r['ipv6'] == '2001:db8::1'
    assert 'ipv4' not in r


def test_decode_fteid_dual_stack():
    raw = encode_fteid(0xAABB, FTEID_S11_MME, ipv4='192.168.1.1', ipv6='::1')
    r = decode_fteid(raw)
    assert r['ipv4'] == '192.168.1.1'
    assert r['ipv6'] == '::1'


def test_decode_fteid_too_short_raises():
    with pytest.raises(dpkt_base.UnpackError):
        decode_fteid(b'\x80\x00\x00')   # only 3 bytes, need ≥5


def test_decode_fteid_truncated_ipv4_raises():
    # flags say V4 present but only 2 bytes of address follow
    raw = bytes([0x80 | FTEID_S11_MME]) + struct.pack('!I', 0x1234) + b'\x01\x02'
    with pytest.raises(dpkt_base.UnpackError):
        decode_fteid(raw)


def test_fteid_roundtrip_ipv4():
    orig = dict(teid=0xDEADBEEF, interface_type=FTEID_S11_MME, ipv4='10.0.0.1')
    r = decode_fteid(encode_fteid(**orig))
    assert r['teid'] == orig['teid']
    assert r['interface_type'] == orig['interface_type']
    assert r['ipv4'] == orig['ipv4']


def test_fteid_roundtrip_ipv6():
    orig = dict(teid=0x1234, interface_type=FTEID_S11S4_SGW, ipv6='2001:db8::1')
    r = decode_fteid(encode_fteid(**orig))
    assert r['teid'] == orig['teid']
    assert r['ipv6'] == orig['ipv6']


def test_fteid_roundtrip_dual_stack():
    orig = dict(teid=0xAABB, interface_type=FTEID_S11_MME,
                ipv4='10.0.0.2', ipv6='2001:db8::2')
    r = decode_fteid(encode_fteid(**orig))
    assert r['ipv4'] == orig['ipv4']
    assert r['ipv6'] == orig['ipv6']


# ── GTPv1CFactory ─────────────────────────────────────────────────────────────

def test_v1_echo_req_type():
    assert GTPv1CFactory.echo_req().type == V1_ECHO_REQ


def test_v1_echo_req_fields():
    pkt = GTPv1CFactory.echo_req(teid=0x1234, seqnum=5)
    assert pkt.teid == 0x1234
    assert pkt.seqnum == 5


def test_v1_echo_req_no_ies():
    assert GTPv1CFactory.echo_req().data == []


def test_v1_echo_req_roundtrip():
    pkt = GTPv1CFactory.echo_req(teid=TEID_CP, seqnum=SEQ)
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_ECHO_REQ
    assert parsed.teid == TEID_CP
    assert parsed.seqnum == SEQ
    assert parsed.data == []


def test_v1_echo_res_type():
    assert GTPv1CFactory.echo_res().type == V1_ECHO_RES


def test_v1_echo_res_has_recovery_ie():
    pkt = GTPv1CFactory.echo_res(recovery=5)
    assert len(pkt.data) == 1
    assert pkt.data[0].type == TV_RECOVERY
    assert pkt.data[0].data == b'\x05'


def test_v1_echo_res_roundtrip():
    pkt = GTPv1CFactory.echo_res(teid=0, seqnum=SEQ, recovery=7)
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_ECHO_RES
    assert parsed.seqnum == SEQ
    rc = _find_ie(parsed, TV_RECOVERY)
    assert rc is not None
    assert rc.data == b'\x07'


def test_v1_create_pdp_ctx_req_type():
    assert GTPv1CFactory.create_pdp_ctx_req().type == V1_CREATE_PDP_CXT_REQ


def test_v1_create_pdp_ctx_req_mandatory_ies():
    pkt = GTPv1CFactory.create_pdp_ctx_req(imsi=IMSI, apn=APN)
    types = [ie.type for ie in pkt.data]
    assert TV_IMSI in types
    assert 0x83 in types            # APN TLV
    assert TV_NSAPI in types
    assert TV_TEID_DATA_1 in types
    assert TV_TEID_C_PLANE in types


def test_v1_create_pdp_ctx_req_imsi_encoding():
    pkt = GTPv1CFactory.create_pdp_ctx_req(imsi=IMSI)
    imsi_ie = next(ie for ie in pkt.data if ie.type == TV_IMSI)
    assert imsi_ie.data == _encode_imsi(IMSI)


def test_v1_create_pdp_ctx_req_teid_values():
    pkt = GTPv1CFactory.create_pdp_ctx_req(teid_data=TEID_UP, teid_cplane=TEID_CP)
    ies = {ie.type: ie for ie in pkt.data}
    assert struct.unpack('!I', ies[TV_TEID_DATA_1].data)[0] == TEID_UP
    assert struct.unpack('!I', ies[TV_TEID_C_PLANE].data)[0] == TEID_CP


def test_v1_create_pdp_ctx_req_optional_msisdn_present():
    pkt = GTPv1CFactory.create_pdp_ctx_req(msisdn=MSISDN)
    assert 0x86 in [ie.type for ie in pkt.data]


def test_v1_create_pdp_ctx_req_optional_msisdn_absent():
    pkt = GTPv1CFactory.create_pdp_ctx_req()
    assert 0x86 not in [ie.type for ie in pkt.data]


def test_v1_create_pdp_ctx_req_optional_recovery():
    pkt_with = GTPv1CFactory.create_pdp_ctx_req(recovery=3)
    pkt_without = GTPv1CFactory.create_pdp_ctx_req()
    assert TV_RECOVERY in [ie.type for ie in pkt_with.data]
    assert TV_RECOVERY not in [ie.type for ie in pkt_without.data]


def test_v1_create_pdp_ctx_req_roundtrip():
    pkt = GTPv1CFactory.create_pdp_ctx_req(
        teid=0, seqnum=SEQ, imsi=IMSI, nsapi=5, apn=APN,
        teid_data=TEID_UP, teid_cplane=TEID_CP, msisdn=MSISDN, recovery=0,
    )
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_CREATE_PDP_CXT_REQ
    assert parsed.seqnum == SEQ
    ptypes = [ie.type for ie in parsed.data]
    assert TV_IMSI in ptypes
    assert 0x83 in ptypes           # APN


def test_v1_create_pdp_ctx_res_type():
    assert GTPv1CFactory.create_pdp_ctx_res().type == V1_CREATE_PDP_CXT_RES


def test_v1_create_pdp_ctx_res_cause():
    pkt = GTPv1CFactory.create_pdp_ctx_res()
    cause_ie = next(ie for ie in pkt.data if ie.type == TV_CAUSE)
    assert cause_ie.data == bytes([V1_CAUSE_REQUEST_ACCEPTED])


def test_v1_create_pdp_ctx_res_charging_id():
    pkt = GTPv1CFactory.create_pdp_ctx_res(charging_id=0xDEADBEEF)
    ch_ie = next(ie for ie in pkt.data if ie.type == TV_CHARGING_ID)
    assert struct.unpack('!I', ch_ie.data)[0] == 0xDEADBEEF


def test_v1_create_pdp_ctx_res_optional_recovery():
    pkt_with = GTPv1CFactory.create_pdp_ctx_res(recovery=0)
    pkt_without = GTPv1CFactory.create_pdp_ctx_res()
    assert TV_RECOVERY in [ie.type for ie in pkt_with.data]
    assert TV_RECOVERY not in [ie.type for ie in pkt_without.data]


def test_v1_create_pdp_ctx_res_roundtrip():
    pkt = GTPv1CFactory.create_pdp_ctx_res(
        teid=TEID_CP, seqnum=SEQ,
        teid_data=TEID_UP, teid_cplane=TEID_CP,
        charging_id=0xDEADBEEF, recovery=0,
    )
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_CREATE_PDP_CXT_RES
    assert parsed.teid == TEID_CP
    assert TV_CAUSE in [ie.type for ie in parsed.data]
    assert TV_CHARGING_ID in [ie.type for ie in parsed.data]


def test_v1_update_pdp_ctx_req_type():
    assert GTPv1CFactory.update_pdp_ctx_req().type == V1_UPDATE_PDP_CXT_REQ


def test_v1_update_pdp_ctx_req_teid_values():
    pkt = GTPv1CFactory.update_pdp_ctx_req(teid_data=TEID_UP, teid_cplane=TEID_CP)
    ies = {ie.type: ie for ie in pkt.data}
    assert struct.unpack('!I', ies[TV_TEID_DATA_1].data)[0] == TEID_UP
    assert struct.unpack('!I', ies[TV_TEID_C_PLANE].data)[0] == TEID_CP


def test_v1_update_pdp_ctx_req_roundtrip():
    pkt = GTPv1CFactory.update_pdp_ctx_req(
        teid=TEID_CP, seqnum=SEQ, nsapi=5,
        teid_data=TEID_UP, teid_cplane=TEID_CP,
    )
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_UPDATE_PDP_CXT_REQ
    assert TV_NSAPI in [ie.type for ie in parsed.data]


def test_v1_update_pdp_ctx_res_type():
    assert GTPv1CFactory.update_pdp_ctx_res().type == V1_UPDATE_PDP_CXT_RES


def test_v1_update_pdp_ctx_res_roundtrip():
    pkt = GTPv1CFactory.update_pdp_ctx_res(
        teid=TEID_CP, seqnum=SEQ,
        teid_data=TEID_UP, teid_cplane=TEID_CP,
        charging_id=0xDEADBEEF,
    )
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_UPDATE_PDP_CXT_RES
    assert TV_CHARGING_ID in [ie.type for ie in parsed.data]


def test_v1_delete_pdp_ctx_req_type():
    assert GTPv1CFactory.delete_pdp_ctx_req().type == V1_DELETE_PDP_CXT_REQ


def test_v1_delete_pdp_ctx_req_has_nsapi():
    pkt = GTPv1CFactory.delete_pdp_ctx_req(nsapi=5)
    nsapi_ie = next(ie for ie in pkt.data if ie.type == TV_NSAPI)
    assert nsapi_ie.data == b'\x05'


def test_v1_delete_pdp_ctx_req_teardown_absent_by_default():
    pkt = GTPv1CFactory.delete_pdp_ctx_req(nsapi=5)
    assert TV_TEARDOWN_IND not in [ie.type for ie in pkt.data]


def test_v1_delete_pdp_ctx_req_teardown_present():
    pkt = GTPv1CFactory.delete_pdp_ctx_req(nsapi=5, teardown_ind=True)
    td_ie = next(ie for ie in pkt.data if ie.type == TV_TEARDOWN_IND)
    assert td_ie.data == b'\x01'


def test_v1_delete_pdp_ctx_req_roundtrip():
    pkt = GTPv1CFactory.delete_pdp_ctx_req(
        teid=TEID_CP, seqnum=SEQ, nsapi=5, teardown_ind=True,
    )
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_DELETE_PDP_CXT_REQ
    assert TV_TEARDOWN_IND in [ie.type for ie in parsed.data]


def test_v1_delete_pdp_ctx_res_type():
    assert GTPv1CFactory.delete_pdp_ctx_res().type == V1_DELETE_PDP_CXT_RES


def test_v1_delete_pdp_ctx_res_cause():
    pkt = GTPv1CFactory.delete_pdp_ctx_res()
    cause_ie = next(ie for ie in pkt.data if ie.type == TV_CAUSE)
    assert cause_ie.data == bytes([V1_CAUSE_REQUEST_ACCEPTED])


def test_v1_delete_pdp_ctx_res_roundtrip():
    pkt = GTPv1CFactory.delete_pdp_ctx_res(teid=TEID_CP, seqnum=SEQ)
    parsed = GTPv1C(bytes(pkt))
    assert parsed.type == V1_DELETE_PDP_CXT_RES
    assert TV_CAUSE in [ie.type for ie in parsed.data]


# ── GTPv2CFactory ─────────────────────────────────────────────────────────────

def test_v2_echo_req_type():
    assert GTPv2CFactory.echo_req().type == V2_ECHO_REQ


def test_v2_echo_req_no_teid_flag():
    assert GTPv2CFactory.echo_req().t_flag == 0


def test_v2_echo_req_seqnum():
    assert GTPv2CFactory.echo_req(seqnum=SEQ).seqnum == SEQ


def test_v2_echo_req_no_ies():
    assert GTPv2CFactory.echo_req().data == []


def test_v2_echo_req_roundtrip():
    pkt = GTPv2CFactory.echo_req(seqnum=SEQ)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_ECHO_REQ
    assert parsed.seqnum == SEQ
    assert parsed.data == []


def test_v2_echo_res_type():
    assert GTPv2CFactory.echo_res().type == V2_ECHO_RES


def test_v2_echo_res_has_recovery_ie():
    pkt = GTPv2CFactory.echo_res(recovery=5)
    assert any(ie.type == GTPV2_REC_REST_CNT for ie in pkt.data)


def test_v2_echo_res_recovery_value():
    pkt = GTPv2CFactory.echo_res(recovery=5)
    rc = next(ie for ie in pkt.data if ie.type == GTPV2_REC_REST_CNT)
    assert rc.data == b'\x05'


def test_v2_echo_res_roundtrip():
    pkt = GTPv2CFactory.echo_res(seqnum=SEQ, recovery=7)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_ECHO_RES
    assert parsed.seqnum == SEQ
    rc = _find_ie(parsed, GTPV2_REC_REST_CNT)
    assert rc is not None
    assert rc.data == b'\x07'


def test_v2_create_session_req_type():
    assert GTPv2CFactory.create_session_req(sender_ipv4=MME_IP).type == V2_CREATE_SESSION_REQ


def test_v2_create_session_req_has_teid_flag():
    assert GTPv2CFactory.create_session_req(teid=0, sender_ipv4=MME_IP).t_flag == 1


def test_v2_create_session_req_mandatory_ies():
    pkt = GTPv2CFactory.create_session_req(imsi=IMSI, apn=APN, sender_ipv4=MME_IP)
    types = [ie.type for ie in pkt.data]
    assert GTPV2_IE_IMSI in types
    assert GTPV2_IE_APN in types
    assert GTPV2_IE_RAT_TYPE in types
    assert GTPV2_IE_PDN_TYPE in types
    assert GTPV2_AMBR in types
    assert GTPV2_IE_F_TEID in types
    assert GTPV2_IE_BEARER_CTX in types


def test_v2_create_session_req_imsi_encoding():
    pkt = GTPv2CFactory.create_session_req(imsi=IMSI, sender_ipv4=MME_IP)
    imsi_ie = _find_ie(pkt, GTPV2_IE_IMSI)
    assert imsi_ie is not None
    assert imsi_ie.data == _encode_imsi(IMSI)


def test_v2_create_session_req_ambr_values():
    pkt = GTPv2CFactory.create_session_req(
        sender_ipv4=MME_IP, ambr_ul=50_000, ambr_dl=100_000,
    )
    ambr_ie = _find_ie(pkt, GTPV2_AMBR)
    assert ambr_ie.data == struct.pack('!II', 50_000, 100_000)


def test_v2_create_session_req_optional_msisdn_present():
    pkt = GTPv2CFactory.create_session_req(sender_ipv4=MME_IP, msisdn=MSISDN)
    assert GTPV2_IE_MSISDN in [ie.type for ie in pkt.data]


def test_v2_create_session_req_optional_msisdn_absent():
    pkt = GTPv2CFactory.create_session_req(sender_ipv4=MME_IP)
    assert GTPV2_IE_MSISDN not in [ie.type for ie in pkt.data]


def test_v2_create_session_req_optional_mei_present():
    pkt = GTPv2CFactory.create_session_req(sender_ipv4=MME_IP, mei=MEI)
    assert GTPV2_IE_MEI in [ie.type for ie in pkt.data]


def test_v2_create_session_req_optional_mei_absent():
    pkt = GTPv2CFactory.create_session_req(sender_ipv4=MME_IP)
    assert GTPV2_IE_MEI not in [ie.type for ie in pkt.data]


def test_v2_create_session_req_optional_recovery():
    pkt_with = GTPv2CFactory.create_session_req(sender_ipv4=MME_IP, recovery=0)
    pkt_without = GTPv2CFactory.create_session_req(sender_ipv4=MME_IP)
    assert GTPV2_REC_REST_CNT in [ie.type for ie in pkt_with.data]
    assert GTPV2_REC_REST_CNT not in [ie.type for ie in pkt_without.data]


def test_v2_create_session_req_roundtrip():
    pkt = GTPv2CFactory.create_session_req(
        teid=0, seqnum=SEQ, imsi=IMSI, msisdn=MSISDN, mei=MEI,
        rat_type=6, apn=APN, pdn_type=1,
        sender_teid=TEID_CP, sender_ipv4=MME_IP,
        ebi=5, qci=9, ambr_ul=50_000, ambr_dl=100_000,
    )
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_CREATE_SESSION_REQ
    assert parsed.seqnum == SEQ
    ptypes = [ie.type for ie in parsed.data]
    assert GTPV2_IE_IMSI in ptypes
    assert GTPV2_IE_BEARER_CTX in ptypes


def test_v2_create_session_res_type():
    assert GTPv2CFactory.create_session_res(sender_ipv4=SGW_IP).type == V2_CREATE_SESSION_RES


def test_v2_create_session_res_cause():
    pkt = GTPv2CFactory.create_session_res(sender_ipv4=SGW_IP)
    cause_ie = _find_ie(pkt, GTPV2_IE_CAUSE)
    assert cause_ie.data == bytes([V2_CAUSE_REQUEST_ACCEPTED])


def test_v2_create_session_res_roundtrip():
    pkt = GTPv2CFactory.create_session_res(
        teid=TEID_CP, seqnum=SEQ,
        sender_teid=TEID_CP, sender_ipv4=SGW_IP,
        ebi=5, fteid_data_teid=TEID_UP, fteid_data_ipv4=SGW_IP,
        ambr_ul=50_000, ambr_dl=100_000, recovery=0,
    )
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_CREATE_SESSION_RES
    assert parsed.seqnum == SEQ
    assert GTPV2_IE_CAUSE in [ie.type for ie in parsed.data]


def test_v2_modify_bearer_req_type():
    assert GTPv2CFactory.modify_bearer_req().type == V2_MODIFY_BEARER_REQ


def test_v2_modify_bearer_req_has_bearer_ctx():
    pkt = GTPv2CFactory.modify_bearer_req(ebi=5, fteid_data_teid=TEID_UP, fteid_data_ipv4=MME_IP)
    assert GTPV2_IE_BEARER_CTX in [ie.type for ie in pkt.data]


def test_v2_modify_bearer_req_optional_rat_type_present():
    pkt = GTPv2CFactory.modify_bearer_req(rat_type=6)
    assert GTPV2_IE_RAT_TYPE in [ie.type for ie in pkt.data]


def test_v2_modify_bearer_req_optional_rat_type_absent():
    pkt = GTPv2CFactory.modify_bearer_req()
    assert GTPV2_IE_RAT_TYPE not in [ie.type for ie in pkt.data]


def test_v2_modify_bearer_req_roundtrip():
    pkt = GTPv2CFactory.modify_bearer_req(
        teid=TEID_CP, seqnum=SEQ, ebi=5,
        rat_type=6, fteid_data_teid=TEID_UP, fteid_data_ipv4=MME_IP,
    )
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_MODIFY_BEARER_REQ
    assert GTPV2_IE_BEARER_CTX in [ie.type for ie in parsed.data]


def test_v2_modify_bearer_res_type():
    assert GTPv2CFactory.modify_bearer_res().type == V2_MODIFY_BEARER_RES


def test_v2_modify_bearer_res_roundtrip():
    pkt = GTPv2CFactory.modify_bearer_res(teid=TEID_CP, seqnum=SEQ, ebi=5)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_MODIFY_BEARER_RES


def test_v2_delete_session_req_type():
    assert GTPv2CFactory.delete_session_req(sender_ipv4=MME_IP).type == V2_DELETE_SESSION_REQ


def test_v2_delete_session_req_ies():
    pkt = GTPv2CFactory.delete_session_req(ebi=5, sender_teid=TEID_CP, sender_ipv4=MME_IP)
    types = [ie.type for ie in pkt.data]
    assert GTPV2_EBI in types
    assert GTPV2_IE_F_TEID in types


def test_v2_delete_session_req_ebi_value():
    pkt = GTPv2CFactory.delete_session_req(ebi=7, sender_ipv4=MME_IP)
    ebi_ie = _find_ie(pkt, GTPV2_EBI)
    assert ebi_ie.data == bytes([7])


def test_v2_delete_session_req_roundtrip():
    pkt = GTPv2CFactory.delete_session_req(
        teid=TEID_CP, seqnum=SEQ, ebi=5,
        sender_teid=TEID_CP, sender_ipv4=MME_IP,
    )
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_DELETE_SESSION_REQ
    assert GTPV2_EBI in [ie.type for ie in parsed.data]


def test_v2_delete_session_res_type():
    assert GTPv2CFactory.delete_session_res().type == V2_DELETE_SESSION_RES


def test_v2_delete_session_res_cause():
    pkt = GTPv2CFactory.delete_session_res()
    cause_ie = _find_ie(pkt, GTPV2_IE_CAUSE)
    assert cause_ie.data == bytes([V2_CAUSE_REQUEST_ACCEPTED])


def test_v2_delete_session_res_optional_recovery():
    pkt_with = GTPv2CFactory.delete_session_res(recovery=5)
    pkt_without = GTPv2CFactory.delete_session_res()
    assert GTPV2_REC_REST_CNT in [ie.type for ie in pkt_with.data]
    assert GTPV2_REC_REST_CNT not in [ie.type for ie in pkt_without.data]


def test_v2_delete_session_res_roundtrip():
    pkt = GTPv2CFactory.delete_session_res(teid=TEID_CP, seqnum=SEQ)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_DELETE_SESSION_RES
    assert GTPV2_IE_CAUSE in [ie.type for ie in parsed.data]


def test_v2_create_bearer_req_type():
    assert GTPv2CFactory.create_bearer_req().type == V2_CREATE_BEARER_REQ


def test_v2_create_bearer_req_linked_ebi():
    pkt = GTPv2CFactory.create_bearer_req(linked_ebi=5, ebi=6)
    # first IE should be EBI for the linked (default) bearer
    assert pkt.data[0].type == GTPV2_EBI
    assert pkt.data[0].data == bytes([5])


def test_v2_create_bearer_req_bearer_ctx():
    pkt = GTPv2CFactory.create_bearer_req(linked_ebi=5, ebi=6)
    assert GTPV2_IE_BEARER_CTX in [ie.type for ie in pkt.data]


def test_v2_create_bearer_req_roundtrip():
    pkt = GTPv2CFactory.create_bearer_req(
        teid=TEID_CP, seqnum=SEQ, linked_ebi=5, ebi=6,
        qci=1, pci=1, pl=8,
        mbr_ul=1024, mbr_dl=1024, gbr_ul=512, gbr_dl=512,
        fteid_data_teid=TEID_UP, fteid_data_ipv4=SGW_IP,
    )
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_CREATE_BEARER_REQ
    assert GTPV2_IE_BEARER_CTX in [ie.type for ie in parsed.data]


def test_v2_create_bearer_res_type():
    assert GTPv2CFactory.create_bearer_res().type == V2_CREATE_BEARER_RES


def test_v2_create_bearer_res_roundtrip():
    pkt = GTPv2CFactory.create_bearer_res(
        teid=TEID_CP, seqnum=SEQ, ebi=6,
        fteid_data_teid=TEID_UP, fteid_data_ipv4=MME_IP,
    )
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_CREATE_BEARER_RES


def test_v2_delete_bearer_req_type():
    assert GTPv2CFactory.delete_bearer_req().type == V2_DELETE_BEARER_REQ


def test_v2_delete_bearer_req_has_ebi():
    pkt = GTPv2CFactory.delete_bearer_req(ebi=6)
    ebi_ie = _find_ie(pkt, GTPV2_EBI)
    assert ebi_ie is not None
    assert ebi_ie.data == bytes([6])


def test_v2_delete_bearer_req_optional_cause_present():
    pkt = GTPv2CFactory.delete_bearer_req(ebi=6, cause=V2_CAUSE_REQUEST_ACCEPTED)
    assert GTPV2_IE_CAUSE in [ie.type for ie in pkt.data]


def test_v2_delete_bearer_req_optional_cause_absent():
    pkt = GTPv2CFactory.delete_bearer_req(ebi=6)
    assert GTPV2_IE_CAUSE not in [ie.type for ie in pkt.data]


def test_v2_delete_bearer_req_roundtrip():
    pkt = GTPv2CFactory.delete_bearer_req(teid=TEID_CP, seqnum=SEQ, ebi=6)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_DELETE_BEARER_REQ
    assert GTPV2_EBI in [ie.type for ie in parsed.data]


def test_v2_delete_bearer_res_type():
    assert GTPv2CFactory.delete_bearer_res().type == V2_DELETE_BEARER_RES


def test_v2_delete_bearer_res_roundtrip():
    pkt = GTPv2CFactory.delete_bearer_res(teid=TEID_CP, seqnum=SEQ, ebi=6)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_DELETE_BEARER_RES
    assert GTPV2_IE_CAUSE in [ie.type for ie in parsed.data]


def test_v2_release_access_bearers_req_type():
    assert GTPv2CFactory.release_access_bearers_req().type == V2_RELEASE_ACCESS_BEARERS_REQ


def test_v2_release_access_bearers_req_empty_by_default():
    pkt = GTPv2CFactory.release_access_bearers_req(teid=TEID_CP)
    assert pkt.data == []


def test_v2_release_access_bearers_req_roundtrip():
    pkt = GTPv2CFactory.release_access_bearers_req(teid=TEID_CP, seqnum=SEQ)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_RELEASE_ACCESS_BEARERS_REQ
    assert parsed.data == []


def test_v2_release_access_bearers_res_type():
    assert GTPv2CFactory.release_access_bearers_res().type == V2_RELEASE_ACCESS_BEARERS_RES


def test_v2_release_access_bearers_res_cause():
    pkt = GTPv2CFactory.release_access_bearers_res()
    cause_ie = _find_ie(pkt, GTPV2_IE_CAUSE)
    assert cause_ie.data == bytes([V2_CAUSE_REQUEST_ACCEPTED])


def test_v2_release_access_bearers_res_roundtrip():
    pkt = GTPv2CFactory.release_access_bearers_res(teid=TEID_CP, seqnum=SEQ)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_RELEASE_ACCESS_BEARERS_RES
    assert GTPV2_IE_CAUSE in [ie.type for ie in parsed.data]


def test_v2_dl_data_notification_type():
    assert GTPv2CFactory.dl_data_notification().type == V2_DL_DATA_NOTIFY


def test_v2_dl_data_notification_ies():
    pkt = GTPv2CFactory.dl_data_notification(ebi=5)
    types = [ie.type for ie in pkt.data]
    assert GTPV2_EBI in types
    assert GTPV2_IE_ARP in types


def test_v2_dl_data_notification_ebi_value():
    pkt = GTPv2CFactory.dl_data_notification(ebi=7)
    ebi_ie = _find_ie(pkt, GTPV2_EBI)
    assert ebi_ie.data == bytes([7])


def test_v2_dl_data_notification_arp_byte():
    # arp_pci=0, arp_pl=8, arp_pvi=0 → (0<<6)|(8<<2)|(0<<1) = 0x20
    pkt = GTPv2CFactory.dl_data_notification(ebi=5, arp_pci=0, arp_pl=8, arp_pvi=0)
    arp_ie = _find_ie(pkt, GTPV2_IE_ARP)
    assert arp_ie.data == bytes([0x20])


def test_v2_dl_data_notification_roundtrip():
    pkt = GTPv2CFactory.dl_data_notification(teid=TEID_CP, seqnum=SEQ, ebi=5, arp_pl=8)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_DL_DATA_NOTIFY
    assert GTPV2_EBI in [ie.type for ie in parsed.data]


def test_v2_dl_data_notification_ack_type():
    assert GTPv2CFactory.dl_data_notification_ack().type == V2_DL_DATA_NOTIFY_ACK


def test_v2_dl_data_notification_ack_cause():
    pkt = GTPv2CFactory.dl_data_notification_ack()
    cause_ie = _find_ie(pkt, GTPV2_IE_CAUSE)
    assert cause_ie.data == bytes([V2_CAUSE_REQUEST_ACCEPTED])


def test_v2_dl_data_notification_ack_roundtrip():
    pkt = GTPv2CFactory.dl_data_notification_ack(teid=TEID_CP, seqnum=SEQ)
    parsed = GTPv2C(bytes(pkt))
    assert parsed.type == V2_DL_DATA_NOTIFY_ACK
    assert GTPV2_IE_CAUSE in [ie.type for ie in parsed.data]
