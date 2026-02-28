# -*- coding: utf-8 -*-
"""Factory for building GTPv1-C and GTPv2-C control-plane messages.

Each static method on :class:`GTPv1CFactory` / :class:`GTPv2CFactory`
corresponds to one message type.  All arguments carry defaults so callers
only need to supply the fields that differ from the common case.

Example::

    from dpkt.gtpc_factory import GTPv1CFactory, GTPv2CFactory

    req = GTPv2CFactory.create_session_req(
        teid=0, seqnum=1,
        imsi='001011234567890',
        apn='internet',
        sender_ipv4='10.0.0.1',
    )
    print(bytes(req).hex())
"""
import struct

from .gtp_c import (
    GTPv1C, GTPv2C, IEv1, IEv2,
    # GTPv1 message types
    V1_ECHO_REQ, V1_ECHO_RES,
    V1_CREATE_PDP_CXT_REQ, V1_CREATE_PDP_CXT_RES,
    V1_UPDATE_PDP_CXT_REQ, V1_UPDATE_PDP_CXT_RES,
    V1_DELETE_PDP_CXT_REQ, V1_DELETE_PDP_CXT_RES,
    # GTPv1 TV IE types
    TV_CAUSE, TV_IMSI, TV_RECOVERY, TV_SELECTION_MODE,
    TV_TEID_DATA_1, TV_TEID_C_PLANE, TV_TEID_DATA_2,
    TV_TEARDOWN_IND, TV_NSAPI, TV_CHARGING_CHARS, TV_CHARGING_ID,
    # GTPv2 message types
    V2_ECHO_REQ, V2_ECHO_RES,
    V2_CREATE_SESSION_REQ, V2_CREATE_SESSION_RES,
    V2_MODIFY_BEARER_REQ, V2_MODIFY_BEARER_RES,
    V2_DELETE_SESSION_REQ, V2_DELETE_SESSION_RES,
    V2_CREATE_BEARER_REQ, V2_CREATE_BEARER_RES,
    V2_DELETE_BEARER_REQ, V2_DELETE_BEARER_RES,
    V2_RELEASE_ACCESS_BEARERS_REQ, V2_RELEASE_ACCESS_BEARERS_RES,
    V2_DL_DATA_NOTIFY, V2_DL_DATA_NOTIFY_ACK,
    # GTPv2 IE types
    GTPV2_IE_IMSI, GTPV2_IE_CAUSE, GTPV2_REC_REST_CNT,
    GTPV2_AMBR, GTPV2_EBI, GTPV2_IE_MEI, GTPV2_IE_MSISDN,
    GTPV2_BEARER_QOS, GTPV2_IE_RAT_TYPE,
    GTPV2_IE_F_TEID, GTPV2_IE_APN, GTPV2_IE_PDN_TYPE,
    GTPV2_IE_BEARER_CTX, GTPV2_IE_ARP,
    GTPV2_IE_CHAR_ID, GTPV2_IE_CHAR_CHAR,
    # F-TEID helpers
    FTEID_S11_MME, FTEID_S11S4_SGW,
    FTEID_S5S8_SGW_GTPC, FTEID_S5S8_PGW_GTPC,
    FTEID_S5S8_SGW_GTPU, FTEID_S5S8_PGW_GTPU,
    FTEID_S1U_ENB, FTEID_S1U_SGW,
    encode_fteid,
)

# ---------------------------------------------------------------------------
# GTPv1 TLV IE type bytes (type >= 128, not defined as named constants in gtp_c)
# ---------------------------------------------------------------------------
_V1_IE_END_USER_ADDR = 0x80   # End User Address
_V1_IE_APN           = 0x83   # Access Point Name
_V1_IE_PCO           = 0x84   # Protocol Configuration Options
_V1_IE_GSN_ADDR      = 0x85   # GSN Address (control-plane or user-plane)
_V1_IE_MSISDN        = 0x86   # MSISDN
_V1_IE_QOS_PROFILE   = 0x87   # Quality of Service Profile

# Minimal GTPv1 QoS profile (3 bytes, Release 97/98 format):
#   delay_class=4 (best effort), reliability_class=3, peak_throughput=1,
#   precedence=2 (normal), mean_throughput=31 (best effort)
_DEFAULT_V1_QOS = b'\x0b\x9b\x1f'

# GTPv1 cause codes (3GPP TS 29.060 Table 7.7.1)
V1_CAUSE_REQUEST_ACCEPTED = 0xc0   # 192

# GTPv2 cause codes (3GPP TS 29.274 Table 8.4-1)
V2_CAUSE_REQUEST_ACCEPTED = 0x10   # 16
V2_CAUSE_CTX_NOT_FOUND    = 0x40   # 64
V2_CAUSE_SYSTEM_FAILURE   = 0x12   # 18


# ---------------------------------------------------------------------------
# Internal encoding helpers
# ---------------------------------------------------------------------------

def _encode_imsi(imsi_str):
    """Encode a decimal IMSI/MSISDN string to packed BCD semi-octet bytes.

    Digits are packed low-nibble-first; an odd-length string is padded with
    0xF in the final high nibble.
    """
    s = str(imsi_str)
    if len(s) % 2:
        s += 'F'
    return bytes(int(s[i + 1], 16) << 4 | int(s[i], 16) for i in range(0, len(s), 2))


def _encode_apn(apn_str):
    """Encode a dotted APN string into DNS-style length-prefixed label bytes.

    e.g. 'internet.epc.mnc001.mcc001.gprs' ->
         b'\\x08internet\\x03epc...'
    """
    out = b''
    for label in apn_str.split('.'):
        out += bytes([len(label)]) + label.encode()
    return out


def _encode_bearer_qos(qci=9, pci=0, pl=15, pvi=0,
                       mbr_ul=0, mbr_dl=0, gbr_ul=0, gbr_dl=0):
    """Encode a GTPv2 Bearer QoS IE value field (22 bytes).

    3GPP TS 29.274 §8.15.  Bit rates are in kbps; each is encoded as a
    40-bit (5-byte) big-endian unsigned integer.

    Args:
        qci    : QoS Class Identifier (default 9 — non-GBR best effort)
        pci    : Pre-emption Capability Indicator (0=not capable, 1=capable)
        pl     : Priority Level 1–15 (15=lowest)
        pvi    : Pre-emption Vulnerability Indicator (0=not vulnerable, 1=vulnerable)
        mbr_ul : Maximum Bit Rate UL in kbps
        mbr_dl : Maximum Bit Rate DL in kbps
        gbr_ul : Guaranteed Bit Rate UL in kbps (0 for non-GBR bearers)
        gbr_dl : Guaranteed Bit Rate DL in kbps (0 for non-GBR bearers)
    """
    flags = ((pci & 0x1) << 6) | ((pl & 0xf) << 2) | ((pvi & 0x1) << 1)

    def _br(v):
        return struct.pack('!Q', v)[-5:]  # 40-bit big-endian

    return (struct.pack('!BB', flags, qci) +
            _br(mbr_ul) + _br(mbr_dl) + _br(gbr_ul) + _br(gbr_dl))


def _encode_ambr(ambr_ul=50000, ambr_dl=100000):
    """Encode a GTPv2 AMBR IE value field (8 bytes).

    Both values are in kbps as 32-bit big-endian unsigned integers.
    """
    return struct.pack('!II', ambr_ul, ambr_dl)


def _ie2(type_, instance, data):
    """Shorthand for constructing a single IEv2."""
    return IEv2(type=type_, instance=instance, data=data)


def _build_bearer_ctx_create(ebi=5, qci=9, pci=0, pl=15, pvi=0,
                              mbr_ul=0, mbr_dl=0, gbr_ul=0, gbr_dl=0,
                              fteid_data_teid=None, fteid_data_ipv4=None,
                              fteid_data_ipv6=None,
                              fteid_data_interface=FTEID_S1U_SGW):
    """Build a GTPv2 Bearer Context to be Created grouped IE.

    Contains: EBI, Bearer QoS, and optionally an S1-U/S5 data-plane F-TEID.
    """
    inner = [
        _ie2(GTPV2_EBI, 0, bytes([ebi & 0x0f])),
        _ie2(GTPV2_BEARER_QOS, 0,
             _encode_bearer_qos(qci=qci, pci=pci, pl=pl, pvi=pvi,
                                mbr_ul=mbr_ul, mbr_dl=mbr_dl,
                                gbr_ul=gbr_ul, gbr_dl=gbr_dl)),
    ]
    if fteid_data_teid is not None:
        inner.append(_ie2(GTPV2_IE_F_TEID, 2,
                          encode_fteid(fteid_data_teid, fteid_data_interface,
                                       ipv4=fteid_data_ipv4,
                                       ipv6=fteid_data_ipv6)))
    return _ie2(GTPV2_IE_BEARER_CTX, 0,
                b''.join(bytes(ie) for ie in inner))


def _build_bearer_ctx_modify(ebi=5, fteid_data_teid=None,
                              fteid_data_ipv4=None, fteid_data_ipv6=None,
                              fteid_data_interface=FTEID_S1U_ENB):
    """Build a GTPv2 Bearer Context to be Modified grouped IE.

    Contains: EBI, and optionally the new access-side data-plane F-TEID.
    """
    inner = [_ie2(GTPV2_EBI, 0, bytes([ebi & 0x0f]))]
    if fteid_data_teid is not None:
        inner.append(_ie2(GTPV2_IE_F_TEID, 0,
                          encode_fteid(fteid_data_teid, fteid_data_interface,
                                       ipv4=fteid_data_ipv4,
                                       ipv6=fteid_data_ipv6)))
    return _ie2(GTPV2_IE_BEARER_CTX, 0,
                b''.join(bytes(ie) for ie in inner))


def _build_bearer_ctx_response(ebi=5, cause=V2_CAUSE_REQUEST_ACCEPTED,
                                fteid_data_teid=None, fteid_data_ipv4=None,
                                fteid_data_ipv6=None,
                                fteid_data_interface=FTEID_S5S8_PGW_GTPU):
    """Build a GTPv2 Bearer Context within a response message grouped IE."""
    inner = [
        _ie2(GTPV2_EBI, 0, bytes([ebi & 0x0f])),
        _ie2(GTPV2_IE_CAUSE, 0, bytes([cause])),
    ]
    if fteid_data_teid is not None:
        inner.append(_ie2(GTPV2_IE_F_TEID, 0,
                          encode_fteid(fteid_data_teid, fteid_data_interface,
                                       ipv4=fteid_data_ipv4,
                                       ipv6=fteid_data_ipv6)))
    return _ie2(GTPV2_IE_BEARER_CTX, 0,
                b''.join(bytes(ie) for ie in inner))


# ---------------------------------------------------------------------------
# GTPv1-C factory
# ---------------------------------------------------------------------------

class GTPv1CFactory:
    """Static factory methods for GTPv1-C messages (3GPP TS 29.060)."""

    @staticmethod
    def _hdr(msg_type, teid=0, seqnum=0, npdu=0, next_type=0):
        """Build the GTPv1C packet base with s_flag=1 (seqnum present)."""
        return GTPv1C(
            version=1, proto_type=1,
            e_flag=0, s_flag=1, np_flag=0,
            type=msg_type,
            teid=teid,
            seqnum=seqnum,
            npdu=npdu,
            next_type=next_type,
        )

    # ------------------------------------------------------------------
    # Path management
    # ------------------------------------------------------------------

    @staticmethod
    def echo_req(teid=0, seqnum=0, npdu=0, next_type=0):
        """GTPv1-C Echo Request (type 1)."""
        pkt = GTPv1CFactory._hdr(V1_ECHO_REQ, teid, seqnum, npdu, next_type)
        pkt.data = []
        return pkt

    @staticmethod
    def echo_res(teid=0, seqnum=0, npdu=0, next_type=0,
                 recovery=0):
        """GTPv1-C Echo Response (type 2).

        Args:
            recovery: Restart counter value (0–255).
        """
        pkt = GTPv1CFactory._hdr(V1_ECHO_RES, teid, seqnum, npdu, next_type)
        pkt.data = [
            IEv1(type=TV_RECOVERY, data=bytes([recovery & 0xff])),
        ]
        return pkt

    # ------------------------------------------------------------------
    # PDP Context management
    # ------------------------------------------------------------------

    @staticmethod
    def create_pdp_ctx_req(teid=0, seqnum=0, npdu=0, next_type=0,
                           imsi='000000000000000',
                           nsapi=5,
                           teid_data=0,
                           teid_cplane=0,
                           selection_mode=0,
                           charging_chars=0x0800,
                           apn='internet',
                           qos_profile=_DEFAULT_V1_QOS,
                           msisdn=None,
                           recovery=None):
        """GTPv1-C Create PDP Context Request (type 16).

        Args:
            imsi          : IMSI as a decimal string (up to 15 digits).
            nsapi         : Network layer Service Access Point Identifier (0–15).
            teid_data     : TEID for user-plane data (Data I).
            teid_cplane   : TEID for control plane.
            selection_mode: 0=MS/NW provided APN, 1=MS provided, 2=NW provided.
            charging_chars: 2-byte charging characteristics value.
            apn           : Access Point Name string (dot-separated labels).
            qos_profile   : Raw bytes for the QoS Profile IE value.
                            Defaults to a minimal best-effort profile.
            msisdn        : MSISDN as a decimal string (optional).
            recovery      : Restart counter (int); omitted if None.
        """
        pkt = GTPv1CFactory._hdr(V1_CREATE_PDP_CXT_REQ, teid, seqnum,
                                  npdu, next_type)
        ies = [
            IEv1(type=TV_IMSI,
                 data=_encode_imsi(imsi)),
            IEv1(type=TV_SELECTION_MODE,
                 data=bytes([selection_mode & 0x03])),
            IEv1(type=TV_TEID_DATA_1,
                 data=struct.pack('!I', teid_data)),
            IEv1(type=TV_TEID_C_PLANE,
                 data=struct.pack('!I', teid_cplane)),
            IEv1(type=TV_NSAPI,
                 data=bytes([nsapi & 0x0f])),
            IEv1(type=TV_CHARGING_CHARS,
                 data=struct.pack('!H', charging_chars)),
            IEv1(type=_V1_IE_APN,
                 data=_encode_apn(apn)),
            IEv1(type=_V1_IE_QOS_PROFILE,
                 data=qos_profile),
        ]
        if msisdn is not None:
            ies.append(IEv1(type=_V1_IE_MSISDN, data=_encode_imsi(msisdn)))
        if recovery is not None:
            ies.append(IEv1(type=TV_RECOVERY, data=bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def create_pdp_ctx_res(teid=0, seqnum=0, npdu=0, next_type=0,
                           cause=V1_CAUSE_REQUEST_ACCEPTED,
                           nsapi=5,
                           teid_data=0,
                           teid_cplane=0,
                           charging_id=0,
                           qos_profile=_DEFAULT_V1_QOS,
                           recovery=None):
        """GTPv1-C Create PDP Context Response (type 17).

        Args:
            cause       : GTPv1 cause code (default: Request Accepted).
            nsapi       : NSAPI of the created context.
            teid_data   : Allocated TEID for user-plane data (GGSN side).
            teid_cplane : Allocated TEID for control plane (GGSN side).
            charging_id : 4-byte charging ID assigned by the GGSN.
            qos_profile : Raw bytes for the negotiated QoS Profile IE value.
            recovery    : Restart counter (int); omitted if None.
        """
        pkt = GTPv1CFactory._hdr(V1_CREATE_PDP_CXT_RES, teid, seqnum,
                                  npdu, next_type)
        ies = [
            IEv1(type=TV_CAUSE,
                 data=bytes([cause & 0xff])),
            IEv1(type=TV_TEID_DATA_1,
                 data=struct.pack('!I', teid_data)),
            IEv1(type=TV_TEID_C_PLANE,
                 data=struct.pack('!I', teid_cplane)),
            IEv1(type=TV_NSAPI,
                 data=bytes([nsapi & 0x0f])),
            IEv1(type=TV_CHARGING_ID,
                 data=struct.pack('!I', charging_id)),
            IEv1(type=_V1_IE_QOS_PROFILE,
                 data=qos_profile),
        ]
        if recovery is not None:
            ies.append(IEv1(type=TV_RECOVERY, data=bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def update_pdp_ctx_req(teid=0, seqnum=0, npdu=0, next_type=0,
                           nsapi=5,
                           teid_data=0,
                           teid_cplane=0,
                           qos_profile=_DEFAULT_V1_QOS,
                           recovery=None):
        """GTPv1-C Update PDP Context Request (type 18).

        Args:
            nsapi       : NSAPI of the context to update.
            teid_data   : New TEID for user-plane data.
            teid_cplane : New TEID for control plane.
            qos_profile : Raw bytes for the requested QoS Profile IE value.
            recovery    : Restart counter (int); omitted if None.
        """
        pkt = GTPv1CFactory._hdr(V1_UPDATE_PDP_CXT_REQ, teid, seqnum,
                                  npdu, next_type)
        ies = [
            IEv1(type=TV_TEID_DATA_1,
                 data=struct.pack('!I', teid_data)),
            IEv1(type=TV_TEID_C_PLANE,
                 data=struct.pack('!I', teid_cplane)),
            IEv1(type=TV_NSAPI,
                 data=bytes([nsapi & 0x0f])),
            IEv1(type=_V1_IE_QOS_PROFILE,
                 data=qos_profile),
        ]
        if recovery is not None:
            ies.append(IEv1(type=TV_RECOVERY, data=bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def update_pdp_ctx_res(teid=0, seqnum=0, npdu=0, next_type=0,
                           cause=V1_CAUSE_REQUEST_ACCEPTED,
                           teid_data=0,
                           teid_cplane=0,
                           qos_profile=_DEFAULT_V1_QOS,
                           charging_id=0,
                           recovery=None):
        """GTPv1-C Update PDP Context Response (type 19).

        Args:
            cause       : GTPv1 cause code.
            teid_data   : Updated TEID for user-plane data.
            teid_cplane : Updated TEID for control plane.
            qos_profile : Raw bytes for the negotiated QoS Profile IE value.
            charging_id : 4-byte charging ID.
            recovery    : Restart counter (int); omitted if None.
        """
        pkt = GTPv1CFactory._hdr(V1_UPDATE_PDP_CXT_RES, teid, seqnum,
                                  npdu, next_type)
        ies = [
            IEv1(type=TV_CAUSE,
                 data=bytes([cause & 0xff])),
            IEv1(type=TV_TEID_DATA_1,
                 data=struct.pack('!I', teid_data)),
            IEv1(type=TV_TEID_C_PLANE,
                 data=struct.pack('!I', teid_cplane)),
            IEv1(type=TV_CHARGING_ID,
                 data=struct.pack('!I', charging_id)),
            IEv1(type=_V1_IE_QOS_PROFILE,
                 data=qos_profile),
        ]
        if recovery is not None:
            ies.append(IEv1(type=TV_RECOVERY, data=bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def delete_pdp_ctx_req(teid=0, seqnum=0, npdu=0, next_type=0,
                           nsapi=5,
                           teardown_ind=False):
        """GTPv1-C Delete PDP Context Request (type 20).

        Args:
            nsapi        : NSAPI of the context to delete.
            teardown_ind : True to tear down the entire PDP address (all NSAPIs).
        """
        pkt = GTPv1CFactory._hdr(V1_DELETE_PDP_CXT_REQ, teid, seqnum,
                                  npdu, next_type)
        ies = [IEv1(type=TV_NSAPI, data=bytes([nsapi & 0x0f]))]
        if teardown_ind:
            ies.append(IEv1(type=TV_TEARDOWN_IND, data=b'\x01'))
        pkt.data = ies
        return pkt

    @staticmethod
    def delete_pdp_ctx_res(teid=0, seqnum=0, npdu=0, next_type=0,
                           cause=V1_CAUSE_REQUEST_ACCEPTED):
        """GTPv1-C Delete PDP Context Response (type 21).

        Args:
            cause: GTPv1 cause code.
        """
        pkt = GTPv1CFactory._hdr(V1_DELETE_PDP_CXT_RES, teid, seqnum,
                                  npdu, next_type)
        pkt.data = [IEv1(type=TV_CAUSE, data=bytes([cause & 0xff]))]
        return pkt


# ---------------------------------------------------------------------------
# GTPv2-C factory
# ---------------------------------------------------------------------------

class GTPv2CFactory:
    """Static factory methods for GTPv2-C messages (3GPP TS 29.274)."""

    @staticmethod
    def _hdr(msg_type, teid=None, seqnum=0):
        """Build the GTPv2C packet base; TEID field is included iff teid is not None."""
        if teid is not None:
            return GTPv2C(version=2, p_flag=0, t_flag=1,
                          type=msg_type, teid=teid, seqnum=seqnum)
        return GTPv2C(version=2, p_flag=0, t_flag=0,
                      type=msg_type, seqnum=seqnum)

    # ------------------------------------------------------------------
    # Path management
    # ------------------------------------------------------------------

    @staticmethod
    def echo_req(seqnum=0):
        """GTPv2-C Echo Request (type 1).  No TEID, no IEs."""
        pkt = GTPv2CFactory._hdr(V2_ECHO_REQ, teid=None, seqnum=seqnum)
        pkt.data = []
        return pkt

    @staticmethod
    def echo_res(seqnum=0, recovery=0):
        """GTPv2-C Echo Response (type 2).

        Args:
            recovery: Restart counter value (0–255).
        """
        pkt = GTPv2CFactory._hdr(V2_ECHO_RES, teid=None, seqnum=seqnum)
        pkt.data = [_ie2(GTPV2_REC_REST_CNT, 0, bytes([recovery & 0xff]))]
        return pkt

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    @staticmethod
    def create_session_req(teid=0, seqnum=0,
                           imsi='000000000000000',
                           msisdn=None,
                           mei=None,
                           rat_type=6,
                           apn='internet',
                           pdn_type=1,
                           sender_teid=0,
                           sender_ipv4=None,
                           sender_ipv6=None,
                           sender_interface=FTEID_S11_MME,
                           ebi=5,
                           qci=9,
                           pci=0,
                           pl=15,
                           pvi=0,
                           mbr_ul=0,
                           mbr_dl=0,
                           gbr_ul=0,
                           gbr_dl=0,
                           ambr_ul=50000,
                           ambr_dl=100000,
                           fteid_data_teid=None,
                           fteid_data_ipv4=None,
                           fteid_data_ipv6=None,
                           fteid_data_interface=FTEID_S1U_SGW,
                           recovery=None):
        """GTPv2-C Create Session Request (type 32).

        Args:
            teid              : Peer's TEID (0 for initial attach).
            seqnum            : Sequence number.
            imsi              : IMSI as a decimal string.
            msisdn            : MSISDN as a decimal string (optional).
            mei               : Mobile Equipment Identity / IMEI string (optional).
            rat_type          : RAT Type value (6=EUTRAN, 1=UTRAN, 2=GERAN).
            apn               : APN string (dot-separated labels).
            pdn_type          : PDN Type (1=IPv4, 2=IPv6, 3=IPv4v6).
            sender_teid       : Sender's GTP-C TEID on the control-plane interface.
            sender_ipv4       : Sender's control-plane IPv4 address string (optional).
            sender_ipv6       : Sender's control-plane IPv6 address string (optional).
            sender_interface  : Sender's F-TEID interface type constant.
            ebi               : EPS Bearer ID for the default bearer (1–15).
            qci               : QoS Class Identifier for the default bearer.
            pci               : Pre-emption Capability Indicator.
            pl                : Priority Level (1=highest, 15=lowest).
            pvi               : Pre-emption Vulnerability Indicator.
            mbr_ul/mbr_dl     : Maximum Bit Rate UL/DL in kbps.
            gbr_ul/gbr_dl     : Guaranteed Bit Rate UL/DL in kbps (0=non-GBR).
            ambr_ul/ambr_dl   : Aggregate Maximum Bit Rate UL/DL in kbps.
            fteid_data_teid   : Data-plane F-TEID TEID value (optional).
            fteid_data_ipv4   : Data-plane F-TEID IPv4 address string (optional).
            fteid_data_ipv6   : Data-plane F-TEID IPv6 address string (optional).
            fteid_data_interface : Data-plane F-TEID interface type constant.
            recovery          : Restart counter (int); omitted if None.
        """
        if sender_ipv4 is None and sender_ipv6 is None:
            sender_ipv4 = '0.0.0.0'

        pkt = GTPv2CFactory._hdr(V2_CREATE_SESSION_REQ, teid, seqnum)
        ies = [
            _ie2(GTPV2_IE_IMSI, 0, _encode_imsi(imsi)),
            _ie2(GTPV2_IE_RAT_TYPE, 0, bytes([rat_type & 0xff])),
            _ie2(GTPV2_IE_APN, 0, _encode_apn(apn)),
            _ie2(GTPV2_IE_PDN_TYPE, 0, bytes([pdn_type & 0x07])),
            _ie2(GTPV2_AMBR, 0, _encode_ambr(ambr_ul, ambr_dl)),
            _ie2(GTPV2_IE_F_TEID, 0,
                 encode_fteid(sender_teid, sender_interface,
                              ipv4=sender_ipv4, ipv6=sender_ipv6)),
            _build_bearer_ctx_create(
                ebi=ebi, qci=qci, pci=pci, pl=pl, pvi=pvi,
                mbr_ul=mbr_ul, mbr_dl=mbr_dl,
                gbr_ul=gbr_ul, gbr_dl=gbr_dl,
                fteid_data_teid=fteid_data_teid,
                fteid_data_ipv4=fteid_data_ipv4,
                fteid_data_ipv6=fteid_data_ipv6,
                fteid_data_interface=fteid_data_interface,
            ),
        ]
        if msisdn is not None:
            ies.insert(1, _ie2(GTPV2_IE_MSISDN, 0, _encode_imsi(msisdn)))
        if mei is not None:
            ies.insert(2, _ie2(GTPV2_IE_MEI, 0, _encode_imsi(mei)))
        if recovery is not None:
            ies.append(_ie2(GTPV2_REC_REST_CNT, 0, bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def create_session_res(teid=0, seqnum=0,
                           cause=V2_CAUSE_REQUEST_ACCEPTED,
                           sender_teid=0,
                           sender_ipv4=None,
                           sender_ipv6=None,
                           sender_interface=FTEID_S11S4_SGW,
                           ebi=5,
                           fteid_data_teid=None,
                           fteid_data_ipv4=None,
                           fteid_data_ipv6=None,
                           fteid_data_interface=FTEID_S5S8_PGW_GTPU,
                           ambr_ul=50000,
                           ambr_dl=100000,
                           recovery=None):
        """GTPv2-C Create Session Response (type 33).

        Args:
            cause             : GTPv2 cause code.
            sender_teid       : Responder's GTP-C TEID on the control-plane interface.
            sender_ipv4       : Responder's control-plane IPv4 address string (optional).
            sender_ipv6       : Responder's control-plane IPv6 address string (optional).
            sender_interface  : Responder's F-TEID interface type constant.
            ebi               : EPS Bearer ID of the created default bearer.
            fteid_data_teid   : Data-plane F-TEID TEID value for the bearer (optional).
            fteid_data_ipv4   : Data-plane F-TEID IPv4 address string (optional).
            fteid_data_ipv6   : Data-plane F-TEID IPv6 address string (optional).
            fteid_data_interface : Data-plane F-TEID interface type constant.
            ambr_ul/ambr_dl   : Aggregate Maximum Bit Rate UL/DL in kbps.
            recovery          : Restart counter (int); omitted if None.
        """
        if sender_ipv4 is None and sender_ipv6 is None:
            sender_ipv4 = '0.0.0.0'

        pkt = GTPv2CFactory._hdr(V2_CREATE_SESSION_RES, teid, seqnum)
        ies = [
            _ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff])),
            _ie2(GTPV2_AMBR, 0, _encode_ambr(ambr_ul, ambr_dl)),
            _ie2(GTPV2_IE_F_TEID, 1,
                 encode_fteid(sender_teid, sender_interface,
                              ipv4=sender_ipv4, ipv6=sender_ipv6)),
            _build_bearer_ctx_response(
                ebi=ebi, cause=cause,
                fteid_data_teid=fteid_data_teid,
                fteid_data_ipv4=fteid_data_ipv4,
                fteid_data_ipv6=fteid_data_ipv6,
                fteid_data_interface=fteid_data_interface,
            ),
        ]
        if recovery is not None:
            ies.append(_ie2(GTPV2_REC_REST_CNT, 0, bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def modify_bearer_req(teid=0, seqnum=0,
                          ebi=5,
                          rat_type=None,
                          fteid_data_teid=None,
                          fteid_data_ipv4=None,
                          fteid_data_ipv6=None,
                          fteid_data_interface=FTEID_S1U_ENB,
                          delay_dl_packet_notif_req=None):
        """GTPv2-C Modify Bearer Request (type 34).

        Args:
            ebi                         : EPS Bearer ID of the bearer to modify.
            rat_type                    : New RAT Type (optional).
            fteid_data_teid             : New access-side data-plane TEID (optional).
            fteid_data_ipv4             : New access-side data-plane IPv4 (optional).
            fteid_data_ipv6             : New access-side data-plane IPv6 (optional).
            fteid_data_interface        : Access-side F-TEID interface type constant.
            delay_dl_packet_notif_req   : Delay value in seconds (optional).
        """
        pkt = GTPv2CFactory._hdr(V2_MODIFY_BEARER_REQ, teid, seqnum)
        ies = [
            _build_bearer_ctx_modify(
                ebi=ebi,
                fteid_data_teid=fteid_data_teid,
                fteid_data_ipv4=fteid_data_ipv4,
                fteid_data_ipv6=fteid_data_ipv6,
                fteid_data_interface=fteid_data_interface,
            ),
        ]
        if rat_type is not None:
            ies.insert(0, _ie2(GTPV2_IE_RAT_TYPE, 0, bytes([rat_type & 0xff])))
        if delay_dl_packet_notif_req is not None:
            ies.append(_ie2(GTPV2_IE_EPC_TIMER, 0,
                            bytes([delay_dl_packet_notif_req & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def modify_bearer_res(teid=0, seqnum=0,
                          cause=V2_CAUSE_REQUEST_ACCEPTED,
                          ebi=5,
                          recovery=None):
        """GTPv2-C Modify Bearer Response (type 35).

        Args:
            cause    : GTPv2 cause code.
            ebi      : EPS Bearer ID of the modified bearer.
            recovery : Restart counter (int); omitted if None.
        """
        pkt = GTPv2CFactory._hdr(V2_MODIFY_BEARER_RES, teid, seqnum)
        ies = [
            _ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff])),
            _build_bearer_ctx_response(ebi=ebi, cause=cause),
        ]
        if recovery is not None:
            ies.append(_ie2(GTPV2_REC_REST_CNT, 0, bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def delete_session_req(teid=0, seqnum=0,
                           ebi=5,
                           sender_teid=0,
                           sender_ipv4=None,
                           sender_ipv6=None,
                           sender_interface=FTEID_S11_MME):
        """GTPv2-C Delete Session Request (type 36).

        Args:
            ebi               : EPS Bearer ID of the default bearer.
            sender_teid       : Sender's GTP-C TEID (for the response).
            sender_ipv4       : Sender's control-plane IPv4 address (optional).
            sender_ipv6       : Sender's control-plane IPv6 address (optional).
            sender_interface  : Sender's F-TEID interface type constant.
        """
        if sender_ipv4 is None and sender_ipv6 is None:
            sender_ipv4 = '0.0.0.0'

        pkt = GTPv2CFactory._hdr(V2_DELETE_SESSION_REQ, teid, seqnum)
        pkt.data = [
            _ie2(GTPV2_EBI, 0, bytes([ebi & 0x0f])),
            _ie2(GTPV2_IE_F_TEID, 0,
                 encode_fteid(sender_teid, sender_interface,
                              ipv4=sender_ipv4, ipv6=sender_ipv6)),
        ]
        return pkt

    @staticmethod
    def delete_session_res(teid=0, seqnum=0,
                           cause=V2_CAUSE_REQUEST_ACCEPTED,
                           recovery=None):
        """GTPv2-C Delete Session Response (type 37).

        Args:
            cause    : GTPv2 cause code.
            recovery : Restart counter (int); omitted if None.
        """
        pkt = GTPv2CFactory._hdr(V2_DELETE_SESSION_RES, teid, seqnum)
        ies = [_ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff]))]
        if recovery is not None:
            ies.append(_ie2(GTPV2_REC_REST_CNT, 0, bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    # ------------------------------------------------------------------
    # Bearer management
    # ------------------------------------------------------------------

    @staticmethod
    def create_bearer_req(teid=0, seqnum=0,
                          linked_ebi=5,
                          ebi=6,
                          qci=1,
                          pci=1,
                          pl=8,
                          pvi=0,
                          mbr_ul=1024,
                          mbr_dl=1024,
                          gbr_ul=512,
                          gbr_dl=512,
                          tft=None,
                          fteid_data_teid=None,
                          fteid_data_ipv4=None,
                          fteid_data_ipv6=None,
                          fteid_data_interface=FTEID_S5S8_PGW_GTPU):
        """GTPv2-C Create Bearer Request (type 95).

        Args:
            linked_ebi        : EBI of the default bearer that triggered this request.
            ebi               : EBI assigned to the new dedicated bearer.
            qci               : QCI for the new bearer (default 1 = conversational voice).
            pci               : Pre-emption Capability Indicator.
            pl                : Priority Level.
            pvi               : Pre-emption Vulnerability Indicator.
            mbr_ul/mbr_dl     : Maximum Bit Rate UL/DL in kbps.
            gbr_ul/gbr_dl     : Guaranteed Bit Rate UL/DL in kbps.
            tft               : Traffic Flow Template as raw bytes (optional).
            fteid_data_teid   : Data-plane F-TEID TEID value (optional).
            fteid_data_ipv4   : Data-plane F-TEID IPv4 address string (optional).
            fteid_data_ipv6   : Data-plane F-TEID IPv6 address string (optional).
            fteid_data_interface : Data-plane F-TEID interface type constant.
        """
        pkt = GTPv2CFactory._hdr(V2_CREATE_BEARER_REQ, teid, seqnum)
        ies = [
            _ie2(GTPV2_EBI, 0, bytes([linked_ebi & 0x0f])),
            _build_bearer_ctx_create(
                ebi=ebi, qci=qci, pci=pci, pl=pl, pvi=pvi,
                mbr_ul=mbr_ul, mbr_dl=mbr_dl,
                gbr_ul=gbr_ul, gbr_dl=gbr_dl,
                fteid_data_teid=fteid_data_teid,
                fteid_data_ipv4=fteid_data_ipv4,
                fteid_data_ipv6=fteid_data_ipv6,
                fteid_data_interface=fteid_data_interface,
            ),
        ]
        if tft is not None:
            ies.append(_ie2(GTPV2_IE_BEARER_TFT, 0, tft))
        pkt.data = ies
        return pkt

    @staticmethod
    def create_bearer_res(teid=0, seqnum=0,
                          cause=V2_CAUSE_REQUEST_ACCEPTED,
                          ebi=6,
                          fteid_data_teid=None,
                          fteid_data_ipv4=None,
                          fteid_data_ipv6=None,
                          fteid_data_interface=FTEID_S1U_ENB):
        """GTPv2-C Create Bearer Response (type 96).

        Args:
            cause             : GTPv2 cause code.
            ebi               : EBI of the created bearer.
            fteid_data_teid   : Access-side data-plane TEID (optional).
            fteid_data_ipv4   : Access-side data-plane IPv4 (optional).
            fteid_data_ipv6   : Access-side data-plane IPv6 (optional).
            fteid_data_interface : Access-side F-TEID interface type constant.
        """
        pkt = GTPv2CFactory._hdr(V2_CREATE_BEARER_RES, teid, seqnum)
        pkt.data = [
            _ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff])),
            _build_bearer_ctx_response(
                ebi=ebi, cause=cause,
                fteid_data_teid=fteid_data_teid,
                fteid_data_ipv4=fteid_data_ipv4,
                fteid_data_ipv6=fteid_data_ipv6,
                fteid_data_interface=fteid_data_interface,
            ),
        ]
        return pkt

    @staticmethod
    def delete_bearer_req(teid=0, seqnum=0,
                          ebi=6,
                          cause=None):
        """GTPv2-C Delete Bearer Request (type 99).

        Args:
            ebi   : EBI of the bearer to delete.
            cause : GTPv2 cause code for the deletion (optional).
        """
        pkt = GTPv2CFactory._hdr(V2_DELETE_BEARER_REQ, teid, seqnum)
        ies = [_ie2(GTPV2_EBI, 0, bytes([ebi & 0x0f]))]
        if cause is not None:
            ies.append(_ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff])))
        pkt.data = ies
        return pkt

    @staticmethod
    def delete_bearer_res(teid=0, seqnum=0,
                          cause=V2_CAUSE_REQUEST_ACCEPTED,
                          ebi=6):
        """GTPv2-C Delete Bearer Response (type 100).

        Args:
            cause : GTPv2 cause code.
            ebi   : EBI of the deleted bearer.
        """
        pkt = GTPv2CFactory._hdr(V2_DELETE_BEARER_RES, teid, seqnum)
        pkt.data = [
            _ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff])),
            _build_bearer_ctx_response(ebi=ebi, cause=cause),
        ]
        return pkt

    # ------------------------------------------------------------------
    # Access bearer management
    # ------------------------------------------------------------------

    @staticmethod
    def release_access_bearers_req(teid=0, seqnum=0,
                                   indication_flags=None):
        """GTPv2-C Release Access Bearers Request (type 170).

        Args:
            indication_flags: Raw 3-byte Indication IE value (optional).
                              Set ISR bit etc. as needed.
        """
        pkt = GTPv2CFactory._hdr(V2_RELEASE_ACCESS_BEARERS_REQ, teid, seqnum)
        ies = []
        if indication_flags is not None:
            ies.append(_ie2(GTPV2_INDICATION, 0, indication_flags))
        pkt.data = ies
        return pkt

    @staticmethod
    def release_access_bearers_res(teid=0, seqnum=0,
                                   cause=V2_CAUSE_REQUEST_ACCEPTED,
                                   recovery=None):
        """GTPv2-C Release Access Bearers Response (type 171).

        Args:
            cause    : GTPv2 cause code.
            recovery : Restart counter (int); omitted if None.
        """
        pkt = GTPv2CFactory._hdr(V2_RELEASE_ACCESS_BEARERS_RES, teid, seqnum)
        ies = [_ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff]))]
        if recovery is not None:
            ies.append(_ie2(GTPV2_REC_REST_CNT, 0, bytes([recovery & 0xff])))
        pkt.data = ies
        return pkt

    # ------------------------------------------------------------------
    # Downlink data notification
    # ------------------------------------------------------------------

    @staticmethod
    def dl_data_notification(teid=0, seqnum=0,
                             ebi=5,
                             arp_pci=0,
                             arp_pl=15,
                             arp_pvi=0):
        """GTPv2-C Downlink Data Notification (type 176).

        Sent by the SGW to the MME when buffered downlink data arrives for
        a UE in idle mode.

        Args:
            ebi      : EBI of the bearer with pending downlink data.
            arp_pci  : ARP Pre-emption Capability Indicator.
            arp_pl   : ARP Priority Level (1=highest, 15=lowest).
            arp_pvi  : ARP Pre-emption Vulnerability Indicator.
        """
        arp_byte = ((arp_pci & 0x1) << 6) | ((arp_pl & 0xf) << 2) | ((arp_pvi & 0x1) << 1)
        pkt = GTPv2CFactory._hdr(V2_DL_DATA_NOTIFY, teid, seqnum)
        pkt.data = [
            _ie2(GTPV2_EBI, 0, bytes([ebi & 0x0f])),
            _ie2(GTPV2_IE_ARP, 0, bytes([arp_byte])),
        ]
        return pkt

    @staticmethod
    def dl_data_notification_ack(teid=0, seqnum=0,
                                 cause=V2_CAUSE_REQUEST_ACCEPTED,
                                 dl_low_prio_traffic_throttling=None):
        """GTPv2-C Downlink Data Notification Acknowledge (type 177).

        Args:
            cause : GTPv2 cause code.
            dl_low_prio_traffic_throttling : Raw byte for throttling IE (optional).
        """
        pkt = GTPv2CFactory._hdr(V2_DL_DATA_NOTIFY_ACK, teid, seqnum)
        ies = [_ie2(GTPV2_IE_CAUSE, 0, bytes([cause & 0xff]))]
        if dl_low_prio_traffic_throttling is not None:
            ies.append(_ie2(GTPV2_IE_THROTTLING, 0,
                            bytes([dl_low_prio_traffic_throttling & 0xff])))
        pkt.data = ies
        return pkt
