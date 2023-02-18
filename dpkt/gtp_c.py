# -*- coding: utf-8 -*-
"""General Packet Radio System (GPRS) Tunneling Protocol (GTP)."""

from __future__ import absolute_import

import struct

from . import dpkt
from .compat import compat_ord
from binascii import hexlify as hx

# General Packet Radio Service (GPRS); GPRS Tunnelling Protocol (GTP)
# across the Gn and Gp interface
# https://www.3gpp.org/DynaReport/29060.htm
# 
# 3GPP Evolved Packet System (EPS);
# Evolved General Packet Radio Service (GPRS) Tunnelling Protocol
# for Control plane (GTPv2-C); Stage 3 
# https://www.3gpp.org/DynaReport/29274.htm
# 
# Telecommunication management; Charging management;
# Charging Data Record (CDR) transfer
# https://www.3gpp.org/DynaReport/32295.htm

# original source is https://github.com/wmnsk/dpkt/tree/gtpc_implementation
# https://github.com/wmnsk/dpkt/blob/gtpc_implementation/dpkt/gtp_c.py

# GTPv1 Message Types
V1_UNKNOWN = 0
V1_ECHO_REQ = 1
V1_ECHO_RES = 2
V1_VER_NOT_SUPPORTED = 3
V1_NODE_ALIVE_REQ = 4
V1_NODE_ALIVE_RES = 5
V1_REDIRECT_REQ = 6
V1_REDIRECT_RES = 7
V1_CREATE_PDP_CXT_REQ = 16
V1_CREATE_PDP_CXT_RES = 17
V1_UPDATE_PDP_CXT_REQ = 18
V1_UPDATE_PDP_CXT_RES = 19
V1_DELETE_PDP_CXT_REQ = 20
V1_DELETE_PDP_CXT_RES = 21
V1_INIT_PDP_CXT_ACT_REQ = 22
V1_INIT_PDP_CXT_ACT_RES = 23
V1_ERROR_INDICATION = 26
V1_PDU_NOTIFICATION_REQ = 27
V1_PDU_NOTIFICATION_RES = 28
V1_PDU_NOTIFICATION_REJECT_REQ = 29
V1_PDU_NOTIFICATION_REJECT_RES = 30
V1_SUPPORTED_EXT_HEADER_NOTIFY = 31
V1_SEND_ROUTING_INFO_GPRS = 32
V1_SEND_ROUTING_INFO_GPRS = 33
V1_FAILURE_REPORT_REQ = 34
V1_FAILURE_REPORT_RES = 35
V1_NOTE_MS_GPRS_PRESENT_REQ = 36
V1_NOTE_MS_GPRS_PRESENT_RES = 37
V1_INDICATION_REQ = 48
V1_INDICATION_RES = 49
V1_SGSN_CXT_REQ = 50
V1_SGSN_CXT_RES = 51
V1_SGSN_CXT_ACK = 52
V1_FORWARD_RELOC_REQ = 53
V1_FORWARD_RELOC_RES = 54
V1_FORWARD_RELOC_COMPLETE = 55
V1_RELOC_CANCEL_REQ = 56
V1_RELOC_CANCEL_RES = 57
V1_FORWARD_SRNS_CXT = 58
V1_FORWARD_RELOC_COMPLETE_ACK = 59
V1_FORWARD_SRNS_CXT_ACK = 60
V1_UE_REGIST_QUERY_REQ = 61
V1_UE_REGIST_QUERY_RES = 62
V1_RAN_INFORMATION_RELAY = 70
V1_MBMS_NOTIFICATION_REQ = 96
V1_MBMS_NOTIFICATION_RES = 97
V1_MBMS_NOTIFICATION_REJECT_REQ = 98
V1_MBMS_NOTIFICATION_REJECT_RES = 99
V1_CREATE_MBMS_CXT_REQ = 100
V1_CREATE_MBMS_CXT_RES = 101
V1_UPDATE_MBMS_CXT_REQ = 102
V1_UPDATE_MBMS_CXT_RES = 103
V1_DELETE_MBMS_CXT_REQ = 104
V1_DELETE_MBMS_CXT_RES = 105
V1_MBMS_REGIST_REQ = 112
V1_MBMS_REGIST_RES = 113
V1_MBMS_DEREGIST_REQ = 114
V1_MBMS_DEREGIST_RES = 115
V1_MBMS_SESSION_START_REQ = 116
V1_MBMS_SESSION_START_RES = 117
V1_MBMS_SESSION_STOP_REQ = 118
V1_MBMS_SESSION_STOP_RES = 119
V1_MBMS_SESSION_UPDATE_REQ = 120
V1_MBMS_SESSION_UPDATE_RES = 121
#V1_MS_INFO_CHANGE_NOTIFY_REQ = 128
V1_END_USER_ADDRESS= 128
V1_MS_INFO_CHANGE_NOTIFY_RES = 129
V1_DATA_RECORD_TRANSFER_REQ = 240
V1_DATA_RECORD_TRANSFER_RES = 241
V1_END_MARKER = 254
V1_G_PDU = 255

# GTPv1 Next Extension Headers
NO_MORE_EXT_HEADERS = 0
MBMS_SUPPORT_INDICATION = 1
MS_INFO_CHANVE_REPORTING_SUPPORT = 2
PDCP_PDU_NUMBER = 192
SUSPEND_REQUEST = 193
SUSPEND_RESPONSE = 194

# GTPv1 IEs without length
TV_RESERVED = 0
TV_CAUSE = 1
TV_IMSI = 2
TV_RAI = 3
TV_TLLI = 4
TV_P_TMSI = 5
TV_REORDER_REQUIRED = 8
TV_AUTH_TRIPLET = 9
TV_MAP_CAUSE = 11
TV_P_TMSI_SIGN = 12
TV_MS_VALIDATED = 13
TV_RECOVERY = 14
TV_SELECTION_MODE = 15
TV_TEID_DATA_1 = 16
TV_TEID_C_PLANE = 17
TV_TEID_DATA_2 = 18
TV_TEARDOWN_IND = 19
TV_NSAPI = 20
TV_RANAP_CAUSE = 21
TV_RAB_CXT = 22
TV_RADIO_PRIORITY_SMS = 23
TV_RADIO_PRIORITY = 24
TV_PACKET_FLOW_ID = 25
TV_CHARGING_CHARS = 26
TV_TRACE_REFERENCE = 27
TV_TRACE_TYPE = 28
TV_MS_NOT_REACHABLE_REASON = 29
TV_CHARGING_ID = 127

TV_LEN_DICT = {
    TV_RESERVED: 0,
    TV_CAUSE: 1,
    TV_IMSI: 8,
    TV_RAI: 6,
    TV_TLLI: 4,
    TV_P_TMSI: 4,
    TV_REORDER_REQUIRED: 1,
    TV_AUTH_TRIPLET: 28,
    TV_MAP_CAUSE: 1,
    TV_P_TMSI_SIGN: 3,
    TV_MS_VALIDATED: 1,
    TV_RECOVERY: 1,
    TV_SELECTION_MODE: 1,
    TV_TEID_DATA_1: 4,
    TV_TEID_C_PLANE: 4,
    TV_TEID_DATA_2: 5,
    TV_TEARDOWN_IND: 1,
    TV_NSAPI: 1,
    TV_RANAP_CAUSE: 1,
    TV_RAB_CXT: 9,
    TV_RADIO_PRIORITY_SMS: 1,
    TV_RADIO_PRIORITY: 1,
    TV_PACKET_FLOW_ID: 2,
    TV_CHARGING_CHARS: 2,
    TV_TRACE_REFERENCE: 2,
    TV_TRACE_TYPE: 2,
    TV_MS_NOT_REACHABLE_REASON: 1,
    TV_CHARGING_ID: 4
}


# GTPv2 Message Types
V2_RESERVED = 0
V2_ECHO_REQ = 1
V2_ECHO_RES = 2
V2_VER_NOT_SUPPORTED = 3
V2_CREATE_SESSION_REQ = 32
V2_CREATE_SESSION_RES = 33
V2_MODIFY_BEARER_REQ = 34
V2_MODIFY_BEARER_RES = 35
V2_DELETE_SESSION_REQ = 36
V2_DELETE_SESSION_RES = 37
V2_CHANGE_NOTIFICATION_REQ = 38
V2_CHANGE_NOTIFICATION_RES = 39
V2_REMOTE_UE_REPORT_NOTIFY = 40
V2_REMOTE_UE_REPORT_ACK = 41
V2_MODIFY_BEARER_CMD = 64
V2_MODIFY_BEARER_FAIL = 65
V2_DELETE_BEARER_CMD = 66
V2_DELETE_BEARER_FAIL = 67
V2_BEARER_RESOURCE_CMD = 68
V2_BEARER_RESOURCE_FAIL = 69
V2_DL_DATA_NOTE_FAIL = 70
V2_TRACE_SESSION_ACT = 71
V2_TRACE_SESSION_DEACT = 72
V2_STOP_PAGING_INDICATION = 73
V2_CREATE_BEARER_REQ = 95
V2_CREATE_BEARER_RES = 96
V2_UPDATE_BEARER_REQ = 97
V2_UPDATE_BEARER_RES = 98
V2_MODIFY_BEARER_REQ = 99
V2_MODIFY_BEARER_RES = 100
V2_DELETE_PDN_CONN_SET_REQ = 101
V2_DELETE_PDN_CONN_SET_RES = 102
V2_PGW_DL_TRIGGER_NOTIFY = 103
V2_PGW_DL_TRIGGER_ACK = 104
V2_INDICATION_REQ = 128
V2_INDICATION_RES = 129
V2_CONTEXT_REQ = 130
V2_CONTEXT_RES = 131
V2_CONTEXT_ACK = 132
V2_FORWARD_RELOC_REQ = 133
V2_FORWARD_RELOC_RES = 134
V2_FORWARD_RELOC_COMPLETE_REQ = 135
V2_FORWARD_RELOC_COMPLETE_REQ = 136
V2_FORWARD_ACCESS_CONTEXT_NOTIFY = 137
V2_FORWARD_ACCESS_CONTEXT_ACK = 138
V2_RELOC_CANCEL_REQ = 139
V2_RELOC_CANCEL_RES = 140
V2_CONFIG_TRANSFER_TUNNEL = 141
V2_DETACH_NOTIFY = 149
V2_DETACH_ACK = 150
V2_CS_PAGING_INDICATION = 151
V2_RAN_INFO_RELAY = 152
V2_ALERT_MME_NOTIFY = 153
V2_ALERT_MME_ACK = 154
V2_UE_ACTIVITY_NOTIFY = 155
V2_UE_ACTIVITY_ACK = 156
V2_ISR_STATUS_INDICATION = 157
V2_UE_REGIST_QUERY_REQ = 158
V2_UE_REGIST_QUERY_RES = 159
V2_CREATE_FORWARDING_TUNNEL_REQ = 160
V2_CREATE_FORWARDING_TUNNEL_RES = 161
V2_SUSPEND_NOTIFY = 162
V2_SUSPEND_NOTIFY = 163
V2_RESUME_NOTIFY = 164
V2_RESUME_ACK = 165
V2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ = 166
V2_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RES = 167
V2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ = 168
V2_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RES = 169
V2_RELEASE_ACCESS_BEARERS_REQ = 170
V2_RELEASE_ACCESS_BEARERS_RES = 171
V2_DL_DATA_NOTIFY = 176
V2_DL_DATA_NOTIFY_ACK = 177
V2_PGW_RESTART_NOTIFY = 179
V2_PGW_RESTART_ACK = 180
V2_UPDATE_PDN_CONN_SET_REQ = 200
V2_UPDATE_PDN_CONN_SET_RES = 201
V2_MODIFY_ACCESS_BEARERS_REQ = 211
V2_MODIFY_ACCESS_BEARERS_RES = 212
V2_MBMS_SESSION_START_REQ = 231
V2_MBMS_SESSION_START_RES = 232
V2_MBMS_SESSION_UPDATE_REQ = 233
V2_MBMS_SESSION_UPDATE_RES = 234
V2_MBMS_SESSION_STOP_REQ = 235
V2_MBMS_SESSION_STOP_RES = 236

# GTP v2 IEIs
###################################################################################
# GTPV2 field tag values originated from https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-gtpv2.c
GTPV2_IE_HEX  =                  -1
GTPV2_IE_RESERVED =               0
GTPV2_IE_IMSI =                   1
GTPV2_IE_CAUSE =                  2
GTPV2_REC_REST_CNT =              3
#/*Start SRVCC Messages*/
GTPV2_IE_STN_SR =                51
GTPV2_IE_SRC_TGT_TRANS_CON =     52
GTPV2_IE_TGT_SRC_TRANS_CON =     53
GTPV2_IE_MM_CON_EUTRAN_SRVCC =   54
GTPV2_IE_MM_CON_UTRAN_SRVCC =    55
GTPV2_IE_SRVCC_CAUSE =           56
GTPV2_IE_TGT_RNC_ID =            57
GTPV2_IE_TGT_GLOGAL_CELL_ID =    58
GTPV2_IE_TEID_C =                59
GTPV2_IE_SV_FLAGS =              60
GTPV2_IE_SAI =                   61
GTPV2_IE_MM_CTX_FOR_CS_TO_PS_SRVCC=62
#/* 61 - 70 for future sv interface use*/
#/*End SRVCC Messages*/
GTPV2_IE_APN =                      71
GTPV2_AMBR =                     72
GTPV2_EBI =                      73
GTPV2_IP_ADDRESS =               74
GTPV2_IE_MEI =                   75
GTPV2_IE_MSISDN =                76
GTPV2_INDICATION =               77
GTPV2_PCO =                      78
GTPV2_PAA =                      79
GTPV2_BEARER_QOS =               80
GTPV2_IE_FLOW_QOS =              81
GTPV2_IE_RAT_TYPE =              82
GTPV2_IE_SERV_NET =              83
GTPV2_IE_BEARER_TFT =            84
GTPV2_IE_TAD =                   85
GTPV2_IE_ULI =                   86
GTPV2_IE_F_TEID =                87
GTPV2_IE_TMSI =                  88
GTPV2_IE_GLOBAL_CNID =           89
GTPV2_IE_S103PDF =               90
GTPV2_IE_S1UDF =                 91
GTPV2_IE_DEL_VAL =               92
GTPV2_IE_BEARER_CTX =            93
GTPV2_IE_CHAR_ID =               94
GTPV2_IE_CHAR_CHAR =             95
GTPV2_IE_TRA_INFO =              96
GTPV2_BEARER_FLAG =              97
#/* define GTPV2_IE_PAGING_CAUSE =        98 (void) */
GTPV2_IE_PDN_TYPE =              99
GTPV2_IE_PTI =                  100
GTPV2_IE_DRX_PARAM =            101
GTPV2_IE_UE_NET_CAPABILITY =    102
GTPV2_IE_MM_CONTEXT_GSM_T =     103
GTPV2_IE_MM_CONTEXT_UTMS_CQ =   104
GTPV2_IE_MM_CONTEXT_GSM_CQ =    105
GTPV2_IE_MM_CONTEXT_UTMS_Q =    106
GTPV2_IE_MM_CONTEXT_EPS_QQ =    107
GTPV2_IE_MM_CONTEXT_UTMS_QQ =   108
GTPV2_IE_PDN_CONNECTION =       109
GTPV2_IE_PDN_NUMBERS =          110
GTPV2_IE_P_TMSI =               111
GTPV2_IE_P_TMSI_SIG =           112
GTPV2_IE_HOP_COUNTER =          113
GTPV2_IE_UE_TIME_ZONE =         114
GTPV2_IE_TRACE_REFERENCE =      115
GTPV2_IE_COMPLETE_REQUEST_MSG = 116
GTPV2_IE_GUTI =                 117
GTPV2_IE_F_CONTAINER =          118
GTPV2_IE_F_CAUSE =              119
GTPV2_IE_SEL_PLMN_ID =          120
GTPV2_IE_TARGET_ID =            121
#/* GTPV2_IE_NSAPI =                     122 */
GTPV2_IE_PKT_FLOW_ID =          123
GTPV2_IE_RAB_CONTEXT =          124
GTPV2_IE_S_RNC_PDCP_CTX_INFO =  125
GTPV2_IE_UDP_S_PORT_NR =        126
GTPV2_IE_APN_RESTRICTION =      127
GTPV2_IE_SEL_MODE =             128
GTPV2_IE_SOURCE_IDENT =         129
GTPV2_IE_BEARER_CONTROL_MODE =  130
GTPV2_IE_CNG_REP_ACT =          131
GTPV2_IE_FQ_CSID =              132
GTPV2_IE_CHANNEL_NEEDED =       133
GTPV2_IE_EMLPP_PRI =            134
GTPV2_IE_NODE_TYPE =            135
GTPV2_IE_FQDN =                 136
GTPV2_IE_TI =                   137
GTPV2_IE_MBMS_SESSION_DURATION =138
GTPV2_IE_MBMS_SERVICE_AREA =    139
GTPV2_IE_MBMS_SESSION_ID =      140
GTPV2_IE_MBMS_FLOW_ID =         141
GTPV2_IE_MBMS_IP_MC_DIST =      142
GTPV2_IE_MBMS_DIST_ACK =        143
GTPV2_IE_RFSP_INDEX =           144
GTPV2_IE_UCI =                  145
GTPV2_IE_CSG_INFO_REP_ACTION =  146
GTPV2_IE_CSG_ID =               147
GTPV2_IE_CMI =                  148
GTPV2_IE_SERVICE_INDICATOR =    149
GTPV2_IE_DETACH_TYPE =          150
GTPV2_IE_LDN =                  151
GTPV2_IE_NODE_FEATURES =        152
GTPV2_IE_MBMS_TIME_TO_DATA_XFER=153
GTPV2_IE_THROTTLING =           154
GTPV2_IE_ARP =                  155
GTPV2_IE_EPC_TIMER =            156
GTPV2_IE_SIG_PRIO_IND =         157
GTPV2_IE_TMGI =                 158
GTPV2_IE_ADD_MM_CONT_FOR_SRVCC =159
GTPV2_IE_ADD_FLAGS_FOR_SRVCC =  160
GTPV2_IE_MMBR =                 161
GTPV2_IE_MDT_CONFIG =           162
GTPV2_IE_APCO =                 163
GTPV2_IE_ABS_MBMS_DATA_TF_TIME =164
GTPV2_IE_HENB_INFO_REPORT =     165
GTPV2_IE_IP4CP =                166
GTPV2_IE_CHANGE_TO_REPORT_FLAGS=167
GTPV2_IE_ACTION_INDICATION =    168
GTPV2_IE_TWAN_IDENTIFIER =      169
GTPV2_IE_ULI_TIMESTAMP =        170
GTPV2_IE_MBMS_FLAGS =           171
GTPV2_IE_RAN_NAS_CAUSE =        172
GTPV2_IE_CN_OP_SEL_ENT =        173
GTPV2_IE_TRUST_WLAN_MODE_IND =  174
GTPV2_IE_NODE_NUMBER =          175
GTPV2_IE_NODE_IDENTIFIER =      176
GTPV2_IE_PRES_REP_AREA_ACT =    177
GTPV2_IE_PRES_REP_AREA_INF =    178
GTPV2_IE_TWAN_ID_TS =           179
GTPV2_IE_OVERLOAD_CONTROL_INF = 180
GTPV2_IE_LOAD_CONTROL_INF =     181
GTPV2_IE_METRIC =               182
GTPV2_IE_SEQ_NO =               183
GTPV2_IE_APN_AND_REL_CAP =      184
GTPV2_IE_WLAN_OFFLOADABILITY_IND=185
GTPV2_IE_PAGING_AND_SERVICE_INF=186
GTPV2_IE_INTEGER_NUMBER =       187
GTPV2_IE_MILLISECOND_TS =       188
# manually added
GTPV2_IE_MONITOR_EVENT_INFO =   189
GTPV2_IE_REMOTE_UE_CTX =   191
GTPV2_IE_EPCO =   197
GTPV2_IE_SERVING_PLMN_RATE_CONTROL = 198
GTPV2_IE_COUNTER = 199
GTPV2_IE_MAP_USAGE = 200
GTPV2_IE_PRIV = 255

glist = list(globals())
gtpv2_fieldnames = {}
for g in glist:
    if "GTPV2_" in g: gtpv2_fieldnames[globals()[g]] = g



class GTPv1C(dpkt.Packet):
    """GTPv1-C Header.

    Attributes:
        __hdr__  : GTPv2-C header in general format
                    - flags: Version, Piggyback flag, TEID flag, and spare bits
                    - type : GTPv2-C Message Type
                    - len  : length of whole payload
        teid     : Tunnel Endpoint Identifier
        seqnum   : Sequence Number
        ndpu     : N-PDU Number
        next_type:  Next Extension Header Type
    """
    __hdr__ = (
        ('flags', 'B', 0),
        ('type', 'B', 0),
        ('len', 'H', 0),
        ('teid', 'I', 0),
    )

    @property
    def version(self):
        return (self.flags >> 5) & 0x7

    @version.setter
    def version(self, v):
        self.flags = (self.flags & ~0xe0) | ((v & 0x7) << 5)

    @property
    def proto_type(self):
        return (self.flags >> 4) & 0x1

    @proto_type.setter
    def proto_type(self, p):
        self.flags = (self.flags & ~0x10) | ((p & 0x1) << 4)

    @property
    def e_flag(self):
        return (self.flags >> 2) & 0x1

    @e_flag.setter
    def e_flag(self, e):
        self.flags = (self.flags & ~0x4) | ((e & 0x1) << 2)

    @property
    def s_flag(self):
        return (self.flags >> 1) & 0x1

    @s_flag.setter
    def s_flag(self, s):
        self.flags = (self.flags & ~0x2) | ((s & 0x1) << 1)

    @property
    def np_flag(self):
        return self.flags & 0x1

    @np_flag.setter
    def np_flag(self, n):
        self.flags = (self.flags & ~0x1) | (n & 0x1)

    @property
    def __additionals(self):
        return self.flags & 0x7

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        if self.__additionals:
            self.seqnum = (
                (compat_ord(self.data[0]) << 8) |
                (compat_ord(self.data[1]))
            )
            self.npdu = compat_ord(self.data[2])
            self.next_type = compat_ord(self.data[3])
            self.data = self.data[4:]

        l = []
        while self.data:
            ie = IEv1(self.data)
            l.append(ie)
            self.data = self.data[len(ie):]
        self.data = self.ies = l

    def pack_hdr(self):
        if type(self.data) != list:
            return dpkt.Packet.pack_hdr(self)
        else:
            data = b''.join([bytes(d) for d in self.data])

        if self.__additionals:
            self.seqnum = struct.pack('BB',
                (self.seqnum >> 8) & 0xff,
                (self.seqnum) & 0xff,
            )
            self.npdu = struct.pack('B', self.npdu & 0xff)
            self.next_type = struct.pack('B', self.next_type & 0xff)
            data = self.seqnum + self.npdu + self.next_type + data
        else:
            self.seqnum = b''
            self.npdu = b''
            self.next_type = b''

        self.data = self.seqnum + self.npdu + self.next_type + b''.join([bytes(d) for d in self.data])
        self.len = len(self.data)

        return dpkt.Packet.pack_hdr(self)
    def __bytes__(self):
        ie_bytes = []
        [ie_bytes.append(bytes(ie)) for ie in self.ies]
        return self.pack_hdr() + b''.join(ie_bytes)


class GTPv2C(dpkt.Packet):
    """GTPv2-C Header.

    Attributes:
        __hdr__ : GTPv2-C header in general format
                   - flags: Version, Piggyback flag, TEID flag, and spare bits
                   - type : GTPv2-C Message Type
                   - len  : length of whole payload
        teid    : Tunnel Endpoint Identifier
        seqnum  : Sequence Number
        priority: Message Priority
    """
    __hdr__ = (
        ('flags', 'B', 0),
        ('type', 'B', 0),
        ('len', 'H', 0),
    )

    @property
    def version(self):
        return (self.flags >> 5) & 0x7

    @version.setter
    def version(self, v):
        self.flags = (self.flags & ~0xe0) | ((v & 0x7) << 5)

    @property
    def p_flag(self):
        return (self.flags >> 4) & 0x1

    @p_flag.setter
    def p_flag(self, p):
        self.flags = (self.flags & ~0x10) | ((p & 0x1) << 4)

    @property
    def t_flag(self):
        return (self.flags >> 3) & 0x1

    @t_flag.setter
    def t_flag(self, t):
        self.flags = (self.flags & ~0x8) | ((t & 0x1) << 3)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        if self.t_flag:
            self.teid = (
                (compat_ord(self.data[0]) << 24) |
                (compat_ord(self.data[1]) << 16) |
                (compat_ord(self.data[2]) << 8) |
                (compat_ord(self.data[3]))
            )
            self.seqnum = (
                (compat_ord(self.data[4]) << 16) |
                (compat_ord(self.data[5]) << 8) |
                (compat_ord(self.data[6]))
            )
            self.priority = (compat_ord(self.data[7]) >> 4) & 0xf
            self.data = self.data[8:]
        else:
            self.seqnum = self.data[:3]
            self.data = self.data[5:]

        l = []
        while self.data:
            ie = IEv2(self.data)
            l.append(ie)
            self.data = self.data[len(ie):]
        self.data = self.ies = l

    def pack_hdr(self):
        if type(self.data) != list:
            return dpkt.Packet.pack_hdr(self)
        else:
            data = b''.join([bytes(d) for d in self.data])

            self.seqnum = struct.pack('3B',
                (self.seqnum >> 16) & 0xff,
                (self.seqnum >> 8) & 0xff,
                (self.seqnum) & 0xff,
            )
            data = self.seqnum + b'\x00' + data

            if self.t_flag:
                self.teid = struct.pack('4B',
                    (self.teid >> 24) & 0xff,
                    (self.teid >> 16) & 0xff,
                    (self.teid >> 8) & 0xff,
                    (self.teid) & 0xff,
                )
                data = self.teid + data

            self.data = data
            self.len = len(self.data)
            return dpkt.Packet.pack_hdr(self)
    def __bytes__(self):
        ie_bytes = []
        [ie_bytes.append(bytes(ie)) for ie in self.ies]
        return self.pack_hdr() + b''.join(ie_bytes)


class IEv1(dpkt.Packet):
    """docstring for IEv1
        __hdr__ : Information Element Header for GTPv1-C.
                   - type : IE Type
                   - len  : length
    """
    __hdr__ = (
        ('type', 'B', 0),
    )

    @property
    def encoding(self):
        return (self.type >> 7) & 0x1

    @encoding.setter
    def encoding(self, e):
        self.type = (self.type & ~0x80) | ((e & 0x1) << 7) 

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.encoding:
            # there is a 2 byte length field
            self.len = struct.unpack("!H", self.data[:2])[0]
            self.data = self.data[2:2+self.len]
        else:
            self.len = TV_LEN_DICT.get(self.type)
            self.data = self.data[:self.len]

    def pack_hdr(self):
        data = dpkt.Packet.pack_hdr(self)
        if self.encoding:
            packed_len = struct.pack('!H', self.len)
            data =  data + packed_len

        return data
    def __len__(self):
        if self.encoding:
            return self.__hdr_len__ + 2 + len(self.data)  # 2 byte length field
        else:
            return self.__hdr_len__ + len(self.data)


class IEv2(dpkt.Packet):
    """docstring for IEv2

    Attributes:
        __hdr__ : Information Element Header for GTPv2-C.
                   - type : IE Type
                   - len  : length
                   - flags: CR flag and Instance
    """
    __hdr__ = (
        ('type', 'B', 0),
        ('len', 'H', 0),
        ('flags', 'B', 0),
    )

    @property
    def cr_flag(self):
        return (self.flags >> 4) & 0xf

    @cr_flag.setter
    def cr_flag(self, c):
        pass

    @property
    def instance(self):
        return self.flags & 0xf

    @instance.setter
    def instance(self, c):
        pass

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = self.data[:self.len]

    def pack_hdr(self):
        self.len = len(self.data)
        return dpkt.Packet.pack_hdr(self)


__v1c_payloads = [
    b'2\x10\x00%\x00\x00\x00\x10\x00\n\xca\xfe', # Header
    b'\x01\x00\x08\x00D\x90\x01\x12#4E\xf5', #IMSI
    b'G\x00\x11\x00some.operator.net' # APN
]

__v1c = b''.join(__v1c_payloads)

__v2c_payloads = [
    b'H \x00\x29\x00\x00\x00\x10\x01\x00\n\x00', # Header
    b'\x01\x00\x08\x00D\x90\x01\x12#4E\xf5', #IMSI
    b'G\x00\x11\x00some.operator.net' # APN
]

__v2c = b''.join(__v2c_payloads)


def test_unpack():
    v2c = GTPv2C(__v2c)
    assert (v2c.version == 2)
    assert (v2c.p_flag == 0)
    assert (v2c.t_flag == 1)
    assert (v2c.type == V2_CREATE_SESSION_REQ)
    assert (v2c.len == 41)
    assert (v2c.teid == 0x00000010)
    assert (v2c.seqnum == 0x01000a)

    imsi = v2c.ies[0]
    assert (imsi.type == 1)
    assert (imsi.len == 8)
    assert (imsi.cr_flag == 0)
    assert (imsi.instance == 0)
    assert (imsi.data == b'D\x90\x01\x12#4E\xf5')

    apn = v2c.ies[1]
    assert (apn.type == 71)
    assert (apn.len == 17)
    assert (apn.cr_flag == 0)
    assert (apn.instance == 0)
    assert (apn.data == b'some.operator.net')

    v1c = GTPv1C(__v1c)
    assert (v1c.version == 1)
    assert (v1c.proto_type == 1)
    assert (v1c.e_flag == 0)
    assert (v1c.s_flag == 1)
    assert (v1c.np_flag == 0)
    assert (v1c.type == V1_CREATE_PDP_CXT_REQ)
    assert (v1c.len == 37)
    assert (v1c.teid == 0x00000010)
    assert (v1c.seqnum == 0x000a)
    assert (v1c.npdu == 0xca)
    assert (v1c.next_type == 0xfe)

    imsi = v1c.ies[0]
    assert (imsi.type == 1)
    assert (imsi.len == 8)
    assert (imsi.cr_flag == 0)
    assert (imsi.instance == 0)
    assert (imsi.data == b'D\x90\x01\x12#4E\xf5')

    apn = v1c.ies[1]
    assert (apn.type == 71)
    assert (apn.len == 17)
    assert (apn.cr_flag == 0)
    assert (apn.instance == 0)
    assert (apn.data == b'some.operator.net')

def test_pack():
    v1c = GTPv1C(
        version=1,
        proto_type=1,
        e_flag=0,
        s_flag=1,
        np_flag=0,
        type=V1_CREATE_PDP_CXT_REQ,
        teid=0x00000010,
        seqnum=0x000a,
        npdu=0xca,
        next_type=0xfe
        )

    v2c = GTPv2C(
        version=2,
        p_flag=0,
        t_flag=1,
        type=V2_CREATE_SESSION_REQ,
        teid=0x00000010,
        seqnum=0x01000a
        )

    infoelems = [
        IEv2(
            type=1,
            cr_flag=0,
            instance=0,
            data=b'D\x90\x01\x12#4E\xf5'
        ),
        IEv2(
            type=71,
            cr_flag=0,
            instance=0,
            data=b'some.operator.net'
        )
    ]

    v1c.data = infoelems
    assert (bytes(v1c) == __v1c)

    v2c.data = infoelems
    assert (bytes(v2c) == __v2c)