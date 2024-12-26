/*
 * cydivert_device.h
 * (C) 2019, all rights reserved,
 *
 * This file is part of CyDivert.
 *
 * CyDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * CyDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __CYDIVERT_DEVICE_H
#define __CYDIVERT_DEVICE_H

/*
 * NOTE: This is the low-level interface to the CyDivert device driver.
 *       This interface should not be used directly, instead use the high-level
 *       interface provided by the CyDivert API.
 */

#define CYDIVERT_KERNEL
#include "cydivert.h"

#define CYDIVERT_VERSION_MAJOR                     1
#define CYDIVERT_VERSION_MINOR                     0

#define CYDIVERT_MAGIC_DLL                         0x4C4C447669645724ull
#define CYDIVERT_MAGIC_SYS                         0x5359537669645723ull

#define CYDIVERT_STR2(s)                           #s
#define CYDIVERT_STR(s)                            CYDIVERT_STR2(s)
#define CYDIVERT_LSTR2(s)                          L ## #s
#define CYDIVERT_LSTR(s)                           CYDIVERT_LSTR2(s)

#define CYDIVERT_VERSION_LSTR                                              \
    CYDIVERT_LSTR(CYDIVERT_VERSION_MAJOR) L"."                            \
        CYDIVERT_LSTR(CYDIVERT_VERSION_MINOR)

#define CYDIVERT_DEVICE_NAME                                               \
    L"CyDivert"
#define CYDIVERT_LAYER_NAME                                                \
    CYDIVERT_DEVICE_NAME CYDIVERT_VERSION_LSTR

#define CYDIVERT_FILTER_FIELD_ZERO                 0
#define CYDIVERT_FILTER_FIELD_INBOUND              1
#define CYDIVERT_FILTER_FIELD_OUTBOUND             2
#define CYDIVERT_FILTER_FIELD_IFIDX                3
#define CYDIVERT_FILTER_FIELD_SUBIFIDX             4
#define CYDIVERT_FILTER_FIELD_IP                   5
#define CYDIVERT_FILTER_FIELD_IPV6                 6
#define CYDIVERT_FILTER_FIELD_ICMP                 7
#define CYDIVERT_FILTER_FIELD_TCP                  8
#define CYDIVERT_FILTER_FIELD_UDP                  9
#define CYDIVERT_FILTER_FIELD_ICMPV6               10
#define CYDIVERT_FILTER_FIELD_IP_HDRLENGTH         11
#define CYDIVERT_FILTER_FIELD_IP_TOS               12
#define CYDIVERT_FILTER_FIELD_IP_LENGTH            13
#define CYDIVERT_FILTER_FIELD_IP_ID                14
#define CYDIVERT_FILTER_FIELD_IP_DF                15
#define CYDIVERT_FILTER_FIELD_IP_MF                16
#define CYDIVERT_FILTER_FIELD_IP_FRAGOFF           17
#define CYDIVERT_FILTER_FIELD_IP_TTL               18
#define CYDIVERT_FILTER_FIELD_IP_PROTOCOL          19
#define CYDIVERT_FILTER_FIELD_IP_CHECKSUM          20
#define CYDIVERT_FILTER_FIELD_IP_SRCADDR           21
#define CYDIVERT_FILTER_FIELD_IP_DSTADDR           22
#define CYDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS    23
#define CYDIVERT_FILTER_FIELD_IPV6_FLOWLABEL       24
#define CYDIVERT_FILTER_FIELD_IPV6_LENGTH          25
#define CYDIVERT_FILTER_FIELD_IPV6_NEXTHDR         26
#define CYDIVERT_FILTER_FIELD_IPV6_HOPLIMIT        27
#define CYDIVERT_FILTER_FIELD_IPV6_SRCADDR         28
#define CYDIVERT_FILTER_FIELD_IPV6_DSTADDR         29
#define CYDIVERT_FILTER_FIELD_ICMP_TYPE            30
#define CYDIVERT_FILTER_FIELD_ICMP_CODE            31
#define CYDIVERT_FILTER_FIELD_ICMP_CHECKSUM        32
#define CYDIVERT_FILTER_FIELD_ICMP_BODY            33
#define CYDIVERT_FILTER_FIELD_ICMPV6_TYPE          34
#define CYDIVERT_FILTER_FIELD_ICMPV6_CODE          35
#define CYDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM      36
#define CYDIVERT_FILTER_FIELD_ICMPV6_BODY          37
#define CYDIVERT_FILTER_FIELD_TCP_SRCPORT          38
#define CYDIVERT_FILTER_FIELD_TCP_DSTPORT          39
#define CYDIVERT_FILTER_FIELD_TCP_SEQNUM           40
#define CYDIVERT_FILTER_FIELD_TCP_ACKNUM           41
#define CYDIVERT_FILTER_FIELD_TCP_HDRLENGTH        42
#define CYDIVERT_FILTER_FIELD_TCP_URG              43
#define CYDIVERT_FILTER_FIELD_TCP_ACK              44
#define CYDIVERT_FILTER_FIELD_TCP_PSH              45
#define CYDIVERT_FILTER_FIELD_TCP_RST              46
#define CYDIVERT_FILTER_FIELD_TCP_SYN              47
#define CYDIVERT_FILTER_FIELD_TCP_FIN              48
#define CYDIVERT_FILTER_FIELD_TCP_WINDOW           49
#define CYDIVERT_FILTER_FIELD_TCP_CHECKSUM         50
#define CYDIVERT_FILTER_FIELD_TCP_URGPTR           51
#define CYDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH    52
#define CYDIVERT_FILTER_FIELD_UDP_SRCPORT          53
#define CYDIVERT_FILTER_FIELD_UDP_DSTPORT          54
#define CYDIVERT_FILTER_FIELD_UDP_LENGTH           55
#define CYDIVERT_FILTER_FIELD_UDP_CHECKSUM         56
#define CYDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH    57
#define CYDIVERT_FILTER_FIELD_LOOPBACK             58
#define CYDIVERT_FILTER_FIELD_IMPOSTOR             59
#define CYDIVERT_FILTER_FIELD_PROCESSID            60
#define CYDIVERT_FILTER_FIELD_LOCALADDR            61
#define CYDIVERT_FILTER_FIELD_REMOTEADDR           62
#define CYDIVERT_FILTER_FIELD_LOCALPORT            63
#define CYDIVERT_FILTER_FIELD_REMOTEPORT           64
#define CYDIVERT_FILTER_FIELD_PROTOCOL             65
#define CYDIVERT_FILTER_FIELD_ENDPOINTID           66
#define CYDIVERT_FILTER_FIELD_PARENTENDPOINTID     67
#define CYDIVERT_FILTER_FIELD_LAYER                68
#define CYDIVERT_FILTER_FIELD_PRIORITY             69
#define CYDIVERT_FILTER_FIELD_EVENT                70
#define CYDIVERT_FILTER_FIELD_PACKET               71
#define CYDIVERT_FILTER_FIELD_PACKET16             72
#define CYDIVERT_FILTER_FIELD_PACKET32             73
#define CYDIVERT_FILTER_FIELD_TCP_PAYLOAD          74
#define CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16        75
#define CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32        76
#define CYDIVERT_FILTER_FIELD_UDP_PAYLOAD          77
#define CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16        78
#define CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32        79
#define CYDIVERT_FILTER_FIELD_LENGTH               80
#define CYDIVERT_FILTER_FIELD_TIMESTAMP            81
#define CYDIVERT_FILTER_FIELD_RANDOM8              82
#define CYDIVERT_FILTER_FIELD_RANDOM16             83
#define CYDIVERT_FILTER_FIELD_RANDOM32             84
#define CYDIVERT_FILTER_FIELD_FRAGMENT             85
#define CYDIVERT_FILTER_FIELD_MAX                  \
    CYDIVERT_FILTER_FIELD_FRAGMENT

#define CYDIVERT_FILTER_TEST_EQ                    0
#define CYDIVERT_FILTER_TEST_NEQ                   1
#define CYDIVERT_FILTER_TEST_LT                    2
#define CYDIVERT_FILTER_TEST_LEQ                   3
#define CYDIVERT_FILTER_TEST_GT                    4
#define CYDIVERT_FILTER_TEST_GEQ                   5
#define CYDIVERT_FILTER_TEST_MAX                   CYDIVERT_FILTER_TEST_GEQ

#define CYDIVERT_FILTER_MAXLEN                     256

#define CYDIVERT_FILTER_RESULT_ACCEPT              0x7FFE
#define CYDIVERT_FILTER_RESULT_REJECT              0x7FFF

/*
 * CyDivert layers.
 */
#define CYDIVERT_LAYER_MAX                         CYDIVERT_LAYER_REFLECT

/*
 * CyDivert events.
 */
#define CYDIVERT_EVENT_MAX                         \
    CYDIVERT_EVENT_REFLECT_CLOSE

/*
 * CyDivert flags.
 */
#define CYDIVERT_FLAGS_ALL                                                 \
    (CYDIVERT_FLAG_SNIFF | CYDIVERT_FLAG_DROP | CYDIVERT_FLAG_RECV_ONLY |\
        CYDIVERT_FLAG_SEND_ONLY | CYDIVERT_FLAG_NO_INSTALL |              \
        CYDIVERT_FLAG_FRAGMENTS)
#define CYDIVERT_FLAGS_EXCLUDE(flags, flag1, flag2)                        \
    (((flags) & ((flag1) | (flag2))) != ((flag1) | (flag2)))
#define CYDIVERT_FLAGS_VALID(flags)                                        \
    ((((flags) & ~CYDIVERT_FLAGS_ALL) == 0) &&                             \
     CYDIVERT_FLAGS_EXCLUDE(flags, CYDIVERT_FLAG_SNIFF,                   \
        CYDIVERT_FLAG_DROP) &&                                             \
     CYDIVERT_FLAGS_EXCLUDE(flags, CYDIVERT_FLAG_RECV_ONLY,               \
        CYDIVERT_FLAG_SEND_ONLY))

/*
 * CyDivert filter flags.
 */
#define CYDIVERT_FILTER_FLAG_INBOUND               0x0000000000000010ull
#define CYDIVERT_FILTER_FLAG_OUTBOUND              0x0000000000000020ull
#define CYDIVERT_FILTER_FLAG_IP                    0x0000000000000040ull
#define CYDIVERT_FILTER_FLAG_IPV6                  0x0000000000000080ull
#define CYDIVERT_FILTER_FLAG_EVENT_FLOW_DELETED    0x0000000000000100ull
#define CYDIVERT_FILTER_FLAG_EVENT_SOCKET_BIND     0x0000000000000200ull
#define CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CONNECT  0x0000000000000400ull
#define CYDIVERT_FILTER_FLAG_EVENT_SOCKET_LISTEN   0x0000000000000800ull
#define CYDIVERT_FILTER_FLAG_EVENT_SOCKET_ACCEPT   0x0000000000001000ull
#define CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CLOSE    0x0000000000002000ull

#define CYDIVERT_FILTER_FLAGS_ALL                                          \
    (CYDIVERT_FILTER_FLAG_INBOUND |                                        \
        CYDIVERT_FILTER_FLAG_OUTBOUND |                                    \
        CYDIVERT_FILTER_FLAG_IP |                                          \
        CYDIVERT_FILTER_FLAG_IPV6 |                                        \
        CYDIVERT_FILTER_FLAG_EVENT_FLOW_DELETED |                          \
        CYDIVERT_FILTER_FLAG_EVENT_SOCKET_BIND |                           \
        CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CONNECT |                        \
        CYDIVERT_FILTER_FLAG_EVENT_SOCKET_LISTEN |                         \
        CYDIVERT_FILTER_FLAG_EVENT_SOCKET_ACCEPT |                         \
        CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CLOSE)

/*
 * CyDivert priorities.
 */
#define CYDIVERT_PRIORITY_MAX                      CYDIVERT_PRIORITY_HIGHEST
#define CYDIVERT_PRIORITY_MIN                      CYDIVERT_PRIORITY_LOWEST

/*
 * CyDivert timestamps.
 */
#define CYDIVERT_TIMESTAMP_MAX                     0x7FFFFFFFFFFFFFFFull

/*
 * CyDivert message definitions.
 */
#pragma pack(push, 1)
typedef union
{
    struct
    {
        UINT64 addr;                // CYDIVERT_ADDRESS pointer.
        UINT64 addr_len_ptr;        // sizeof(addr) pointer.
    } recv;
    struct
    {
        UINT64 addr;                // CYDIVERT_ADDRESS pointer.
        UINT64 addr_len;            // sizeof(addr).
    } send;
    struct
    {
        UINT32 layer;               // Handle layer.
        UINT32 priority;            // Handle priority.
        UINT64 flags;               // Handle flags.
    } initialize;
    struct
    {
        UINT64 flags;               // Filter flags.
    } startup;
    struct
    {
        UINT32 how;                 // CYDIVERT_SHUTDOWN_*
    } shutdown;
    struct
    {
        UINT32 param;               // CYDIVERT_PARAM_*
    } get_param;
    struct
    {
        UINT64 val;                 // Value pointer.
        UINT32 param;               // CYDIVERT_PARAM_*
    } set_param;
} CYDIVERT_IOCTL, *PCYDIVERT_IOCTL;

/*
 * CyDivert initialization structure.
 */
typedef struct
{
    UINT64 magic;                   // Magic number (in/out).
    UINT32 major;                   // Driver major version (in/out).
    UINT32 minor;                   // Driver minor version (in/out).
    UINT32 bits;                    // 32 or 64 (in/out).
    UINT32 reserved32[3];
    UINT64 reserved64[4];
} CYDIVERT_VERSION, *PCYDIVERT_VERSION;

/*
 * CyDivert filter structure.
 */
typedef struct
{
    UINT32 field:11;                // CYDIVERT_FILTER_FIELD_*
    UINT32 test:5;                  // CYDIVERT_FILTER_TEST_*
    UINT32 success:16;              // Success continuation.
    UINT32 failure:16;              // Fail continuation.
    UINT32 neg:1;                   // Argument negative?
    UINT32 reserved:15;
    UINT32 arg[4];                  // Argument.
} CYDIVERT_FILTER, *PCYDIVERT_FILTER;
#pragma pack(pop)

/*
 * IOCTL codes.
 */
#define IOCTL_CYDIVERT_INITIALIZE                                          \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x921, METHOD_OUT_DIRECT, FILE_READ_DATA |\
        FILE_WRITE_DATA)
#define IOCTL_CYDIVERT_STARTUP                                             \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x922, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_CYDIVERT_RECV                                                \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x923, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_CYDIVERT_SEND                                                \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x924, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_CYDIVERT_SET_PARAM                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x925, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)
#define IOCTL_CYDIVERT_GET_PARAM                                           \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x926, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_CYDIVERT_SHUTDOWN                                            \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x927, METHOD_IN_DIRECT, FILE_READ_DATA | \
        FILE_WRITE_DATA)

#endif      /* __CYDIVERT_DEVICE_H */
