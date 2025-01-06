/*
 * cydivert_shared.c
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

#define CYDIVERT_OBJECT_MAXLEN                                         \
    (8 + 4 + 2 + CYDIVERT_FILTER_MAXLEN * (1 + 1 + 2 + 2 + 4*7 + 3 + 3) + 1)

#define MAX(a, b)                               ((a) > (b)? (a): (b))

/*
 * Definitions to remove (some) external dependencies:
 */
#define BYTESWAP16(x)                   \
    ((((x) >> 8) & 0x00FFu) | (((x) << 8) & 0xFF00u))
#define BYTESWAP32(x)                   \
    ((((x) >> 24) & 0x000000FFu) | (((x) >> 8) & 0x0000FF00u) | \
     (((x) << 8) & 0x00FF0000u) | (((x) << 24) & 0xFF000000u))
#define BYTESWAP64(x)                   \
    ((((x) >> 56) & 0x00000000000000FFull) | \
     (((x) >> 40) & 0x000000000000FF00ull) | \
     (((x) >> 24) & 0x0000000000FF0000ull) | \
     (((x) >> 8)  & 0x00000000FF000000ull) | \
     (((x) << 8)  & 0x000000FF00000000ull) | \
     (((x) << 24) & 0x0000FF0000000000ull) | \
     (((x) << 40) & 0x00FF000000000000ull) | \
     (((x) << 56) & 0xFF00000000000000ull))
#define ntohs(x)                        BYTESWAP16(x)
#define htons(x)                        BYTESWAP16(x)
#define ntohl(x)                        BYTESWAP32(x)
#define htonl(x)                        BYTESWAP32(x)

/*
 * Layer flags shorthand.
 */
#define CYDIVERT_LAYER_FLAG_NETWORK            (1 << CYDIVERT_LAYER_NETWORK)
#define CYDIVERT_LAYER_FLAG_NETWORK_FORWARD    \
    (1 << CYDIVERT_LAYER_NETWORK_FORWARD)
#define CYDIVERT_LAYER_FLAG_FLOW               (1 << CYDIVERT_LAYER_FLOW)
#define CYDIVERT_LAYER_FLAG_SOCKET             (1 << CYDIVERT_LAYER_SOCKET)
#define CYDIVERT_LAYER_FLAG_REFLECT            (1 << CYDIVERT_LAYER_REFLECT)
#define LNMFSR          (CYDIVERT_LAYER_FLAG_NETWORK |                     \
                         CYDIVERT_LAYER_FLAG_NETWORK_FORWARD |             \
                         CYDIVERT_LAYER_FLAG_FLOW |                        \
                         CYDIVERT_LAYER_FLAG_SOCKET |                      \
                         CYDIVERT_LAYER_FLAG_REFLECT)
#define LNMFS_          (CYDIVERT_LAYER_FLAG_NETWORK |                     \
                         CYDIVERT_LAYER_FLAG_NETWORK_FORWARD |             \
                         CYDIVERT_LAYER_FLAG_FLOW |                        \
                         CYDIVERT_LAYER_FLAG_SOCKET)
#define L__F_R          (CYDIVERT_LAYER_FLAG_FLOW |                        \
                         CYDIVERT_LAYER_FLAG_REFLECT)
#define LN_FS_          (CYDIVERT_LAYER_FLAG_NETWORK |                     \
                         CYDIVERT_LAYER_FLAG_FLOW |                        \
                         CYDIVERT_LAYER_FLAG_SOCKET)
#define L__FS_          (CYDIVERT_LAYER_FLAG_FLOW |                        \
                         CYDIVERT_LAYER_FLAG_SOCKET)
#define L___SR          (CYDIVERT_LAYER_FLAG_SOCKET |                      \
                         CYDIVERT_LAYER_FLAG_REFLECT)
#define L__FSR          (CYDIVERT_LAYER_FLAG_FLOW |                        \
                         CYDIVERT_LAYER_FLAG_SOCKET |                      \
                         CYDIVERT_LAYER_FLAG_REFLECT)
#define LNM___          (CYDIVERT_LAYER_FLAG_NETWORK |                     \
                         CYDIVERT_LAYER_FLAG_NETWORK_FORWARD)
#define L__F__          CYDIVERT_LAYER_FLAG_FLOW
#define L___S_          CYDIVERT_LAYER_FLAG_SOCKET
#define L____R          CYDIVERT_LAYER_FLAG_REFLECT

#if defined(WIN32) && defined(_MSC_VER)
#pragma intrinsic(__emulu)
static UINT64 CyDivertMul64(UINT64 a, UINT64 b)
{
    UINT64 r = __emulu((UINT32)a, (UINT32)b);
    r += __emulu((UINT32)(a >> 32), (UINT32)b) << 32;
    r += __emulu((UINT32)a, (UINT32)(b >> 32)) << 32;
    return r;
}
#define CYDIVERT_MUL64(a, b)   CyDivertMul64(a, b)
#else       /* WIN32 */
#define CYDIVERT_MUL64(a, b)   ((a) * (b))
#endif      /* WIN32 */

/*
 * IPv6 fragment header.
 */
typedef struct
{
    UINT8 NextHdr;
    UINT8 Reserved;
    UINT16 FragOff0;
    UINT32 Id;
} CYDIVERT_IPV6FRAGHDR, *PCYDIVERT_IPV6FRAGHDR;
#define CYDIVERT_IPV6FRAGHDR_GET_FRAGOFF(hdr)                          \
    (((hdr)->FragOff0) & 0xF8FF)
#define CYDIVERT_IPV6FRAGHDR_GET_MF(hdr)                               \
    ((((hdr)->FragOff0) & 0x0100) != 0)

#include "cydivert_hash.c"

/*
 * IPv4/IPv6 pseudo headers.
 */
typedef struct
{
    UINT32 SrcAddr;
    UINT32 DstAddr;
    UINT8  Zero;
    UINT8  Protocol;
    UINT16 Length;
} CYDIVERT_PSEUDOHDR, *PCYDIVERT_PSEUDOHDR;

typedef struct
{
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
    UINT32 Length;
    UINT32 Zero:24;
    UINT32 NextHdr:8;
} CYDIVERT_PSEUDOV6HDR, *PCYDIVERT_PSEUDOV6HDR;

/*
 * Packet info.
 */
typedef struct
{
    UINT32 HeaderLength:17;
    UINT32 FragOff:13;
    UINT32 Fragment:1;
    UINT32 MF:1;
    UINT32 PayloadLength:16;
    UINT32 Protocol:8;
    UINT32 Truncated:1;
    UINT32 Extended:1;
    UINT32 Reserved1:6;
    PCYDIVERT_IPHDR IPHeader;
    PCYDIVERT_IPV6HDR IPv6Header;
    PCYDIVERT_ICMPHDR ICMPHeader;
    PCYDIVERT_ICMPV6HDR ICMPv6Header;
    PCYDIVERT_TCPHDR TCPHeader;
    PCYDIVERT_UDPHDR UDPHeader;
    UINT8 *Payload;
} CYDIVERT_PACKET, *PCYDIVERT_PACKET;

/*
 * Streams.
 */
typedef struct
{
    char *data;
    UINT pos;
    UINT max;
    BOOL overflow;
} CYDIVERT_STREAM, *PCYDIVERT_STREAM;

/*
 * Prototypes.
 */
static UINT16 CyDivertInitPseudoHeader(PCYDIVERT_IPHDR ip_header,
    PCYDIVERT_IPV6HDR ipv6_header, UINT8 protocol, UINT len,
    void *pseudo_header);
static UINT16 CyDivertCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len);

/*
 * Put a char into a stream.
 */
static void CyDivertPutChar(PCYDIVERT_STREAM stream, char c)
{
    if (stream->pos >= stream->max)
    {
        stream->overflow = TRUE;
        return;
    }
    stream->data[stream->pos] = c;
    stream->pos++;
}

/*
 * Put a string into a stream.
 */
static void CyDivertPutString(PCYDIVERT_STREAM stream, const char *str)
{
    while (*str)
    {
        CyDivertPutChar(stream, *str);
        str++;
    }
}

/*
 * Put a NUL character into a stream.
 */
static void CyDivertPutNul(PCYDIVERT_STREAM stream)
{
    if (stream->pos >= stream->max && stream->max > 0)
    {
        stream->data[stream->max-1] = '\0';     // Truncate
    }
    else
    {
        CyDivertPutChar(stream, '\0');
    }
}

/*
 * Encode a digit.
 */
static char CyDivertEncodeDigit(UINT8 dig, BOOL final)
{
    static const char cydivert_digits[64+1] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+=";
    return cydivert_digits[(dig & 0x1F) + (final? 32: 0)];
}

/*
 * Serialize a number.
 */
static void CyDivertSerializeNumber(PCYDIVERT_STREAM stream, UINT32 val)
{
    UINT32 mask = 0xC0000000;
    UINT dig = 6;
    UINT8 digit;
    BOOL final;

    while ((mask & val) == 0 && dig != 0)
    {
        mask = (dig == 6? 0x3E000000: mask >> 5);
        dig--;
    }
    while (TRUE)
    {
        final = (dig == 0);
        digit = (UINT8)((mask & val) >> (5 * dig));
        CyDivertPutChar(stream, CyDivertEncodeDigit(digit, final));
        if (final)
        {
            break;
        }
        mask = (dig == 6? 0x3E000000: mask >> 5);
        dig--;
    }
}

/*
 * Serialize a label.
 */
static void CyDivertSerializeLabel(PCYDIVERT_STREAM stream, UINT16 label)
{
    switch (label)
    {
        case CYDIVERT_FILTER_RESULT_ACCEPT:
            CyDivertPutChar(stream, 'A');
            break;
        case CYDIVERT_FILTER_RESULT_REJECT:
            CyDivertPutChar(stream, 'X');
            break;
        default:
            CyDivertPutChar(stream, 'L');
            CyDivertSerializeNumber(stream, label);
            break;
    }
}

/*
 * Serialize a test.
 */
static void CyDivertSerializeTest(PCYDIVERT_STREAM stream,
    const CYDIVERT_FILTER *filter)
{
    INT idx;
    UINT i;

    CyDivertPutChar(stream, '_');
    CyDivertSerializeNumber(stream, filter->field);
    CyDivertSerializeNumber(stream, filter->test);
    CyDivertSerializeNumber(stream, filter->neg);
    CyDivertSerializeNumber(stream, filter->arg[0]);
    switch (filter->field)
    {
        case CYDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case CYDIVERT_FILTER_FIELD_IPV6_DSTADDR:
        case CYDIVERT_FILTER_FIELD_LOCALADDR:
        case CYDIVERT_FILTER_FIELD_REMOTEADDR:
            for (i = 1; i < 4; i++)
            {
                CyDivertSerializeNumber(stream, filter->arg[i]);
            }
            break;
        case CYDIVERT_FILTER_FIELD_ENDPOINTID:
        case CYDIVERT_FILTER_FIELD_PARENTENDPOINTID:
        case CYDIVERT_FILTER_FIELD_TIMESTAMP:
            CyDivertSerializeNumber(stream, filter->arg[1]);
            break;
        case CYDIVERT_FILTER_FIELD_PACKET:
        case CYDIVERT_FILTER_FIELD_PACKET16:
        case CYDIVERT_FILTER_FIELD_PACKET32:
        case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD:
        case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
        case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32:
        case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD:
        case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
        case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32:
            idx = (INT)filter->arg[1];
            idx += UINT16_MAX;
            CyDivertSerializeNumber(stream, (UINT32)idx);
            break;
        default:
            break;
    }
    CyDivertSerializeLabel(stream, (UINT16)filter->success);
    CyDivertSerializeLabel(stream, (UINT16)filter->failure);
}

/*
 * Serialize a test.
 */
static void CyDivertSerializeFilter(PCYDIVERT_STREAM stream,
    const CYDIVERT_FILTER *filter, UINT8 length)
{
    UINT8 i;
    CyDivertPutString(stream, "@WinDiv_");     // Magic
    CyDivertSerializeNumber(stream, 0);        // Version
    CyDivertSerializeNumber(stream, length);   // Length
    for (i = 0; i < length; i++)
    {
        CyDivertSerializeTest(stream, filter + i);
    }
    CyDivertPutNul(stream);
}

/*
 * Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.
 */
static BOOL CyDivertHelperParsePacketEx(const VOID *pPacket, UINT packetLen,
    PCYDIVERT_PACKET pInfo)
{
    PCYDIVERT_IPHDR ip_header = NULL;
    PCYDIVERT_IPV6HDR ipv6_header = NULL;
    PCYDIVERT_ICMPHDR icmp_header = NULL;
    PCYDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PCYDIVERT_TCPHDR tcp_header = NULL;
    PCYDIVERT_UDPHDR udp_header = NULL;
    PCYDIVERT_IPV6FRAGHDR frag_header;
    UINT8 protocol = 0;
    UINT8 *data = NULL;
    UINT packet_len, total_len, header_len, data_len = 0, frag_off = 0;
    BOOL MF = FALSE, fragment = FALSE, is_ext_header;

    if (pPacket == NULL || packetLen < sizeof(CYDIVERT_IPHDR))
    {
        return FALSE;
    }
    data = (UINT8 *)pPacket;
    data_len = packetLen;

    ip_header = (PCYDIVERT_IPHDR)data;
    switch (ip_header->Version)
    {
        case 4:
            if (packetLen < sizeof(CYDIVERT_IPHDR) ||
                ip_header->HdrLength < 5)
            {
                return FALSE;
            }
            total_len  = (UINT)ntohs(ip_header->Length);
            protocol   = ip_header->Protocol;
            header_len = ip_header->HdrLength * sizeof(UINT32);
            if (total_len < header_len || packetLen < header_len)
            {
                return FALSE;
            }
            frag_off   = ntohs(CYDIVERT_IPHDR_GET_FRAGOFF(ip_header));
            MF         = (CYDIVERT_IPHDR_GET_MF(ip_header) != 0);
            fragment   = (MF || frag_off != 0);
            packet_len = (total_len < packetLen? total_len: packetLen);
            data      += header_len;
            data_len   = packet_len - header_len;
            break;

        case 6:
            ip_header   = NULL;
            ipv6_header = (PCYDIVERT_IPV6HDR)data;
            if (packetLen < sizeof(CYDIVERT_IPV6HDR))
            {
                return FALSE;
            }
            protocol   = ipv6_header->NextHdr;
            total_len  = (UINT)ntohs(ipv6_header->Length) +
                sizeof(CYDIVERT_IPV6HDR);
            packet_len = (total_len < packetLen? total_len: packetLen);
            data      += sizeof(CYDIVERT_IPV6HDR);
            data_len   = packet_len - sizeof(CYDIVERT_IPV6HDR);

            while (frag_off == 0 && data_len >= 2)
            {
                header_len = (UINT)data[1];
                is_ext_header = TRUE;
                switch (protocol)
                {
                    case IPPROTO_FRAGMENT:
                        header_len = 8;
                        if (fragment || data_len < header_len)
                        {
                            is_ext_header = FALSE;
                            break;
                        }
                        frag_header = (PCYDIVERT_IPV6FRAGHDR)data;
                        frag_off    = ntohs(
                            CYDIVERT_IPV6FRAGHDR_GET_FRAGOFF(frag_header));
                        MF          = CYDIVERT_IPV6FRAGHDR_GET_MF(frag_header);
                        fragment    = TRUE;
                        break;
                    case IPPROTO_AH:
                        header_len += 2;
                        header_len *= 4;
                        break;
                    case IPPROTO_HOPOPTS:
                    case IPPROTO_DSTOPTS:
                    case IPPROTO_ROUTING:
                    case IPPROTO_MH:
                        header_len++;
                        header_len *= 8;
                        break;
                    default:
                        is_ext_header = FALSE;
                        break;
                }
                if (!is_ext_header || data_len < header_len)
                {
                    break;
                }
                protocol  = data[0];
                data     += header_len;
                data_len -= header_len;
            }
            break;

        default:
            return FALSE;
    }

    if (frag_off != 0)
    {
        goto CyDivertHelperParsePacketExit;
    }
    switch (protocol)
    {
        case IPPROTO_TCP:
            tcp_header = (PCYDIVERT_TCPHDR)data;
            if (data_len < sizeof(CYDIVERT_TCPHDR) ||
                tcp_header->HdrLength < 5)
            {
                tcp_header = NULL;
                goto CyDivertHelperParsePacketExit;
            }
            header_len = tcp_header->HdrLength * sizeof(UINT32);
            header_len = (header_len > data_len? data_len: header_len);
            break;

        case IPPROTO_UDP:
            if (data_len < sizeof(CYDIVERT_UDPHDR))
            {
                goto CyDivertHelperParsePacketExit;
            }
            udp_header = (PCYDIVERT_UDPHDR)data;
            header_len = sizeof(CYDIVERT_UDPHDR);
            break;

        case IPPROTO_ICMP:
            if (ip_header == NULL ||
                data_len < sizeof(CYDIVERT_ICMPHDR))
            {
                goto CyDivertHelperParsePacketExit;
            }
            icmp_header = (PCYDIVERT_ICMPHDR)data;
            header_len  = sizeof(CYDIVERT_ICMPHDR);
            break;

        case IPPROTO_ICMPV6:
            if (ipv6_header == NULL ||
                data_len < sizeof(CYDIVERT_ICMPV6HDR))
            {
                goto CyDivertHelperParsePacketExit;
            }
            icmpv6_header = (PCYDIVERT_ICMPV6HDR)data;
            header_len    = sizeof(CYDIVERT_ICMPV6HDR);
            break;

        default:
            goto CyDivertHelperParsePacketExit;
    }
    data     += header_len;
    data_len -= header_len;

CyDivertHelperParsePacketExit:
    if (pInfo == NULL)
    {
        return TRUE;
    }
    data                 = (data_len == 0? NULL: data);
    pInfo->Protocol      = (UINT32)protocol;
    pInfo->Fragment      = (fragment? 1: 0);
    pInfo->MF            = (MF? 1: 0);
    pInfo->FragOff       = (UINT32)frag_off;
    pInfo->Truncated     = (total_len > packetLen? 1: 0);
    pInfo->Extended      = (total_len < packetLen? 1: 0);
    pInfo->Reserved1     = 0;
    pInfo->IPHeader      = ip_header;
    pInfo->IPv6Header    = ipv6_header;
    pInfo->ICMPHeader    = icmp_header;
    pInfo->ICMPv6Header  = icmpv6_header;
    pInfo->TCPHeader     = tcp_header;
    pInfo->UDPHeader     = udp_header;
    pInfo->Payload       = data;
    pInfo->HeaderLength  = (UINT32)(packet_len - data_len);
    pInfo->PayloadLength = (UINT32)data_len;
    return TRUE;
}

/*
 * Calculate IPv4/IPv6/ICMP/ICMPv6/TCP/UDP checksums.
 */
BOOL CyDivertHelperCalcChecksums(PVOID pPacket, UINT packetLen,
    CYDIVERT_ADDRESS *pAddr, UINT64 flags)
{
    UINT8 pseudo_header[
        MAX(sizeof(CYDIVERT_PSEUDOHDR), sizeof(CYDIVERT_PSEUDOV6HDR))];
    UINT16 pseudo_header_len;
    PCYDIVERT_IPHDR ip_header;
    PCYDIVERT_IPV6HDR ipv6_header;
    PCYDIVERT_ICMPHDR icmp_header;
    PCYDIVERT_ICMPV6HDR icmpv6_header;
    PCYDIVERT_TCPHDR tcp_header;
    PCYDIVERT_UDPHDR udp_header;
    CYDIVERT_PACKET info;
    UINT payload_len, checksum_len;
    BOOL truncated;

    if (!CyDivertHelperParsePacketEx(pPacket, packetLen, &info))
    {
        return FALSE;
    }

    ip_header = info.IPHeader;
    if (ip_header != NULL && !(flags & CYDIVERT_HELPER_NO_IP_CHECKSUM))
    {
        ip_header->Checksum = 0;
        ip_header->Checksum = CyDivertCalcChecksum(NULL, 0, ip_header,
            ip_header->HdrLength * sizeof(UINT32));
        if (pAddr != NULL)
        {
            pAddr->IPChecksum = 1;
        }
    }

    payload_len = info.PayloadLength;
    truncated   = (info.Truncated || info.MF || info.FragOff != 0);
 
    icmp_header = info.ICMPHeader;
    if (icmp_header != NULL)
    {
        if ((flags & CYDIVERT_HELPER_NO_ICMP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        icmp_header->Checksum = 0;
        icmp_header->Checksum = CyDivertCalcChecksum(NULL, 0,
            icmp_header, payload_len + sizeof(CYDIVERT_ICMPHDR));
        return TRUE;
    }

    icmpv6_header = info.ICMPv6Header;
    if (icmpv6_header != NULL)
    {
        if ((flags & CYDIVERT_HELPER_NO_ICMPV6_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        ipv6_header = info.IPv6Header;
        checksum_len = payload_len + sizeof(CYDIVERT_ICMPV6HDR);
        pseudo_header_len = CyDivertInitPseudoHeader(NULL, ipv6_header, 
            IPPROTO_ICMPV6, checksum_len, pseudo_header);
        icmpv6_header->Checksum = 0;
        icmpv6_header->Checksum = CyDivertCalcChecksum(pseudo_header,
            pseudo_header_len, icmpv6_header, checksum_len);
        return TRUE;
    }

    tcp_header = info.TCPHeader;
    if (tcp_header != NULL)
    {
        if ((flags & CYDIVERT_HELPER_NO_TCP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        checksum_len = payload_len + tcp_header->HdrLength * sizeof(UINT32);
        ipv6_header = info.IPv6Header;
        pseudo_header_len = CyDivertInitPseudoHeader(ip_header,
            ipv6_header, IPPROTO_TCP, checksum_len, pseudo_header);
        tcp_header->Checksum = 0;
        tcp_header->Checksum = CyDivertCalcChecksum(
            pseudo_header, pseudo_header_len, tcp_header, checksum_len);
        if (pAddr != NULL)
        {
            pAddr->TCPChecksum = 1;
        }
        return TRUE;
    }

    udp_header = info.UDPHeader;
    if (udp_header != NULL)
    {
        if ((flags & CYDIVERT_HELPER_NO_UDP_CHECKSUM) != 0)
        {
            return TRUE;
        }
        if (truncated)
        {
            return FALSE;
        }
        // Full UDP checksum
        checksum_len = payload_len + sizeof(CYDIVERT_UDPHDR);
        ipv6_header = info.IPv6Header;
        pseudo_header_len = CyDivertInitPseudoHeader(ip_header,
            ipv6_header, IPPROTO_UDP, checksum_len, pseudo_header);
        udp_header->Checksum = 0;
        udp_header->Checksum = CyDivertCalcChecksum(
            pseudo_header, pseudo_header_len, udp_header, checksum_len);
        if (udp_header->Checksum == 0)
        {
            udp_header->Checksum = 0xFFFF;
        }
        if (pAddr != NULL)
        {
            pAddr->UDPChecksum = 1;
        }
        return TRUE;
    }

    return TRUE;
}

/*
 * Initialize the IP/IPv6 pseudo header.
 */
static UINT16 CyDivertInitPseudoHeader(PCYDIVERT_IPHDR ip_header,
    PCYDIVERT_IPV6HDR ipv6_header, UINT8 protocol, UINT len,
    void *pseudo_header)
{
    if (ip_header != NULL)
    {
        PCYDIVERT_PSEUDOHDR pseudo_header_v4 =
            (PCYDIVERT_PSEUDOHDR)pseudo_header;
        pseudo_header_v4->SrcAddr  = ip_header->SrcAddr;
        pseudo_header_v4->DstAddr  = ip_header->DstAddr;
        pseudo_header_v4->Zero     = 0;
        pseudo_header_v4->Protocol = protocol;
        pseudo_header_v4->Length   = htons((UINT16)len);
        return sizeof(CYDIVERT_PSEUDOHDR);
    }
    else
    {
        PCYDIVERT_PSEUDOV6HDR pseudo_header_v6 =
            (PCYDIVERT_PSEUDOV6HDR)pseudo_header;
        memcpy(pseudo_header_v6->SrcAddr, ipv6_header->SrcAddr,
            sizeof(pseudo_header_v6->SrcAddr));
        memcpy(pseudo_header_v6->DstAddr, ipv6_header->DstAddr,
            sizeof(pseudo_header_v6->DstAddr));
        pseudo_header_v6->Length  = htonl((UINT32)len);
        pseudo_header_v6->NextHdr = protocol;
        pseudo_header_v6->Zero    = 0;
        return sizeof(CYDIVERT_PSEUDOV6HDR);
    }
}

/*
 * Generic checksum computation.
 */
static UINT16 CyDivertCalcChecksum(PVOID pseudo_header,
    UINT16 pseudo_header_len, PVOID data, UINT len)
{
    register const UINT16 *data16 = (const UINT16 *)pseudo_header;
    register size_t len16 = pseudo_header_len >> 1;
    register UINT32 sum = 0;
    size_t i;

    // Pseudo header:
    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }

    // Main data:
    data16 = (const UINT16 *)data;
    len16 = len >> 1;
    for (i = 0; i < len16; i++)
    {
        sum += (UINT32)data16[i];
    }

    if (len & 0x1)
    {
        const UINT8 *data8 = (const UINT8 *)data;
        sum += (UINT16)data8[len-1];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    sum = ~sum;
    return (UINT16)sum;
}

/*
 * Decrement the TTL.
 */
BOOL CyDivertHelperDecrementTTL(VOID *packet, UINT packetLen)
{
    PCYDIVERT_IPHDR ip_header;
    PCYDIVERT_IPV6HDR ipv6_header;

    if (packet == NULL || packetLen < sizeof(CYDIVERT_IPHDR))
    {
        return FALSE;
    }

    ip_header = (PCYDIVERT_IPHDR)packet;
    switch (ip_header->Version)
    {
        case 4:
            if (ip_header->TTL <= 1)
            {
                return FALSE;
            }
            ip_header->TTL--;
    
            // Incremental checksum update:
            if (ip_header->Checksum >= 0xFFFE)
            {
                ip_header->Checksum -= 0xFFFE;
            }
            else
            {
                ip_header->Checksum += 1;
            }
            return TRUE;

        case 6:
            if (packetLen < sizeof(CYDIVERT_IPV6HDR))
            {
                return FALSE;
            }
            ipv6_header = (PCYDIVERT_IPV6HDR)packet;
            if (ipv6_header->HopLimit <= 1)
            {
                return FALSE;
            }
            ipv6_header->HopLimit--;
            return TRUE;

        default:
            return FALSE;
    }
}

/*
 * Validate a CyDivert field for given layer.
 */
static BOOL CyDivertValidateField(CYDIVERT_LAYER layer, UINT32 field)
{
    static const UINT8 flags[] =
    {
        LNMFSR,     /* CYDIVERT_FILTER_FIELD_ZERO */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_INBOUND */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_OUTBOUND */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IFIDX */
        LNM___,     /* CYDIVERT_FILTER_FIELD_SUBIFIDX */
        LNMFS_,     /* CYDIVERT_FILTER_FIELD_IP */
        LNMFS_,     /* CYDIVERT_FILTER_FIELD_IPV6 */
        LNMFS_,     /* CYDIVERT_FILTER_FIELD_ICMP */
        LNMFS_,     /* CYDIVERT_FILTER_FIELD_TCP */
        LNMFS_,     /* CYDIVERT_FILTER_FIELD_UDP */
        LNMFS_,     /* CYDIVERT_FILTER_FIELD_ICMPV6 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_HDRLENGTH */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_TOS */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_LENGTH */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_ID */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_DF */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_MF */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_FRAGOFF */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_TTL */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_PROTOCOL */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_CHECKSUM */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_SRCADDR */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IP_DSTADDR */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IPV6_FLOWLABEL */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IPV6_LENGTH */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IPV6_NEXTHDR */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IPV6_HOPLIMIT */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IPV6_SRCADDR */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IPV6_DSTADDR */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMP_TYPE */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMP_CODE */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMP_CHECKSUM */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMP_BODY */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMPV6_TYPE */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMPV6_CODE */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM */
        LNM___,     /* CYDIVERT_FILTER_FIELD_ICMPV6_BODY */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_SRCPORT */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_DSTPORT */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_SEQNUM */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_ACKNUM */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_HDRLENGTH */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_URG */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_ACK */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_PSH */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_RST */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_SYN */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_FIN */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_WINDOW */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_CHECKSUM */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_URGPTR */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_SRCPORT */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_DSTPORT */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_LENGTH */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_CHECKSUM */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_LOOPBACK */
        LNM___,     /* CYDIVERT_FILTER_FIELD_IMPOSTOR */
        L__FSR,     /* CYDIVERT_FILTER_FIELD_PROCESSID */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_LOCALADDR */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_REMOTEADDR */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_LOCALPORT */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_REMOTEPORT */
        LN_FS_,     /* CYDIVERT_FILTER_FIELD_PROTOCOL */
        L__FS_,     /* CYDIVERT_FILTER_FIELD_ENDPOINTID */
        L__FS_,     /* CYDIVERT_FILTER_FIELD_PARENTENDPOINTID */
        L____R,     /* CYDIVERT_FILTER_FIELD_LAYER */
        L____R,     /* CYDIVERT_FILTER_FIELD_PRIORITY */
        LNMFSR,     /* CYDIVERT_FILTER_FIELD_EVENT */
        LNM___,     /* CYDIVERT_FILTER_FIELD_PACKET */
        LNM___,     /* CYDIVERT_FILTER_FIELD_PACKET16 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_PACKET32 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_PAYLOAD */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_PAYLOAD */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_LENGTH */
        LNMFSR,     /* CYDIVERT_FILTER_FIELD_TIMESTAMP */
        LNM___,     /* CYDIVERT_FILTER_FIELD_RANDOM8 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_RANDOM16 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_RANDOM32 */
        LNM___,     /* CYDIVERT_FILTER_FIELD_FRAGMENT */
    };

    if (field > CYDIVERT_FILTER_FIELD_MAX)
    {
        return FALSE;
    }
    return ((flags[field] & (1 << layer)) != 0);
}

/*
 * Big number comparison.
 */
static int CyDivertCompare128(BOOL neg_a, const UINT32 *a, BOOL neg_b,
    const UINT32 *b, BOOL big)
{
    int neg;
    if (neg_a && !neg_b)
    {
        return -1;
    }
    if (!neg_a && neg_b)
    {
        return 1;
    }
    neg = (neg_a? -1: 1);
    if (big)
    {
        if (a[3] < b[3])
        {
            return -neg;
        }
        if (a[3] > b[3])
        {
            return neg;
        }
        if (a[2] < b[2])
        {
            return -neg;
        }
        if (a[2] > b[2])
        {
            return neg;
        }
        if (a[1] < b[1])
        {
            return -neg;
        }
        if (a[1] > b[1])
        {
            return neg;
        }
    }
    if (a[0] < b[0])
    {
        return -neg;
    }
    if (a[0] > b[0])
    {
        return neg;
    }
    return 0;
}

/*
 * CyDivert filter execute function.
 */
static CYDIVERT_INLINE int CyDivertExecuteFilter(
    const CYDIVERT_FILTER *filter,
    CYDIVERT_LAYER layer,
    LONGLONG timestamp,
    CYDIVERT_EVENT event,
    BOOL ipv4,
    BOOL outbound,
    BOOL loopback,
    BOOL impostor,
    BOOL fragment,
    const CYDIVERT_DATA_NETWORK *network_data,
    const CYDIVERT_DATA_FLOW *flow_data,
    const CYDIVERT_DATA_SOCKET *socket_data,
    const CYDIVERT_DATA_REFLECT *reflect_data,
    const CYDIVERT_IPHDR *ip_header,
    const CYDIVERT_IPV6HDR *ipv6_header,
    const CYDIVERT_ICMPHDR *icmp_header,
    const CYDIVERT_ICMPV6HDR *icmpv6_header,
    const CYDIVERT_TCPHDR *tcp_header,
    const CYDIVERT_UDPHDR *udp_header,
    UINT8 protocol,
    const void *packet,
    UINT packet_len,
    UINT header_len,
    UINT payload_len)
{
    UINT64 random64 = 0;
    UINT16 ip, ttl;
    UINT8 data8;
    UINT16 data16;
    UINT32 data32;
    ULARGE_INTEGER val64;

    ip = 0;
    ttl = CYDIVERT_FILTER_MAXLEN+1;
    while (ttl-- != 0)
    {
        BOOL result = TRUE;
        BOOL big    = FALSE;
        BOOL neg    = FALSE;
        int cmp;
        UINT32 val[4];

        if (!CyDivertValidateField(layer, filter[ip].field))
        {
            return -1;
        }
        switch (filter[ip].field)
        {
            case CYDIVERT_FILTER_FIELD_RANDOM8:
            case CYDIVERT_FILTER_FIELD_RANDOM16:
            case CYDIVERT_FILTER_FIELD_RANDOM32:
                if (random64 == 0)
                {
                    random64 = CyDivertHashPacket((UINT64)timestamp,
                        ip_header, ipv6_header, icmp_header, icmpv6_header,
                        tcp_header, udp_header);
                    random64 |= 0xFF00000000000000ull;  // Make non-zero.
                }
                break;
            case CYDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case CYDIVERT_FILTER_FIELD_IP_TOS:
            case CYDIVERT_FILTER_FIELD_IP_LENGTH:
            case CYDIVERT_FILTER_FIELD_IP_ID:
            case CYDIVERT_FILTER_FIELD_IP_DF:
            case CYDIVERT_FILTER_FIELD_IP_MF:
            case CYDIVERT_FILTER_FIELD_IP_FRAGOFF:
            case CYDIVERT_FILTER_FIELD_IP_TTL:
            case CYDIVERT_FILTER_FIELD_IP_PROTOCOL:
            case CYDIVERT_FILTER_FIELD_IP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_IP_SRCADDR:
            case CYDIVERT_FILTER_FIELD_IP_DSTADDR:
                result = (ip_header != NULL);
                break;
            case CYDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case CYDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
            case CYDIVERT_FILTER_FIELD_IPV6_LENGTH:
            case CYDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case CYDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case CYDIVERT_FILTER_FIELD_IPV6_SRCADDR:
            case CYDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                result = (ipv6_header != NULL);
                break;
            case CYDIVERT_FILTER_FIELD_ICMP_TYPE:
            case CYDIVERT_FILTER_FIELD_ICMP_CODE:
            case CYDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_ICMP_BODY:
                result = (icmp_header != NULL);
                break;
            case CYDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case CYDIVERT_FILTER_FIELD_ICMPV6_CODE:
            case CYDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_ICMPV6_BODY:
                result = (icmpv6_header != NULL);
                break;
            case CYDIVERT_FILTER_FIELD_TCP_SRCPORT:
            case CYDIVERT_FILTER_FIELD_TCP_DSTPORT:
            case CYDIVERT_FILTER_FIELD_TCP_SEQNUM:
            case CYDIVERT_FILTER_FIELD_TCP_ACKNUM:
            case CYDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
            case CYDIVERT_FILTER_FIELD_TCP_URG:
            case CYDIVERT_FILTER_FIELD_TCP_ACK:
            case CYDIVERT_FILTER_FIELD_TCP_PSH:
            case CYDIVERT_FILTER_FIELD_TCP_RST:
            case CYDIVERT_FILTER_FIELD_TCP_SYN:
            case CYDIVERT_FILTER_FIELD_TCP_FIN:
            case CYDIVERT_FILTER_FIELD_TCP_WINDOW:
            case CYDIVERT_FILTER_FIELD_TCP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_TCP_URGPTR:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                result = (tcp_header != NULL);
                break;
            case CYDIVERT_FILTER_FIELD_UDP_SRCPORT:
            case CYDIVERT_FILTER_FIELD_UDP_DSTPORT:
            case CYDIVERT_FILTER_FIELD_UDP_LENGTH:
            case CYDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                result = (udp_header != NULL);
                break;
            default:
                break;
        }

        if (result)
        {
            switch (filter[ip].field)
            {
                case CYDIVERT_FILTER_FIELD_ZERO:
                    val[0] = 0;
                    break;
                case CYDIVERT_FILTER_FIELD_EVENT:
                    val[0] = (UINT32)event;
                    break;
                case CYDIVERT_FILTER_FIELD_LENGTH:
                    val[0] = (UINT32)packet_len;
                    break;
                case CYDIVERT_FILTER_FIELD_TIMESTAMP:
                    big = TRUE;
                    neg = (timestamp < 0);
                    val64.QuadPart = (UINT64)(neg? -timestamp: timestamp);
                    val[0] = (UINT32)val64.LowPart;
                    val[1] = (UINT32)val64.HighPart;
                    val[2] = val[3] = 0;
                    break;
                case CYDIVERT_FILTER_FIELD_RANDOM8:
                    val64.QuadPart = random64;
                    val[0] = ((UINT32)val64.HighPart >> 16) & 0xFF;
                    break; 
                case CYDIVERT_FILTER_FIELD_RANDOM16:
                    val64.QuadPart = random64;
                    val[0] = (UINT32)val64.HighPart & 0xFFFF;
                    break;
                case CYDIVERT_FILTER_FIELD_RANDOM32:
                    val[0] = (UINT32)random64;
                    break;
                case CYDIVERT_FILTER_FIELD_PACKET:
                    result = CYDIVERT_GET_DATA(packet, packet_len, 0,
                        packet_len, (INT)filter[ip].arg[1], &data8,
                        sizeof(data8));
                    val[0] = (UINT32)data8;
                    break;
                case CYDIVERT_FILTER_FIELD_PACKET16:
                    result = CYDIVERT_GET_DATA(packet, packet_len, 0,
                        packet_len, (INT)filter[ip].arg[1], &data16,
                        sizeof(data16));
                    val[0] = (UINT32)ntohs(data16);
                    break;
                case CYDIVERT_FILTER_FIELD_PACKET32:
                    result = CYDIVERT_GET_DATA(packet, packet_len, 0,
                        packet_len, (INT)filter[ip].arg[1], &data32,
                        sizeof(data32));
                    val[0] = ntohl(data32);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD:
                case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD:
                    result = CYDIVERT_GET_DATA(packet, packet_len,
                        header_len, header_len + payload_len,
                        (INT)filter[ip].arg[1], &data8, sizeof(data8));
                    val[0] = (UINT32)data8;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
                case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
                    result = CYDIVERT_GET_DATA(packet, packet_len,
                        header_len, header_len + payload_len,
                        (INT)filter[ip].arg[1], &data16, sizeof(data16));
                    val[0] = (UINT32)ntohs(data16);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32:
                case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32:
                    result = CYDIVERT_GET_DATA(packet, packet_len,
                        header_len, header_len + payload_len,
                        (INT)filter[ip].arg[1], &data32, sizeof(data32));
                    val[0] = ntohl(data32);
                    break;
                case CYDIVERT_FILTER_FIELD_INBOUND:
                    val[0] = (UINT32)!outbound;
                    break;
                case CYDIVERT_FILTER_FIELD_OUTBOUND:
                    val[0] = (UINT32)outbound;
                    break;
                case CYDIVERT_FILTER_FIELD_FRAGMENT:
                    val[0] = (UINT32)fragment;
                    break;
                case CYDIVERT_FILTER_FIELD_IFIDX:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                        case CYDIVERT_LAYER_NETWORK_FORWARD:
                            val[0] = network_data->IfIdx;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_SUBIFIDX:
                    val[0] = network_data->SubIfIdx;
                    break;
                case CYDIVERT_FILTER_FIELD_LOOPBACK:
                    val[0] = (UINT32)loopback;
                    break;
                case CYDIVERT_FILTER_FIELD_IMPOSTOR:
                    val[0] = (UINT32)impostor;
                    break;
                case CYDIVERT_FILTER_FIELD_IP:
                    val[0] = (UINT32)(ip_header != NULL);
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6:
                    val[0] = (UINT32)(ipv6_header != NULL);
                    break;
                case CYDIVERT_FILTER_FIELD_ICMP:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                        case CYDIVERT_LAYER_NETWORK_FORWARD:
                            val[0] = (UINT32)(icmp_header != NULL);
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = (UINT32)(ipv4 &&
                                socket_data->Protocol == IPPROTO_ICMP);
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = (UINT32)(ipv4 &&
                                flow_data->Protocol == IPPROTO_ICMP);
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_ICMPV6:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                        case CYDIVERT_LAYER_NETWORK_FORWARD:
                            val[0] = (UINT32)(icmpv6_header != NULL);
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = (UINT32)(!ipv4 &&
                                socket_data->Protocol == IPPROTO_ICMPV6);
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = (UINT32)(!ipv4 &&
                                flow_data->Protocol == IPPROTO_ICMPV6);
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_TCP:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                        case CYDIVERT_LAYER_NETWORK_FORWARD:
                            val[0] = (UINT32)(tcp_header != NULL);
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] =
                                (UINT32)(socket_data->Protocol == IPPROTO_TCP);
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] =
                                (UINT32)(flow_data->Protocol == IPPROTO_TCP);
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_UDP:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                        case CYDIVERT_LAYER_NETWORK_FORWARD:
                            val[0] = (UINT32)(udp_header != NULL);
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] =
                                (UINT32)(socket_data->Protocol == IPPROTO_UDP);
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] =
                                (UINT32)(flow_data->Protocol == IPPROTO_UDP);
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_IP_HDRLENGTH:
                    val[0] = (UINT32)ip_header->HdrLength;
                    break;
                case CYDIVERT_FILTER_FIELD_IP_TOS:
                    val[0] = (UINT32)ip_header->TOS;
                    break;
                case CYDIVERT_FILTER_FIELD_IP_LENGTH:
                    val[0] = (UINT32)ntohs(ip_header->Length);
                    break;
                case CYDIVERT_FILTER_FIELD_IP_ID:
                    val[0] = (UINT32)ntohs(ip_header->Id);
                    break;
                case CYDIVERT_FILTER_FIELD_IP_DF:
                    val[0] = (UINT32)CYDIVERT_IPHDR_GET_DF(ip_header);
                    break;
                case CYDIVERT_FILTER_FIELD_IP_MF:
                    val[0] = (UINT32)CYDIVERT_IPHDR_GET_MF(ip_header);
                    break;
                case CYDIVERT_FILTER_FIELD_IP_FRAGOFF:
                    val[0] = (UINT32)ntohs(
                        CYDIVERT_IPHDR_GET_FRAGOFF(ip_header));
                    break;
                case CYDIVERT_FILTER_FIELD_IP_TTL:
                    val[0] = (UINT32)ip_header->TTL;
                    break;
                case CYDIVERT_FILTER_FIELD_IP_PROTOCOL:
                    val[0] = (UINT32)ip_header->Protocol;
                    break;
                case CYDIVERT_FILTER_FIELD_IP_CHECKSUM:
                    val[0] = (UINT32)ntohs(ip_header->Checksum);
                    break;
                case CYDIVERT_FILTER_FIELD_IP_SRCADDR:
                    big = TRUE;
                    val[3] = val[2] = 0;
                    val[1] = 0x0000FFFF;
                    val[0] = (UINT32)ntohl(ip_header->SrcAddr);
                    break;
                case CYDIVERT_FILTER_FIELD_IP_DSTADDR:
                    big = TRUE;
                    val[3] = val[2] = 0;
                    val[1] = 0x0000FFFF;
                    val[0] = (UINT32)ntohl(ip_header->DstAddr);
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
                    val[0] =
                        (UINT32)CYDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header);
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                    val[0] = (UINT32)ntohl(
                        CYDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header));
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6_LENGTH:
                    val[0] = (UINT32)ntohs(ipv6_header->Length);
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
                    val[0] = (UINT32)ipv6_header->NextHdr;
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
                    val[0] = (UINT32)ipv6_header->HopLimit;
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6_SRCADDR:
                    big = TRUE;
                    val[3] = (UINT32)ntohl(ipv6_header->SrcAddr[0]);
                    val[2] = (UINT32)ntohl(ipv6_header->SrcAddr[1]);
                    val[1] = (UINT32)ntohl(ipv6_header->SrcAddr[2]);
                    val[0] = (UINT32)ntohl(ipv6_header->SrcAddr[3]);
                    break;
                case CYDIVERT_FILTER_FIELD_IPV6_DSTADDR:
                    big = TRUE;
                    val[3] = (UINT32)ntohl(ipv6_header->DstAddr[0]);
                    val[2] = (UINT32)ntohl(ipv6_header->DstAddr[1]);
                    val[1] = (UINT32)ntohl(ipv6_header->DstAddr[2]);
                    val[0] = (UINT32)ntohl(ipv6_header->DstAddr[3]);
                    break;
                case CYDIVERT_FILTER_FIELD_ICMP_TYPE:
                    val[0] = (UINT32)icmp_header->Type;
                    break;
                case CYDIVERT_FILTER_FIELD_ICMP_CODE:
                    val[0] = (UINT32)icmp_header->Code;
                    break;
                case CYDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
                    val[0] = (UINT32)ntohs(icmp_header->Checksum);
                    break;
                case CYDIVERT_FILTER_FIELD_ICMP_BODY:
                    val[0] = (UINT32)ntohl(icmp_header->Body);
                    break;
                case CYDIVERT_FILTER_FIELD_ICMPV6_TYPE:
                    val[0] = (UINT32)icmpv6_header->Type;
                    break;
                case CYDIVERT_FILTER_FIELD_ICMPV6_CODE:
                    val[0] = (UINT32)icmpv6_header->Code;
                    break;
                case CYDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
                    val[0] = (UINT32)ntohs(icmpv6_header->Checksum);
                    break;
                case CYDIVERT_FILTER_FIELD_ICMPV6_BODY:
                    val[0] = (UINT32)ntohl(icmpv6_header->Body);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_SRCPORT:
                    val[0] = (UINT32)ntohs(tcp_header->SrcPort);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_DSTPORT:
                    val[0] = (UINT32)ntohs(tcp_header->DstPort);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_SEQNUM:
                    val[0] = (UINT32)ntohl(tcp_header->SeqNum);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_ACKNUM:
                    val[0] = (UINT32)ntohl(tcp_header->AckNum);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                    val[0] = (UINT32)tcp_header->HdrLength;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_URG:
                    val[0] = (UINT32)tcp_header->Urg;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_ACK:
                    val[0] = (UINT32)tcp_header->Ack;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_PSH:
                    val[0] = (UINT32)tcp_header->Psh;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_RST:
                    val[0] = (UINT32)tcp_header->Rst;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_SYN:
                    val[0] = (UINT32)tcp_header->Syn;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_FIN:
                    val[0] = (UINT32)tcp_header->Fin;
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_WINDOW:
                    val[0] = (UINT32)ntohs(tcp_header->Window);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_CHECKSUM:
                    val[0] = (UINT32)ntohs(tcp_header->Checksum);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_URGPTR:
                    val[0] = (UINT32)ntohs(tcp_header->UrgPtr);
                    break;
                case CYDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
                    val[0] = (UINT32)payload_len;
                    break;
                case CYDIVERT_FILTER_FIELD_UDP_SRCPORT:
                    val[0] = (UINT32)ntohs(udp_header->SrcPort);
                    break;
                case CYDIVERT_FILTER_FIELD_UDP_DSTPORT:
                    val[0] = (UINT32)ntohs(udp_header->DstPort);
                    break;
                case CYDIVERT_FILTER_FIELD_UDP_LENGTH:
                    val[0] = (UINT32)ntohs(udp_header->Length);
                    break;
                case CYDIVERT_FILTER_FIELD_UDP_CHECKSUM:
                    val[0] = (UINT32)ntohs(udp_header->Checksum);
                    break;
                case CYDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
                    val[0] = (UINT32)payload_len;
                    break;
                case CYDIVERT_FILTER_FIELD_LOCALADDR:
                    big = TRUE;
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                            if (ip_header != NULL)
                            {
                                val[3] = val[2] = 0;
                                val[1] = 0x0000FFFF;
                                val[0] = (UINT32)ntohl(
                                    (outbound? ip_header->SrcAddr:
                                               ip_header->DstAddr));
                            }
                            else if (ipv6_header != NULL && outbound)
                            {
                                val[3] = (UINT32)ntohl(ipv6_header->SrcAddr[0]);
                                val[2] = (UINT32)ntohl(ipv6_header->SrcAddr[1]);
                                val[1] = (UINT32)ntohl(ipv6_header->SrcAddr[2]);
                                val[0] = (UINT32)ntohl(ipv6_header->SrcAddr[3]);
                            }
                            else if (ipv6_header != NULL)
                            {
                                val[3] = (UINT32)ntohl(ipv6_header->DstAddr[0]);
                                val[2] = (UINT32)ntohl(ipv6_header->DstAddr[1]);
                                val[1] = (UINT32)ntohl(ipv6_header->DstAddr[2]);
                                val[0] = (UINT32)ntohl(ipv6_header->DstAddr[3]);
                            }
                            else
                            {
                                val[3] = val[2] = val[1] = val[0] = 0;
                            }
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = flow_data->LocalAddr[0];
                            val[1] = flow_data->LocalAddr[1];
                            val[2] = flow_data->LocalAddr[2];
                            val[3] = flow_data->LocalAddr[3];
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = socket_data->LocalAddr[0];
                            val[1] = socket_data->LocalAddr[1];
                            val[2] = socket_data->LocalAddr[2];
                            val[3] = socket_data->LocalAddr[3];
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_REMOTEADDR:
                    big = TRUE;
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                            if (ip_header != NULL)
                            {
                                val[3] = val[2] = 0;
                                val[1] = 0x0000FFFF;
                                val[0] = (UINT32)ntohl(
                                    (!outbound? ip_header->SrcAddr:
                                                ip_header->DstAddr));
                            }
                            else if (ipv6_header != NULL && !outbound)
                            {
                                val[3] = (UINT32)ntohl(ipv6_header->SrcAddr[0]);
                                val[2] = (UINT32)ntohl(ipv6_header->SrcAddr[1]);
                                val[1] = (UINT32)ntohl(ipv6_header->SrcAddr[2]);
                                val[0] = (UINT32)ntohl(ipv6_header->SrcAddr[3]);
                            }
                            else if (ipv6_header != NULL)
                            {
                                val[3] = (UINT32)ntohl(ipv6_header->DstAddr[0]);
                                val[2] = (UINT32)ntohl(ipv6_header->DstAddr[1]);
                                val[1] = (UINT32)ntohl(ipv6_header->DstAddr[2]);
                                val[0] = (UINT32)ntohl(ipv6_header->DstAddr[3]);
                            }
                            else
                            {
                                val[3] = val[2] = val[1] = val[0] = 0;
                            }
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = flow_data->RemoteAddr[0];
                            val[1] = flow_data->RemoteAddr[1];
                            val[2] = flow_data->RemoteAddr[2];
                            val[3] = flow_data->RemoteAddr[3];
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = socket_data->RemoteAddr[0];
                            val[1] = socket_data->RemoteAddr[1];
                            val[2] = socket_data->RemoteAddr[2];
                            val[3] = socket_data->RemoteAddr[3];
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_LOCALPORT:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                            if (tcp_header != NULL)
                            {
                                val[0] = (UINT32)ntohs(
                                    (outbound? tcp_header->SrcPort:
                                               tcp_header->DstPort));
                            }
                            else if (udp_header != NULL)
                            {
                                val[0] = (UINT32)ntohs(
                                    (outbound? udp_header->SrcPort:
                                               udp_header->DstPort));
                            }
                            else if (icmp_header != NULL)
                            {
                                val[0] = (outbound?
                                    (UINT32)icmp_header->Type: 0);
                            }
                            else if (icmpv6_header != NULL)
                            {
                                val[0] = (outbound?
                                    (UINT32)icmpv6_header->Type: 0);
                            }
                            else
                            {
                                val[0] = 0;
                            }
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = (UINT32)flow_data->LocalPort;
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = (UINT32)socket_data->LocalPort;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_REMOTEPORT:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                            if (tcp_header != NULL)
                            {
                                val[0] = (UINT32)ntohs(
                                    (!outbound? tcp_header->SrcPort:
                                                tcp_header->DstPort));
                            }
                            else if (udp_header != NULL)
                            {
                                val[0] = (UINT32)ntohs(
                                    (!outbound? udp_header->SrcPort:
                                                udp_header->DstPort));
                            }
                            else if (icmp_header != NULL)
                            {
                                val[0] = (!outbound?
                                    (UINT32)icmp_header->Type: 0);
                            }
                            else if (icmpv6_header != NULL)
                            {
                                val[0] = (!outbound?
                                    (UINT32)icmpv6_header->Type: 0);
                            }
                            else
                            {
                                val[0] = 0;
                            }
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = (UINT32)flow_data->RemotePort;
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = (UINT32)socket_data->RemotePort;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_PROTOCOL:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_NETWORK:
                            val[0] = (UINT32)protocol;
                            break;
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = (UINT32)flow_data->Protocol;
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = (UINT32)socket_data->Protocol;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_PROCESSID:
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_FLOW:
                            val[0] = flow_data->ProcessId;
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val[0] = socket_data->ProcessId;
                            break;
                        case CYDIVERT_LAYER_REFLECT:
                            val[0] = reflect_data->ProcessId;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_ENDPOINTID:
                    big = TRUE;
                    val[2] = val[3] = 0;
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_FLOW:
                            val64.QuadPart = flow_data->EndpointId;
                            val[0] = (UINT32)val64.LowPart;
                            val[1] = (UINT32)val64.HighPart;
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val64.QuadPart = socket_data->EndpointId;
                            val[0] = (UINT32)val64.LowPart;
                            val[1] = (UINT32)val64.HighPart;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_PARENTENDPOINTID:
                    big = TRUE;
                    val[2] = val[3] = 0;
                    switch (layer)
                    {
                        case CYDIVERT_LAYER_FLOW:
                            val64.QuadPart = flow_data->ParentEndpointId;
                            val[0] = (UINT32)val64.LowPart;
                            val[1] = (UINT32)val64.HighPart;
                            break;
                        case CYDIVERT_LAYER_SOCKET:
                            val64.QuadPart = socket_data->ParentEndpointId;
                            val[0] = (UINT32)val64.LowPart;
                            val[1] = (UINT32)val64.HighPart;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case CYDIVERT_FILTER_FIELD_LAYER:
                    val[0] = (UINT32)reflect_data->Layer;
                    break;
                case CYDIVERT_FILTER_FIELD_PRIORITY:
                    neg = (reflect_data->Priority < 0);
                    val[0] = (UINT32)(neg? -reflect_data->Priority:
                        reflect_data->Priority);
                    break;
                default:
                    return -1;
            }
        }

        if (result)
        {
            cmp = CyDivertCompare128(neg, val,
                (filter[ip].neg? TRUE: FALSE), filter[ip].arg, big);
            switch (filter[ip].test)
            {
                case CYDIVERT_FILTER_TEST_EQ:
                    result = (cmp == 0);
                    break;
                case CYDIVERT_FILTER_TEST_NEQ:
                    result = (cmp != 0);
                    break;
                case CYDIVERT_FILTER_TEST_LT:
                    result = (cmp < 0);
                    break;
                case CYDIVERT_FILTER_TEST_LEQ:
                    result = (cmp <= 0);
                    break;
                case CYDIVERT_FILTER_TEST_GT:
                    result = (cmp > 0);
                    break;
                case CYDIVERT_FILTER_TEST_GEQ:
                    result = (cmp >= 0);
                    break;
                default:
                    return -1;
            }
        }

        ip = (UINT16)(result? filter[ip].success: filter[ip].failure);
        switch (ip)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
                return 1;
            case CYDIVERT_FILTER_RESULT_REJECT:
                return 0;
            default:
                break;
        }
    }

    return -1;
}

