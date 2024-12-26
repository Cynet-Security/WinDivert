/*
 * cydivert_helper.c
 * (C) 2021, all rights reserved,
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

/****************************************************************************/
/* CYDIVERT HELPER IMPLEMENTATION                                          */
/****************************************************************************/

/*
 * Protocols.
 */
#define IPPROTO_HOPOPTS     0
#define IPPROTO_ICMP        1
#define IPPROTO_TCP         6
#define IPPROTO_UDP         17
#define IPPROTO_ROUTING     43
#define IPPROTO_FRAGMENT    44
#define IPPROTO_AH          51
#define IPPROTO_ICMPV6      58
#define IPPROTO_NONE        59
#define IPPROTO_DSTOPTS     60

/*
 * Filter tokens.
 */
typedef enum
{
    TOKEN_ICMP,
    TOKEN_ICMP_BODY,
    TOKEN_ICMP_CHECKSUM,
    TOKEN_ICMP_CODE,
    TOKEN_ICMP_TYPE,
    TOKEN_ICMPV6,
    TOKEN_ICMPV6_BODY,
    TOKEN_ICMPV6_CHECKSUM,
    TOKEN_ICMPV6_CODE,
    TOKEN_ICMPV6_TYPE,
    TOKEN_IP,
    TOKEN_IP_CHECKSUM,
    TOKEN_IP_DF,
    TOKEN_IP_DST_ADDR,
    TOKEN_IP_FRAG_OFF,
    TOKEN_IP_HDR_LENGTH,
    TOKEN_IP_ID,
    TOKEN_IP_LENGTH,
    TOKEN_IP_MF,
    TOKEN_IP_PROTOCOL,
    TOKEN_IP_SRC_ADDR,
    TOKEN_IP_TOS,
    TOKEN_IP_TTL,
    TOKEN_IPV6,
    TOKEN_IPV6_DST_ADDR,
    TOKEN_IPV6_FLOW_LABEL,
    TOKEN_IPV6_HOP_LIMIT,
    TOKEN_IPV6_LENGTH,
    TOKEN_IPV6_NEXT_HDR,
    TOKEN_IPV6_SRC_ADDR,
    TOKEN_IPV6_TRAFFIC_CLASS,
    TOKEN_TCP,
    TOKEN_TCP_ACK,
    TOKEN_TCP_ACK_NUM,
    TOKEN_TCP_CHECKSUM,
    TOKEN_TCP_DST_PORT,
    TOKEN_TCP_FIN,
    TOKEN_TCP_HDR_LENGTH,
    TOKEN_TCP_PAYLOAD,
    TOKEN_TCP_PAYLOAD16,
    TOKEN_TCP_PAYLOAD32,
    TOKEN_TCP_PAYLOAD_LENGTH,
    TOKEN_TCP_PSH,
    TOKEN_TCP_RST,
    TOKEN_TCP_SEQ_NUM,
    TOKEN_TCP_SRC_PORT,
    TOKEN_TCP_SYN,
    TOKEN_TCP_URG,
    TOKEN_TCP_URG_PTR,
    TOKEN_TCP_WINDOW,
    TOKEN_UDP,
    TOKEN_UDP_CHECKSUM,
    TOKEN_UDP_DST_PORT,
    TOKEN_UDP_LENGTH,
    TOKEN_UDP_PAYLOAD,
    TOKEN_UDP_PAYLOAD16,
    TOKEN_UDP_PAYLOAD32,
    TOKEN_UDP_PAYLOAD_LENGTH,
    TOKEN_UDP_SRC_PORT,
    TOKEN_ZERO,
    TOKEN_EVENT,
    TOKEN_RANDOM8,
    TOKEN_RANDOM16,
    TOKEN_RANDOM32,
    TOKEN_PACKET,
    TOKEN_PACKET16,
    TOKEN_PACKET32,
    TOKEN_LENGTH,
    TOKEN_TIMESTAMP,
    TOKEN_TRUE,
    TOKEN_FALSE,
    TOKEN_INBOUND,
    TOKEN_OUTBOUND,
    TOKEN_FRAGMENT,
    TOKEN_IF_IDX,
    TOKEN_SUB_IF_IDX,
    TOKEN_LOOPBACK,
    TOKEN_IMPOSTOR,
    TOKEN_PROCESS_ID,
    TOKEN_LOCAL_ADDR,
    TOKEN_REMOTE_ADDR,
    TOKEN_LOCAL_PORT,
    TOKEN_REMOTE_PORT,
    TOKEN_PROTOCOL,
    TOKEN_ENDPOINT_ID,
    TOKEN_PARENT_ENDPOINT_ID,
    TOKEN_LAYER,
    TOKEN_PRIORITY,
    TOKEN_FLOW,
    TOKEN_SOCKET,
    TOKEN_NETWORK,
    TOKEN_NETWORK_FORWARD,
    TOKEN_REFLECT,
    TOKEN_EVENT_PACKET,
    TOKEN_EVENT_ESTABLISHED,
    TOKEN_EVENT_DELETED,
    TOKEN_EVENT_BIND,
    TOKEN_EVENT_CONNECT,
    TOKEN_EVENT_LISTEN,
    TOKEN_EVENT_ACCEPT,
    TOKEN_EVENT_OPEN,
    TOKEN_EVENT_CLOSE,
    TOKEN_MACRO_TRUE,
    TOKEN_MACRO_FALSE,
    TOKEN_MACRO_TCP,
    TOKEN_MACRO_UDP,
    TOKEN_MACRO_ICMP,
    TOKEN_MACRO_ICMPV6,
    TOKEN_OPEN,
    TOKEN_CLOSE,
    TOKEN_SQUARE_OPEN,
    TOKEN_SQUARE_CLOSE,
    TOKEN_MINUS,
    TOKEN_BYTES,
    TOKEN_EQ,
    TOKEN_NEQ,
    TOKEN_LT,
    TOKEN_LEQ,
    TOKEN_GT,
    TOKEN_GEQ,
    TOKEN_NOT,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_COLON,
    TOKEN_QUESTION,
    TOKEN_NUMBER,
    TOKEN_END,
} KIND;

typedef struct
{
    KIND kind;
    UINT pos;
    UINT32 val[4];
} TOKEN;
#define TOKEN_MAXLEN                            40

typedef struct
{
    char *name;
    KIND kind;
    UINT8 flags;
} TOKEN_INFO, *PTOKEN_INFO;

/*
 * Filter expressions.
 */
typedef struct EXPR EXPR;
typedef struct EXPR *PEXPR;
struct EXPR
{
    union
    {
        UINT32 val[4];
        PEXPR arg[3];
    };
    UINT8 kind;
    UINT8 count;
    BOOLEAN neg;
    UINT16 succ;
    UINT16 fail;
};

/*
 * Error handling.
 */
#undef ERROR
typedef UINT64 ERROR, *PERROR;

#define CYDIVERT_ERROR_NONE                    0
#define CYDIVERT_ERROR_NO_MEMORY               1
#define CYDIVERT_ERROR_TOO_DEEP                2
#define CYDIVERT_ERROR_TOO_LONG                3
#define CYDIVERT_ERROR_BAD_TOKEN               4
#define CYDIVERT_ERROR_BAD_TOKEN_FOR_LAYER     5
#define CYDIVERT_ERROR_UNEXPECTED_TOKEN        6
#define CYDIVERT_ERROR_INDEX_OOB               7
#define CYDIVERT_ERROR_OUTPUT_TOO_SHORT        8
#define CYDIVERT_ERROR_BAD_OBJECT              9
#define CYDIVERT_ERROR_ASSERTION_FAILED        10

#define CYDIVERT_MIN_POOL_SIZE                 12288
#define CYDIVERT_MAX_POOL_SIZE                 131072

#define MAKE_ERROR(code, pos)                   \
    (((ERROR)(code) << 32) | (ERROR)(pos));
#define GET_CODE(err)                           \
    ((UINT)((err) >> 32))
#define GET_POS(err)                            \
    ((UINT)((err) & 0xFFFFFFFF))
#undef IS_ERROR
#define IS_ERROR(err)                           \
    (GET_CODE(err) != CYDIVERT_ERROR_NONE)

/*
 * Prototypes.
 */
static UINT32 CyDivertKindToField(KIND kind);
static PEXPR CyDivertParseFilter(HANDLE pool, TOKEN *toks, UINT *i,
    INT depth, BOOL and, PERROR error);
static BOOL CyDivertCondExecFilter(PCYDIVERT_FILTER filter, UINT length,
    UINT8 field, UINT32 arg);
static int CyDivertCompare128(BOOL neg_a, const UINT32 *a, BOOL neg_b,
    const UINT32 *b, BOOL big);
static BOOL CyDivertDeserializeFilter(PCYDIVERT_STREAM stream,
    PCYDIVERT_FILTER filter, UINT *length);
static void CyDivertFormatExpr(PCYDIVERT_STREAM stream, PEXPR expr,
    CYDIVERT_LAYER layer, BOOL top_level, BOOL and);

/*
 * Parse an IPv4 address.
 */
BOOL CyDivertHelperParseIPv4Address(const char *str, UINT32 *addr_ptr)
{
    UINT32 addr = 0;
    UINT32 part, i;

    if (str == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (i = 0; i < 4; i++)
    {
        if (!CyDivertAToI(str, (char **)&str, &part, 1) || part > UINT8_MAX)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (i != 3 && *str++ != '.')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        addr |= part << (8*(3-i));
    }
    if (*str != '\0')
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (addr_ptr != NULL)
    {
        *addr_ptr = addr;
    }
    return TRUE;
}

/*
 * Parse an IPv6 address.
 */
BOOL CyDivertHelperParseIPv6Address(const char *str, UINT32 *addr_ptr)
{
    UINT16 laddr[8] = {0};
    UINT16 raddr[8] = {0};
    UINT32 addr[4];
    BOOL left = TRUE, ipv4 = FALSE;
    UINT32 ipv4_addr;
    UINT i, j, k, l, part;
    char part_str[5];

    j = 0;
    if (*str == ':')
    {
        str++;
        if (*str != ':')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        left = FALSE;
        str++;
        if (*str == '\0')
        {
            goto CyDivertHelperParseIPv6AddressSuccess;
        }
    }

    for (i = 0, k = 0; k < 8; k++)
    {
        if (*str == ':')
        {
            if (!left)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            left = FALSE;
            str++;
            if (*str == '\0')
            {
                break;
            }
        }

        if (i < 6 && CyDivertHelperParseIPv4Address(str, &ipv4_addr))
        {
            // Tail is IPv4 address:
            ipv4 = TRUE;
            j += 2;
            goto CyDivertHelperParseIPv6AddressSuccess;
        }
        for (l = 0; l < 4 && CyDivertIsXDigit(*str); l++)
        {
            part_str[l] = *str;
            str++;
        }
        if (l == 0)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        part_str[l] = '\0';
        if (*str != ':' && *str != '\0')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        CyDivertAToX(part_str, NULL, &part, /*size=*/1, /*prefix=*/FALSE);
        if (left)
        {
            laddr[i++] = (UINT16)part;
        }
        else
        {
            raddr[j++] = (UINT16)part;
        }
        if (*str == '\0')
        {
            if (!left || k == 7)
            {
                break;
            }
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        str++;
    }

CyDivertHelperParseIPv6AddressSuccess:

    if (!ipv4 && addr_ptr == NULL)
    {
        return TRUE;
    }
    for (i = 0; i < 4; i++)
    {
        k = 2 * i + j;
        l = k + 1;
        k = (k >= 8? k - 8: k);
        l = (l >= 8? l - 8: l);
        addr[3 - i] =
            (UINT32)laddr[2 * i + 1] |
            (UINT32)laddr[2 * i] << 16 |
            (UINT32)raddr[l] |
            (UINT32)raddr[k] << 16;
    }
    if (ipv4)
    {
        // Validate IPv4 address
        if (addr[3] != 0 || addr[2] != 0 || addr[0] != 0 ||
                (addr[1] != 0x0000FFFF && addr[1] != 0))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        addr[0] = ipv4_addr;
    }
    if (addr_ptr != NULL)
    {
        memcpy(addr_ptr, addr, sizeof(addr));
    }
    return TRUE;
}

/*
 * Lookup a token.
 */
static PTOKEN_INFO CyDivertTokenLookup(PTOKEN_INFO token_info,
    size_t token_info_len, const char *name)
{
    int lo = 0, hi = (int)token_info_len-1, mid;
    int cmp;
    while (hi >= lo)
    {
        mid = (lo + hi) / 2;
        cmp = CyDivertStrCmp(token_info[mid].name, name);
        if (cmp < 0)
        {
            lo = mid+1;
        }
        else if (cmp > 0)
        {
            hi = mid-1;
        }
        else
        {
            return &token_info[mid];
        }
    }
    return NULL;
}

/*
 * Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.
 */
BOOL CyDivertHelperParsePacket(const VOID *pPacket, UINT packetLen,
    PCYDIVERT_IPHDR *ppIPHeader, PCYDIVERT_IPV6HDR *ppIPv6Header,
    UINT8 *pProtocol, PCYDIVERT_ICMPHDR *ppICMPHeader,
    PCYDIVERT_ICMPV6HDR *ppICMPv6Header, PCYDIVERT_TCPHDR *ppTCPHeader,
    PCYDIVERT_UDPHDR *ppUDPHeader, PVOID *ppData, UINT *pDataLen,
    PVOID *ppNext, UINT *pNextLen)
{
    CYDIVERT_PACKET info;
    if (!CyDivertHelperParsePacketEx(pPacket, packetLen, &info))
    {
        return FALSE;
    }
    if (info.Truncated)
    {
        return FALSE;
    }

    if (pProtocol != NULL)
    {
        *pProtocol = info.Protocol;
    }
    if (ppIPHeader != NULL)
    {
        *ppIPHeader = info.IPHeader;
    }
    if (ppIPv6Header != NULL)
    {
        *ppIPv6Header = info.IPv6Header;
    }
    if (ppICMPHeader != NULL)
    {
        *ppICMPHeader = info.ICMPHeader;
    }
    if (ppICMPv6Header != NULL)
    {
        *ppICMPv6Header = info.ICMPv6Header;
    }
    if (ppTCPHeader != NULL)
    {
        *ppTCPHeader = info.TCPHeader;
    }
    if (ppUDPHeader != NULL)
    {
        *ppUDPHeader = info.UDPHeader;
    }
    if (ppData != NULL)
    {
        *ppData = info.Payload;
    }
    if (pDataLen != NULL)
    {
        *pDataLen = info.PayloadLength;
    }
    if (ppNext != NULL)
    {
        *ppNext = (info.Extended? (PVOID)((UINT8 *)pPacket +
            (info.HeaderLength + info.PayloadLength)): NULL);
    }
    if (pNextLen != NULL)
    {
        *pNextLen = (info.Extended?
            packetLen - (info.HeaderLength + info.PayloadLength): 0);
    }

    return TRUE;
}

/*
 * Expand a "macro" value.
 */
static BOOL CyDivertExpandMacro(KIND kind, CYDIVERT_LAYER layer, UINT32 *val)
{
    switch (kind)
    {
        case TOKEN_NETWORK:
            *val = CYDIVERT_LAYER_NETWORK;
            return TRUE;
        case TOKEN_NETWORK_FORWARD:
            *val = CYDIVERT_LAYER_NETWORK_FORWARD;
            return TRUE;
        case TOKEN_FLOW:
            *val = CYDIVERT_LAYER_FLOW;
            return TRUE;
        case TOKEN_SOCKET:
            *val = CYDIVERT_LAYER_SOCKET;
            return TRUE;
        case TOKEN_REFLECT:
            *val = CYDIVERT_LAYER_REFLECT;
            return TRUE;
        case TOKEN_EVENT_PACKET:
            *val = CYDIVERT_EVENT_NETWORK_PACKET;
            return (layer == CYDIVERT_LAYER_NETWORK ||
                    layer == CYDIVERT_LAYER_NETWORK_FORWARD);
        case TOKEN_EVENT_ESTABLISHED:
            *val = CYDIVERT_EVENT_FLOW_ESTABLISHED;
            return (layer == CYDIVERT_LAYER_FLOW);
        case TOKEN_EVENT_DELETED:
            *val = CYDIVERT_EVENT_FLOW_DELETED;
            return (layer == CYDIVERT_LAYER_FLOW);
        case TOKEN_EVENT_BIND:
            *val = CYDIVERT_EVENT_SOCKET_BIND;
            return (layer == CYDIVERT_LAYER_SOCKET);
        case TOKEN_EVENT_CONNECT:
            *val = CYDIVERT_EVENT_SOCKET_CONNECT;
            return (layer == CYDIVERT_LAYER_SOCKET);
        case TOKEN_EVENT_LISTEN:
            *val = CYDIVERT_EVENT_SOCKET_LISTEN;
            return (layer == CYDIVERT_LAYER_SOCKET);
        case TOKEN_EVENT_ACCEPT:
            *val = CYDIVERT_EVENT_SOCKET_ACCEPT;
            return (layer == CYDIVERT_LAYER_SOCKET);
        case TOKEN_EVENT_OPEN:
            *val = CYDIVERT_EVENT_REFLECT_OPEN;
            return (layer == CYDIVERT_LAYER_REFLECT);
        case TOKEN_EVENT_CLOSE:
            switch (layer)
            {
                case CYDIVERT_LAYER_SOCKET:
                    *val = CYDIVERT_EVENT_SOCKET_CLOSE;
                    return TRUE;
                case CYDIVERT_LAYER_REFLECT:
                    *val = CYDIVERT_EVENT_REFLECT_CLOSE;
                    return TRUE;
                default:
                    return FALSE;
            }
        case TOKEN_MACRO_TRUE:
            *val = 1;
            return TRUE;
        case TOKEN_MACRO_FALSE:
            *val = 0;
            return TRUE;
        case TOKEN_MACRO_TCP:
            *val = IPPROTO_TCP;
            return TRUE;
        case TOKEN_MACRO_UDP:
            *val = IPPROTO_UDP;
            return TRUE;
        case TOKEN_MACRO_ICMP:
            *val = IPPROTO_ICMP;
            return TRUE;
        case TOKEN_MACRO_ICMPV6:
            *val = IPPROTO_ICMPV6;
            return TRUE;
        default:
            return FALSE;
    }
}

/*
 * Tokenize the given filter string.
 */
static ERROR CyDivertTokenizeFilter(const char *filter, CYDIVERT_LAYER layer,
    TOKEN *tokens, UINT tokensmax)
{
    static const TOKEN_INFO token_info[] =
    {
        {"ACCEPT",              TOKEN_EVENT_ACCEPT      },
        {"BIND",                TOKEN_EVENT_BIND        },
        {"CLOSE",               TOKEN_EVENT_CLOSE       },
        {"CONNECT",             TOKEN_EVENT_CONNECT     },
        {"DELETED",             TOKEN_EVENT_DELETED     },
        {"ESTABLISHED",         TOKEN_EVENT_ESTABLISHED },
        {"FALSE",               TOKEN_MACRO_FALSE       },
        {"FLOW",                TOKEN_FLOW              },
        {"ICMP",                TOKEN_MACRO_ICMP        },
        {"ICMPV6",              TOKEN_MACRO_ICMPV6      },
        {"LISTEN",              TOKEN_EVENT_LISTEN      },
        {"NETWORK",             TOKEN_NETWORK           },
        {"NETWORK_FORWARD",     TOKEN_NETWORK_FORWARD   },
        {"OPEN",                TOKEN_EVENT_OPEN        },
        {"PACKET",              TOKEN_EVENT_PACKET      },
        {"REFLECT",             TOKEN_REFLECT           },
        {"SOCKET",              TOKEN_SOCKET            },
        {"TCP",                 TOKEN_MACRO_TCP         },
        {"TRUE",                TOKEN_MACRO_TRUE        },
        {"UDP",                 TOKEN_MACRO_UDP         },
        {"and",                 TOKEN_AND               },
        {"endpointId",          TOKEN_ENDPOINT_ID       },
        {"event",               TOKEN_EVENT             },
        {"false",               TOKEN_FALSE             },
        {"fragment",            TOKEN_FRAGMENT          },
        {"icmp",                TOKEN_ICMP              },
        {"icmp.Body",           TOKEN_ICMP_BODY         },
        {"icmp.Checksum",       TOKEN_ICMP_CHECKSUM     },
        {"icmp.Code",           TOKEN_ICMP_CODE         },
        {"icmp.Type",           TOKEN_ICMP_TYPE         },
        {"icmpv6",              TOKEN_ICMPV6            },
        {"icmpv6.Body",         TOKEN_ICMPV6_BODY       },
        {"icmpv6.Checksum",     TOKEN_ICMPV6_CHECKSUM   },
        {"icmpv6.Code",         TOKEN_ICMPV6_CODE       },
        {"icmpv6.Type",         TOKEN_ICMPV6_TYPE       },
        {"ifIdx",               TOKEN_IF_IDX            },
        {"impostor",            TOKEN_IMPOSTOR          },
        {"inbound",             TOKEN_INBOUND           },
        {"ip",                  TOKEN_IP                },
        {"ip.Checksum",         TOKEN_IP_CHECKSUM       },
        {"ip.DF",               TOKEN_IP_DF             },
        {"ip.DstAddr",          TOKEN_IP_DST_ADDR       },
        {"ip.FragOff",          TOKEN_IP_FRAG_OFF       },
        {"ip.HdrLength",        TOKEN_IP_HDR_LENGTH     },
        {"ip.Id",               TOKEN_IP_ID             },
        {"ip.Length",           TOKEN_IP_LENGTH         },
        {"ip.MF",               TOKEN_IP_MF             },
        {"ip.Protocol",         TOKEN_IP_PROTOCOL       },
        {"ip.SrcAddr",          TOKEN_IP_SRC_ADDR       },
        {"ip.TOS",              TOKEN_IP_TOS            },
        {"ip.TTL",              TOKEN_IP_TTL            },
        {"ipv6",                TOKEN_IPV6              },
        {"ipv6.DstAddr",        TOKEN_IPV6_DST_ADDR     },
        {"ipv6.FlowLabel",      TOKEN_IPV6_FLOW_LABEL   },
        {"ipv6.HopLimit",       TOKEN_IPV6_HOP_LIMIT    },
        {"ipv6.Length",         TOKEN_IPV6_LENGTH       },
        {"ipv6.NextHdr",        TOKEN_IPV6_NEXT_HDR     },
        {"ipv6.SrcAddr",        TOKEN_IPV6_SRC_ADDR     },
        {"ipv6.TrafficClass",   TOKEN_IPV6_TRAFFIC_CLASS},
        {"layer",               TOKEN_LAYER             },
        {"length",              TOKEN_LENGTH            },
        {"localAddr",           TOKEN_LOCAL_ADDR        },
        {"localPort",           TOKEN_LOCAL_PORT        },
        {"loopback",            TOKEN_LOOPBACK          },
        {"not",                 TOKEN_NOT               },
        {"or",                  TOKEN_OR                },
        {"outbound",            TOKEN_OUTBOUND          },
        {"packet",              TOKEN_PACKET            },
        {"packet16",            TOKEN_PACKET16          },
        {"packet32",            TOKEN_PACKET32          },
        {"parentEndpointId",    TOKEN_PARENT_ENDPOINT_ID},
        {"priority",            TOKEN_PRIORITY          },
        {"processId",           TOKEN_PROCESS_ID        },
        {"protocol",            TOKEN_PROTOCOL          },
        {"random16",            TOKEN_RANDOM16          },
        {"random32",            TOKEN_RANDOM32          },
        {"random8",             TOKEN_RANDOM8           },
        {"remoteAddr",          TOKEN_REMOTE_ADDR       },
        {"remotePort",          TOKEN_REMOTE_PORT       },
        {"subIfIdx",            TOKEN_SUB_IF_IDX        },
        {"tcp",                 TOKEN_TCP               },
        {"tcp.Ack",             TOKEN_TCP_ACK           },
        {"tcp.AckNum",          TOKEN_TCP_ACK_NUM       },
        {"tcp.Checksum",        TOKEN_TCP_CHECKSUM      },
        {"tcp.DstPort",         TOKEN_TCP_DST_PORT      },
        {"tcp.Fin",             TOKEN_TCP_FIN           },
        {"tcp.HdrLength",       TOKEN_TCP_HDR_LENGTH    },
        {"tcp.Payload",         TOKEN_TCP_PAYLOAD       },
        {"tcp.Payload16",       TOKEN_TCP_PAYLOAD16     },
        {"tcp.Payload32",       TOKEN_TCP_PAYLOAD32     },
        {"tcp.PayloadLength",   TOKEN_TCP_PAYLOAD_LENGTH},
        {"tcp.Psh",             TOKEN_TCP_PSH           },
        {"tcp.Rst",             TOKEN_TCP_RST           },
        {"tcp.SeqNum",          TOKEN_TCP_SEQ_NUM       },
        {"tcp.SrcPort",         TOKEN_TCP_SRC_PORT      },
        {"tcp.Syn",             TOKEN_TCP_SYN           },
        {"tcp.Urg",             TOKEN_TCP_URG           },
        {"tcp.UrgPtr",          TOKEN_TCP_URG_PTR       },
        {"tcp.Window",          TOKEN_TCP_WINDOW        },
        {"timestamp",           TOKEN_TIMESTAMP         },
        {"true",                TOKEN_TRUE              },
        {"udp",                 TOKEN_UDP               },
        {"udp.Checksum",        TOKEN_UDP_CHECKSUM      },
        {"udp.DstPort",         TOKEN_UDP_DST_PORT      },
        {"udp.Length",          TOKEN_UDP_LENGTH        },
        {"udp.Payload",         TOKEN_UDP_PAYLOAD       },
        {"udp.Payload16",       TOKEN_UDP_PAYLOAD16     },
        {"udp.Payload32",       TOKEN_UDP_PAYLOAD32     },
        {"udp.PayloadLength",   TOKEN_UDP_PAYLOAD_LENGTH},
        {"udp.SrcPort",         TOKEN_UDP_SRC_PORT      },
        {"zero",                TOKEN_ZERO              },
    };
    TOKEN_INFO *result;
    char c;
    char token[TOKEN_MAXLEN];
    UINT32 field;
    UINT i = 0, j;
    UINT tp = 0;

    while (TRUE)
    {
        if (tp >= tokensmax-1)
        {
            return MAKE_ERROR(CYDIVERT_ERROR_TOO_LONG, i);
        }
        memset(tokens[tp].val, 0, sizeof(tokens[tp].val));
        while (CyDivertIsSpace(filter[i]))
        {
            i++;
        }
        tokens[tp].pos = i;
        c = filter[i++];
        switch (c)
        {
            case '\0':
                tokens[tp].kind = TOKEN_END;
                return MAKE_ERROR(CYDIVERT_ERROR_NONE, 0);
            case '(':
                tokens[tp++].kind = TOKEN_OPEN;
                continue;
            case ')':
                tokens[tp++].kind = TOKEN_CLOSE;
                continue;
            case '[':
                tokens[tp++].kind = TOKEN_SQUARE_OPEN;
                continue;
            case ']':
                tokens[tp++].kind = TOKEN_SQUARE_CLOSE;
                continue;
            case '-':
                tokens[tp++].kind = TOKEN_MINUS;
                continue;
            case '!':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = TOKEN_NEQ;
                }
                else
                {
                    tokens[tp++].kind = TOKEN_NOT;
                }
                continue;
            case '=':
                if (filter[i] == '=')
                {
                    i++;
                }
                tokens[tp++].kind = TOKEN_EQ;
                continue;
            case '<':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = TOKEN_LEQ;
                }
                else
                {
                    tokens[tp++].kind = TOKEN_LT;
                }
                continue;
            case '>':
                if (filter[i] == '=')
                {
                    i++;
                    tokens[tp++].kind = TOKEN_GEQ;
                }
                else
                {
                    tokens[tp++].kind = TOKEN_GT;
                }
                continue;
            case ':':
                if (filter[i] == ':')
                {
                    break;      // Probably ipv6 address, e.g. ::1.
                }
                tokens[tp++].kind = TOKEN_COLON;
                continue;
            case '?':
                tokens[tp++].kind = TOKEN_QUESTION;
                continue;
            case '&':
                if (filter[i++] != '&')
                {
                    return MAKE_ERROR(CYDIVERT_ERROR_BAD_TOKEN, i-1);
                }
                tokens[tp++].kind = TOKEN_AND;
                continue;
            case '|':
                if (filter[i++] != '|')
                {
                    return MAKE_ERROR(CYDIVERT_ERROR_BAD_TOKEN, i-1);
                }
                tokens[tp++].kind = TOKEN_OR;
                continue;
            default:
                break;
        }
        token[0] = c;
        if (CyDivertIsAlNum(c) || c == '.' || c == ':' || c == '_')
        {
            UINT32 num[4];
            char *end;
            for (j = 1; j < TOKEN_MAXLEN && (CyDivertIsAlNum(filter[i]) ||
                    filter[i] == '.' || filter[i] == ':' || filter[i] == '_');
                    j++, i++)
            {
                token[j] = filter[i];
            }
            if (j >= TOKEN_MAXLEN)
            {
                return MAKE_ERROR(CYDIVERT_ERROR_BAD_TOKEN, i-j);
            }
            token[j] = '\0';

            // Handle trailing colons:
            if (j >= 1 && token[j-1] == ':')
            {
                if (j == 1 || token[j-2] != ':')
                {
                    token[j-1] = '\0';
                    i--;
                }
            }

            // Check for symbol:
            result = CyDivertTokenLookup((PTOKEN_INFO)token_info,
                sizeof(token_info) / sizeof(TOKEN_INFO), token);
            if (result != NULL)
            {
                field = CyDivertKindToField(result->kind);
                if (field <= CYDIVERT_FILTER_FIELD_MAX &&
                        !CyDivertValidateField(layer, field))
                {
                    return MAKE_ERROR(CYDIVERT_ERROR_BAD_TOKEN_FOR_LAYER,
                        i-j);
                }
                if (CyDivertExpandMacro(result->kind, layer,
                        &tokens[tp].val[0]))
                {
                    tokens[tp].kind = TOKEN_NUMBER;
                }
                else
                {
                    tokens[tp].kind = result->kind;
                }
                tp++;
                continue;
            }

            // Check for 'b':
            if (token[0] == 'b' && token[1] == '\0')
            {
                tokens[tp].kind = TOKEN_BYTES;
                continue;
            }

            // Check for base 10 number:
            if (CyDivertAToI(token, &end, num, sizeof(num)/sizeof(num[0])))
            {
                BOOL b = (*end == 'b' && *(end+1) == '\0');
                if (*end == '\0' || b)
                {
                    tokens[tp].kind = TOKEN_NUMBER;
                    memcpy(tokens[tp].val, num, sizeof(tokens[tp].val));
                    tp++;
                    if (b)
                    {
                        memset(tokens[tp].val, 0, sizeof(tokens[tp].val));
                        tokens[tp].kind = TOKEN_BYTES;
                        tp++;
                    }
                    continue;
                }
            }

            // Check for base 16 number:
            if (token[0] == '0' && token[1] == 'x' &&
                CyDivertAToX(token, &end, num, sizeof(num)/sizeof(num[0]),
                    /*prefix=*/TRUE) &&
                *end == '\0')
            {
                tokens[tp].kind = TOKEN_NUMBER;
                memcpy(tokens[tp].val, num, sizeof(tokens[tp].val));
                tp++;
                continue;
            }

            // Check for IPv4 address:
            if (CyDivertHelperParseIPv4Address(token, tokens[tp].val))
            {
                tokens[tp].val[1] = 0x0000FFFF;
                tokens[tp].kind = TOKEN_NUMBER;
                tp++;
                continue;
            }

            // Check for IPv6 address:
            SetLastError(0);
            if (CyDivertHelperParseIPv6Address(token, tokens[tp].val))
            {
                tokens[tp].kind = TOKEN_NUMBER;
                tp++;
                continue;
            }

            return MAKE_ERROR(CYDIVERT_ERROR_BAD_TOKEN, i-j);
        }
        else
        {
            return MAKE_ERROR(CYDIVERT_ERROR_BAD_TOKEN, i);
        }
    }
}

/*
 * Construct a variable/field.
 */
static PEXPR CyDivertMakeVar(KIND kind, PERROR error)
{
    // NOTE: must be in order of kind.
    static const EXPR vars[] =
    {
        {{{0}}, TOKEN_ICMP},
        {{{0}}, TOKEN_ICMP_BODY},
        {{{0}}, TOKEN_ICMP_CHECKSUM},
        {{{0}}, TOKEN_ICMP_CODE},
        {{{0}}, TOKEN_ICMP_TYPE},
        {{{0}}, TOKEN_ICMPV6},
        {{{0}}, TOKEN_ICMPV6_BODY},
        {{{0}}, TOKEN_ICMPV6_CHECKSUM},
        {{{0}}, TOKEN_ICMPV6_CODE},
        {{{0}}, TOKEN_ICMPV6_TYPE},
        {{{0}}, TOKEN_IP},
        {{{0}}, TOKEN_IP_CHECKSUM},
        {{{0}}, TOKEN_IP_DF},
        {{{0}}, TOKEN_IP_DST_ADDR},
        {{{0}}, TOKEN_IP_FRAG_OFF},
        {{{0}}, TOKEN_IP_HDR_LENGTH},
        {{{0}}, TOKEN_IP_ID},
        {{{0}}, TOKEN_IP_LENGTH},
        {{{0}}, TOKEN_IP_MF},
        {{{0}}, TOKEN_IP_PROTOCOL},
        {{{0}}, TOKEN_IP_SRC_ADDR},
        {{{0}}, TOKEN_IP_TOS},
        {{{0}}, TOKEN_IP_TTL},
        {{{0}}, TOKEN_IPV6},
        {{{0}}, TOKEN_IPV6_DST_ADDR},
        {{{0}}, TOKEN_IPV6_FLOW_LABEL},
        {{{0}}, TOKEN_IPV6_HOP_LIMIT},
        {{{0}}, TOKEN_IPV6_LENGTH},
        {{{0}}, TOKEN_IPV6_NEXT_HDR},
        {{{0}}, TOKEN_IPV6_SRC_ADDR},
        {{{0}}, TOKEN_IPV6_TRAFFIC_CLASS},
        {{{0}}, TOKEN_TCP},
        {{{0}}, TOKEN_TCP_ACK},
        {{{0}}, TOKEN_TCP_ACK_NUM},
        {{{0}}, TOKEN_TCP_CHECKSUM},
        {{{0}}, TOKEN_TCP_DST_PORT},
        {{{0}}, TOKEN_TCP_FIN},
        {{{0}}, TOKEN_TCP_HDR_LENGTH},
        {{{0}}, TOKEN_TCP_PAYLOAD_LENGTH},
        {{{0}}, TOKEN_TCP_PSH},
        {{{0}}, TOKEN_TCP_RST},
        {{{0}}, TOKEN_TCP_SEQ_NUM},
        {{{0}}, TOKEN_TCP_SRC_PORT},
        {{{0}}, TOKEN_TCP_SYN},
        {{{0}}, TOKEN_TCP_URG},
        {{{0}}, TOKEN_TCP_URG_PTR},
        {{{0}}, TOKEN_TCP_WINDOW},
        {{{0}}, TOKEN_UDP},
        {{{0}}, TOKEN_UDP_CHECKSUM},
        {{{0}}, TOKEN_UDP_DST_PORT},
        {{{0}}, TOKEN_UDP_LENGTH},
        {{{0}}, TOKEN_UDP_PAYLOAD_LENGTH},
        {{{0}}, TOKEN_UDP_SRC_PORT},
        {{{0}}, TOKEN_ZERO},
        {{{0}}, TOKEN_EVENT},
        {{{0}}, TOKEN_RANDOM8},
        {{{0}}, TOKEN_RANDOM16},
        {{{0}}, TOKEN_RANDOM32},
        {{{0}}, TOKEN_LENGTH},
        {{{0}}, TOKEN_TIMESTAMP},
        {{{0}}, TOKEN_TRUE},
        {{{0}}, TOKEN_FALSE},
        {{{0}}, TOKEN_INBOUND},
        {{{0}}, TOKEN_OUTBOUND},
        {{{0}}, TOKEN_FRAGMENT},
        {{{0}}, TOKEN_IF_IDX},
        {{{0}}, TOKEN_SUB_IF_IDX},
        {{{0}}, TOKEN_LOOPBACK},
        {{{0}}, TOKEN_IMPOSTOR},
        {{{0}}, TOKEN_PROCESS_ID},
        {{{0}}, TOKEN_LOCAL_ADDR},
        {{{0}}, TOKEN_REMOTE_ADDR},
        {{{0}}, TOKEN_LOCAL_PORT},
        {{{0}}, TOKEN_REMOTE_PORT},
        {{{0}}, TOKEN_PROTOCOL},
        {{{0}}, TOKEN_ENDPOINT_ID},
        {{{0}}, TOKEN_PARENT_ENDPOINT_ID},
        {{{0}}, TOKEN_LAYER},
        {{{0}}, TOKEN_PRIORITY},
    };

    // Binary search:
    UINT lo = 0, hi = sizeof(vars) / sizeof(vars[0]) - 1, mid;
    while (lo <= hi)
    {
        mid = (hi + lo) / 2;
        if (vars[mid].kind < kind)
        {
            lo = mid + 1;
            continue;
        }
        if (vars[mid].kind > kind)
        {
            hi = mid - 1;
            continue;
        }
        return (PEXPR)(vars + mid);
    }
    if (error != NULL)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_ASSERTION_FAILED, 0);
    }
    return NULL;
}

/*
 * Construct array varable.
 */
static PEXPR CyDivertMakeArrayVar(HANDLE pool, KIND kind, INT idx,
    PERROR error)
{
    PEXPR var = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (var == NULL)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    var->kind = kind;
    var->val[0] = (UINT32)idx;
    return var;
}

/*
 * Construct zero.
 */
static PEXPR CyDivertMakeZero(void)
{
    static const EXPR zero = {{{0, 0, 0, 0}}, TOKEN_NUMBER};
    return (PEXPR)&zero;
}

/*
 * Construct one.
 */
static PEXPR CyDivertMakeOne(void)
{
    static const EXPR one = {{{1, 0, 0, 0}}, TOKEN_NUMBER};
    return (PEXPR)&one;
}

/*
 * Construct a number.
 */
static PEXPR CyDivertMakeNumber(HANDLE pool, UINT32 *val, PERROR error)
{
    PEXPR expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (expr == NULL)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    expr->kind = TOKEN_NUMBER;
    expr->val[0] = val[0];
    expr->val[1] = val[1];
    expr->val[2] = val[2];
    expr->val[3] = val[3];
    return expr;
}

/*
 * Construct a binary operator.
 */
static PEXPR CyDivertMakeBinOp(HANDLE pool, KIND kind, PEXPR arg0, PEXPR arg1,
    PERROR error)
{
    PEXPR expr;
    if (arg0 == NULL || arg1 == NULL)
    {
        return NULL;
    }
    expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (expr == NULL)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    expr->kind = kind;
    expr->arg[0] = arg0;
    expr->arg[1] = arg1;
    return expr;
}

/*
 * Construct an if-then-else.
 */
static PEXPR CyDivertMakeIfThenElse(HANDLE pool, PEXPR cond, PEXPR th,
    PEXPR el, PERROR error)
{
    PEXPR expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (expr == NULL)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_NO_MEMORY, 0);
        return NULL;
    }
    expr->kind = TOKEN_QUESTION;
    expr->arg[0] = cond;
    expr->arg[1] = th;
    expr->arg[2] = el;
    return expr;
}

/*
 * Parse a filter test.
 */
static PEXPR CyDivertParseTest(HANDLE pool, TOKEN *toks, UINT *i, PERROR error)
{
    PEXPR var, val;
    KIND kind;
    BOOL not = FALSE, neg;
    UINT idx, size;
    while (toks[*i].kind == TOKEN_NOT)
    {
        not = !not;
        *i = *i + 1;
    }
    switch (toks[*i].kind)
    {
        case TOKEN_TIMESTAMP:
        case TOKEN_PRIORITY:
        case TOKEN_ZERO:
        case TOKEN_EVENT:
        case TOKEN_RANDOM8:
        case TOKEN_RANDOM16:
        case TOKEN_RANDOM32:
        case TOKEN_TRUE:
        case TOKEN_FALSE:
        case TOKEN_OUTBOUND:
        case TOKEN_INBOUND:
        case TOKEN_FRAGMENT:
        case TOKEN_IF_IDX:
        case TOKEN_SUB_IF_IDX:
        case TOKEN_LOOPBACK:
        case TOKEN_IMPOSTOR:
        case TOKEN_IP:
        case TOKEN_IPV6:
        case TOKEN_ICMP:
        case TOKEN_ICMPV6:
        case TOKEN_TCP:
        case TOKEN_UDP:
        case TOKEN_PROCESS_ID:
        case TOKEN_LOCAL_ADDR:
        case TOKEN_REMOTE_ADDR:
        case TOKEN_LOCAL_PORT:
        case TOKEN_REMOTE_PORT:
        case TOKEN_PROTOCOL:
        case TOKEN_ENDPOINT_ID:
        case TOKEN_PARENT_ENDPOINT_ID:
        case TOKEN_LENGTH:
        case TOKEN_LAYER:
        case TOKEN_IP_HDR_LENGTH:
        case TOKEN_IP_TOS:
        case TOKEN_IP_LENGTH:
        case TOKEN_IP_ID:
        case TOKEN_IP_DF:
        case TOKEN_IP_MF:
        case TOKEN_IP_FRAG_OFF:
        case TOKEN_IP_TTL:
        case TOKEN_IP_PROTOCOL:
        case TOKEN_IP_CHECKSUM:
        case TOKEN_IP_SRC_ADDR:
        case TOKEN_IP_DST_ADDR:
        case TOKEN_IPV6_TRAFFIC_CLASS:
        case TOKEN_IPV6_FLOW_LABEL:
        case TOKEN_IPV6_LENGTH:
        case TOKEN_IPV6_NEXT_HDR:
        case TOKEN_IPV6_HOP_LIMIT:
        case TOKEN_IPV6_SRC_ADDR:
        case TOKEN_IPV6_DST_ADDR:
        case TOKEN_ICMP_TYPE:
        case TOKEN_ICMP_CODE:
        case TOKEN_ICMP_CHECKSUM:
        case TOKEN_ICMP_BODY:
        case TOKEN_ICMPV6_TYPE:
        case TOKEN_ICMPV6_CODE:
        case TOKEN_ICMPV6_CHECKSUM:
        case TOKEN_ICMPV6_BODY:
        case TOKEN_TCP_SRC_PORT:
        case TOKEN_TCP_DST_PORT:
        case TOKEN_TCP_SEQ_NUM:
        case TOKEN_TCP_ACK_NUM:
        case TOKEN_TCP_HDR_LENGTH:
        case TOKEN_TCP_URG:
        case TOKEN_TCP_ACK:
        case TOKEN_TCP_PSH:
        case TOKEN_TCP_RST:
        case TOKEN_TCP_SYN:
        case TOKEN_TCP_FIN:
        case TOKEN_TCP_WINDOW:
        case TOKEN_TCP_CHECKSUM:
        case TOKEN_TCP_URG_PTR:
        case TOKEN_TCP_PAYLOAD_LENGTH:
        case TOKEN_UDP_SRC_PORT:
        case TOKEN_UDP_DST_PORT:
        case TOKEN_UDP_LENGTH:
        case TOKEN_UDP_CHECKSUM:
        case TOKEN_UDP_PAYLOAD_LENGTH:
            var = CyDivertMakeVar(toks[*i].kind, error);
            *i = *i + 1;
            break;
        case TOKEN_PACKET:
        case TOKEN_TCP_PAYLOAD:
        case TOKEN_UDP_PAYLOAD:
            size = sizeof(UINT8);
            goto array;
        case TOKEN_PACKET16:
        case TOKEN_TCP_PAYLOAD16:
        case TOKEN_UDP_PAYLOAD16:
            size = sizeof(UINT16);
            goto array;
        case TOKEN_PACKET32:
        case TOKEN_TCP_PAYLOAD32:
        case TOKEN_UDP_PAYLOAD32:
            size = sizeof(UINT32);
        array:
            kind = toks[*i].kind;
            *i = *i + 1;
            if (toks[*i].kind != TOKEN_SQUARE_OPEN)
            {
                goto unexpected_token;
            }
            *i = *i + 1;
            neg = FALSE;
            if (toks[*i].kind == TOKEN_MINUS)
            {
                neg = TRUE;
                *i = *i + 1;
            }
            if (toks[*i].kind != TOKEN_NUMBER)
            {
                goto unexpected_token;
            }
            if (toks[*i].val[3] != 0 || toks[*i].val[2] != 0 ||
                toks[*i].val[1] != 0 || toks[*i].val[0] > CYDIVERT_MTU_MAX)
            {
                *error = MAKE_ERROR(CYDIVERT_ERROR_INDEX_OOB, toks[*i].pos);
                return NULL;
            }
            idx = toks[*i].val[0];
            *i = *i + 1;
            if (toks[*i].kind == TOKEN_BYTES)
            {
                *i = *i + 1;
            }
            else
            {
                idx *= size;
            }
            if ((!neg && idx > UINT16_MAX - size) ||
                (neg && idx > UINT16_MAX) || (neg && idx < size))
            {
                *error = MAKE_ERROR(CYDIVERT_ERROR_INDEX_OOB, toks[*i].pos);
                return NULL;
            }
            var = CyDivertMakeArrayVar(pool, kind, (neg? -(INT)idx: (INT)idx),
                error);
            if (var == NULL)
            {
                return NULL;
            }
            if (toks[*i].kind != TOKEN_SQUARE_CLOSE)
            {
                goto unexpected_token;
            }
            *i = *i + 1;
            break;
        default:
        unexpected_token:
            *error = MAKE_ERROR(CYDIVERT_ERROR_UNEXPECTED_TOKEN, toks[*i].pos);
            return NULL;
    }
    switch (toks[*i].kind)
    {
        case TOKEN_EQ:
        case TOKEN_NEQ:
        case TOKEN_LT:
        case TOKEN_LEQ:
        case TOKEN_GT:
        case TOKEN_GEQ:
            kind = toks[*i].kind;
            break;
        default:
            return CyDivertMakeBinOp(pool, (not? TOKEN_EQ: TOKEN_NEQ), var,
                CyDivertMakeZero(), error);
    }
    if (not)
    {
        switch (kind)
        {
            case TOKEN_EQ:
                kind = TOKEN_NEQ;
                break;
            case TOKEN_NEQ:
                kind = TOKEN_EQ;
                break;
            case TOKEN_LT:
                kind = TOKEN_GEQ;
                break;
            case TOKEN_LEQ:
                kind = TOKEN_GT;
                break;
            case TOKEN_GT:
                kind = TOKEN_LEQ;
                break;
            case TOKEN_GEQ:
                kind = TOKEN_LT;
                break;
            default:
                break;
        }
    }
    *i = *i + 1;
    neg = FALSE;
    if (toks[*i].kind == TOKEN_MINUS)
    {
        neg = TRUE;
        *i = *i + 1;
    }
    if (toks[*i].kind != TOKEN_NUMBER)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_UNEXPECTED_TOKEN, toks[*i].pos);
        return NULL;
    }
    val = CyDivertMakeNumber(pool, toks[*i].val, error);
    val->neg = neg;
    *i = *i + 1;
    return CyDivertMakeBinOp(pool, kind, var, val, error);
}

/*
 * Parse a filter argument to an (and) (or) operator.
 */
static PEXPR CyDivertParseAndOrArg(HANDLE pool, TOKEN *toks, UINT *i,
    INT depth, PERROR error)
{
    PEXPR arg, th, el;
    if (depth-- < 0)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_TOO_DEEP, toks[*i].pos);
        return NULL;
    }
    switch (toks[*i].kind)
    {
        case TOKEN_OPEN:
            *i = *i + 1;
            arg = CyDivertParseFilter(pool, toks, i, depth, FALSE, error);
            if (toks[*i].kind == TOKEN_CLOSE)
            {
                *i = *i + 1;
                return arg;
            }
            if (toks[*i].kind == TOKEN_QUESTION)
            {
                *i = *i + 1;
                th = CyDivertParseFilter(pool, toks, i, depth, FALSE, error);
                if (th == NULL)
                {
                    return NULL;
                }
                if (toks[*i].kind != TOKEN_COLON)
                {
                    *error = MAKE_ERROR(CYDIVERT_ERROR_UNEXPECTED_TOKEN,
                        toks[*i].pos);
                    return NULL;
                }
                *i = *i + 1;
                el = CyDivertParseFilter(pool, toks, i, depth, FALSE, error);
                if (el == NULL)
                {
                    return NULL;
                }
                if (toks[*i].kind != TOKEN_CLOSE)
                {
                    *error = MAKE_ERROR(CYDIVERT_ERROR_UNEXPECTED_TOKEN,
                        toks[*i].pos);
                    return NULL;
                }
                *i = *i + 1;
                arg = CyDivertMakeIfThenElse(pool, arg, th, el, error);
                return arg;
            }
            *error = MAKE_ERROR(CYDIVERT_ERROR_UNEXPECTED_TOKEN, toks[*i].pos);
            return NULL;
        default:
            return CyDivertParseTest(pool, toks, i, error);
    }
}

/*
 * Parse the filter into an expression object.
 */
static PEXPR CyDivertParseFilter(HANDLE pool, TOKEN *toks, UINT *i, INT depth,
    BOOL and, PERROR error)
{
    PEXPR expr, arg;
    if (depth-- < 0)
    {
        *error = MAKE_ERROR(CYDIVERT_ERROR_TOO_DEEP, toks[*i].pos);
        return NULL;
    }
    if (and)
        expr = CyDivertParseAndOrArg(pool, toks, i, depth, error);
    else
        expr = CyDivertParseFilter(pool, toks, i, depth, TRUE, error);
    do
    {
        if (expr == NULL)
        {
            return NULL;
        }
        switch (toks[*i].kind)
        {
            case TOKEN_AND:
                *i = *i + 1;
                arg = CyDivertParseAndOrArg(pool, toks, i, depth, error);
                expr = CyDivertMakeBinOp(pool, TOKEN_AND, expr, arg, error);
                continue;
            case TOKEN_OR:
                *i = *i + 1;
                arg = CyDivertParseFilter(pool, toks, i, depth, TRUE, error);
                expr = CyDivertMakeBinOp(pool, TOKEN_OR, expr, arg, error);
                continue;
            default:
                return expr;
        }
    }
    while (TRUE);
}

/*
 * Simplify a test if possible.
 */
static void CyDivertSimplifyTest(PEXPR test)
{
    PEXPR var = test->arg[0];
    PEXPR val = test->arg[1];
    BOOL neg_lb = FALSE, neg_ub = FALSE, neg;
    UINT32 lb[4] = {0}, ub[4] = {0};
    int result_lb, result_ub;
    BOOL eq = FALSE, result = FALSE;
    KIND type = TOKEN_TRUE;

    switch (var->kind)
    {
        case TOKEN_ZERO:
        case TOKEN_FALSE:
            eq = TRUE;
            lb[0] = ub[0] = 0;
            break;
        case TOKEN_TRUE:
            eq = TRUE;
            lb[0] = ub[0] = 1;
            break;
        case TOKEN_LAYER:
            lb[0] = 0; ub[0] = CYDIVERT_LAYER_MAX;
            break;
        case TOKEN_PRIORITY:
            neg_lb = TRUE;
            lb[0] = ub[0] = CYDIVERT_PRIORITY_MAX;
            break;
        case TOKEN_EVENT:
            lb[0] = 0; ub[0] = CYDIVERT_EVENT_MAX;
            break;
        case TOKEN_IP_DF:
        case TOKEN_IP_MF:
            type = TOKEN_IP;
            lb[0] = 0; ub[0] = 1;
            break;
        case TOKEN_TCP_URG:
        case TOKEN_TCP_ACK:
        case TOKEN_TCP_PSH:
        case TOKEN_TCP_RST:
        case TOKEN_TCP_SYN:
        case TOKEN_TCP_FIN:
            type = TOKEN_TCP;
            lb[0] = 0; ub[0] = 1;
            break;
        case TOKEN_INBOUND:
        case TOKEN_OUTBOUND:
        case TOKEN_FRAGMENT:
        case TOKEN_IP:
        case TOKEN_IPV6:
        case TOKEN_ICMP:
        case TOKEN_ICMPV6:
        case TOKEN_TCP:
        case TOKEN_UDP:
            lb[0] = 0; ub[0] = 1;
            break;
        case TOKEN_IP_HDR_LENGTH:
            type = TOKEN_IP;
            lb[0] = 0; ub[0] = 0x0F;
            break;
        case TOKEN_TCP_HDR_LENGTH:
            type = TOKEN_TCP;
            lb[0] = 0; ub[0] = 0x0F;
            break;
        case TOKEN_IP_TTL:
        case TOKEN_IP_PROTOCOL:
            type = TOKEN_IP;
            lb[0] = 0; ub[0] = 0xFF;
            break;
        case TOKEN_IPV6_TRAFFIC_CLASS:
        case TOKEN_IPV6_NEXT_HDR:
        case TOKEN_IPV6_HOP_LIMIT:
            type = TOKEN_IPV6;
            lb[0] = 0; ub[0] = 0xFF;
            break;
        case TOKEN_ICMP_TYPE:
        case TOKEN_ICMP_CODE:
            type = TOKEN_ICMP;
            lb[0] = 0; ub[0] = 0xFF;
            break;
        case TOKEN_ICMPV6_TYPE:
        case TOKEN_ICMPV6_CODE:
            type = TOKEN_ICMPV6;
            lb[0] = 0; ub[0] = 0xFF;
            break;
        case TOKEN_TCP_PAYLOAD:
            type = TOKEN_TCP;
            lb[0] = 0; ub[0] = 0xFF;
            break;
        case TOKEN_UDP_PAYLOAD:
            type = TOKEN_UDP;
            lb[0] = 0; ub[0] = 0xFF;
            break;
        case TOKEN_PROTOCOL:
        case TOKEN_PACKET:
        case TOKEN_RANDOM8:
            lb[0] = 0; ub[0] = 0xFF;
            break;
        case TOKEN_IP_FRAG_OFF:
            type = TOKEN_IP;
            lb[0] = 0; ub[0] = 0x1FFF;
            break;
        case TOKEN_IP_TOS:
        case TOKEN_IP_LENGTH:
        case TOKEN_IP_ID:
        case TOKEN_IP_CHECKSUM:
            type = TOKEN_IP;
            lb[0] = 0; ub[0] = 0xFFFF;
            break;
        case TOKEN_IPV6_LENGTH:
            type = TOKEN_IPV6;
            lb[0] = 0; ub[0] = 0xFFFF;
            break;
        case TOKEN_ICMP_CHECKSUM:
            type = TOKEN_ICMP;
            lb[0] = 0; ub[0] = 0xFFFF;
            break;
        case TOKEN_ICMPV6_CHECKSUM:
            type = TOKEN_ICMPV6;
            lb[0] = 0; ub[0] = 0xFFFF;
            break;
        case TOKEN_TCP_SRC_PORT:
        case TOKEN_TCP_DST_PORT:
        case TOKEN_TCP_WINDOW:
        case TOKEN_TCP_CHECKSUM:
        case TOKEN_TCP_URG_PTR:
        case TOKEN_TCP_PAYLOAD_LENGTH:
        case TOKEN_TCP_PAYLOAD16:
            type = TOKEN_TCP;
            lb[0] = 0; ub[0] = 0xFFFF;
            break;
        case TOKEN_UDP_SRC_PORT:
        case TOKEN_UDP_DST_PORT:
        case TOKEN_UDP_LENGTH:
        case TOKEN_UDP_CHECKSUM:
        case TOKEN_UDP_PAYLOAD_LENGTH:
        case TOKEN_UDP_PAYLOAD16:
            type = TOKEN_UDP;
            lb[0] = 0; ub[0] = 0xFFFF;
            break;
        case TOKEN_LOCAL_PORT:
        case TOKEN_REMOTE_PORT:
        case TOKEN_PACKET16:
        case TOKEN_RANDOM16:
            lb[0] = 0; ub[0] = 0xFFFF;
            break;
        case TOKEN_LENGTH:
            lb[0] = sizeof(CYDIVERT_IPHDR); ub[0] = CYDIVERT_MTU_MAX;
            break;
        case TOKEN_IPV6_FLOW_LABEL:
            type = TOKEN_IPV6;
            lb[0] = 0; ub[0] = 0x000FFFFF;
            break;
        case TOKEN_IP_SRC_ADDR:
        case TOKEN_IP_DST_ADDR:
            type = TOKEN_IP;
            lb[0] = 0;
            lb[1] = 0xFFFF;
            ub[0] = 0xFFFFFFFF;
            ub[1] = 0xFFFF;
            break;
        case TOKEN_IPV6_SRC_ADDR:
        case TOKEN_IPV6_DST_ADDR:
            type = TOKEN_IPV6;
            // Fallthrough
        case TOKEN_LOCAL_ADDR:
        case TOKEN_REMOTE_ADDR:
            lb[0] = lb[1] = lb[2] = lb[3] = 0;
            ub[0] = ub[1] = ub[2] = ub[3] = 0xFFFFFFFF;
            break;
        case TOKEN_TIMESTAMP:
            lb[0] = 0;
            lb[1] = 0x80000000;
            ub[0] = 0xFFFFFFFF;
            ub[1] = 0x7FFFFFFF;
            neg_lb = TRUE;
            break;
        case TOKEN_TCP_PAYLOAD32:
            type = TOKEN_TCP;
            lb[0] = 0; ub[0] = 0xFFFFFFFF;
            break;
        case TOKEN_UDP_PAYLOAD32:
            type = TOKEN_UDP;
            lb[0] = 0; ub[0] = 0xFFFFFFFF;
            break;
        case TOKEN_IF_IDX:
        case TOKEN_SUB_IF_IDX:
        case TOKEN_RANDOM32:
        case TOKEN_PROCESS_ID:
            lb[0] = 0; ub[0] = 0xFFFFFFFF;
            break;
        case TOKEN_ENDPOINT_ID:
        case TOKEN_PARENT_ENDPOINT_ID:
            lb[0] = lb[1] = 0;
            ub[0] = ub[1] = 0xFFFFFFFF;
            break;
        default:
            return;
    }
    neg = (val->neg? TRUE: FALSE);
    result_lb = CyDivertCompare128(neg, val->val, neg_lb, lb, /*big=*/TRUE);
    result_ub = CyDivertCompare128(neg, val->val, neg_ub, ub, /*big=*/TRUE);
    switch (test->kind)
    {
        case TOKEN_EQ:
            if (result_lb < 0 || result_ub > 0)
            {
                result = FALSE;
                break;
            }
            if (eq && result_lb == 0)
            {
                result = TRUE;
                break;
            }
            return;
        case TOKEN_NEQ:
            if (result_lb < 0 || result_ub > 0)
            {
                result = TRUE;
                break;
            }
            if (eq && result_lb == 0)
            {
                result = FALSE;
                break;
            }
            return;
        case TOKEN_LT:
            if (result_ub > 0)
            {
                result = TRUE;
                break;
            }
            if (result_lb <= 0)
            {
                result = FALSE;
                break;
            }
            return;
        case TOKEN_LEQ:
            if (result_ub >= 0)
            {
                result = TRUE;
                break;
            }
            if (result_lb < 0)
            {
                result = FALSE;
                break;
            }
            return;
        case TOKEN_GT:
            if (result_ub >= 0)
            {
                result = FALSE;
                break;
            }
            if (result_lb < 0)
            {
                result = TRUE;
                break;
            }
            return;
        case TOKEN_GEQ:
            if (result_ub > 0)
            {
                result = FALSE;
                break;
            }
            if (result_lb <= 0)
            {
                result = TRUE;
                break;
            }
            return;
        default:
            return;
    }
    test->arg[0] = CyDivertMakeVar(type, NULL);
    test->arg[1] = (result? CyDivertMakeOne(): CyDivertMakeZero());
    test->kind   = TOKEN_EQ;
}

/*
 * Flatten an expression into a sequence of tests and jumps.
 */
static INT16 CyDivertFlattenExpr(PEXPR expr, INT16 *label, INT16 succ,
    INT16 fail, PEXPR *stack)
{
    INT16 succ1, fail1;
    if (succ < 0 || fail < 0)
    {
        return -1;
    }
    switch (expr->kind)
    {
        case TOKEN_AND:
            succ = CyDivertFlattenExpr(expr->arg[1], label, succ, fail, stack);
            succ = CyDivertFlattenExpr(expr->arg[0], label, succ, fail, stack);
            return succ;
        case TOKEN_OR:
            fail = CyDivertFlattenExpr(expr->arg[1], label, succ, fail, stack);
            fail = CyDivertFlattenExpr(expr->arg[0], label, succ, fail, stack);
            return fail;
        case TOKEN_QUESTION:
            fail1 = CyDivertFlattenExpr(expr->arg[2], label, succ, fail,
                stack);
            succ1 = CyDivertFlattenExpr(expr->arg[1], label, succ, fail,
                stack);
            succ = CyDivertFlattenExpr(expr->arg[0], label, succ1, fail1,
                stack);
            return succ;
        default:
            CyDivertSimplifyTest(expr);
            if (expr->kind == TOKEN_EQ &&
                expr->arg[0]->kind == TOKEN_TRUE)
            {
                return (expr->arg[1]->val[0] != 0? succ: fail);
            }
            if (*label >= CYDIVERT_FILTER_MAXLEN)
            {
                return -1;
            }
            stack[*label] = expr;
            expr->succ = succ;
            expr->fail = fail;
            succ = *label;
            *label = *label + 1;
            return succ;
    }
}

/*
 * Convert a kind to a field.
 */
static UINT32 CyDivertKindToField(KIND kind)
{
    switch (kind)
    {
        case TOKEN_ZERO:
            return CYDIVERT_FILTER_FIELD_ZERO;
        case TOKEN_EVENT:
            return CYDIVERT_FILTER_FIELD_EVENT;
        case TOKEN_RANDOM8:
            return CYDIVERT_FILTER_FIELD_RANDOM8;
        case TOKEN_RANDOM16:
            return CYDIVERT_FILTER_FIELD_RANDOM16;
        case TOKEN_RANDOM32:
            return CYDIVERT_FILTER_FIELD_RANDOM32;
        case TOKEN_PACKET:
            return CYDIVERT_FILTER_FIELD_PACKET;
        case TOKEN_PACKET16:
            return CYDIVERT_FILTER_FIELD_PACKET16;
        case TOKEN_PACKET32:
            return CYDIVERT_FILTER_FIELD_PACKET32;
        case TOKEN_LENGTH:
            return CYDIVERT_FILTER_FIELD_LENGTH;
        case TOKEN_TIMESTAMP:
            return CYDIVERT_FILTER_FIELD_TIMESTAMP;
        case TOKEN_TCP_PAYLOAD:
            return CYDIVERT_FILTER_FIELD_TCP_PAYLOAD;
        case TOKEN_TCP_PAYLOAD16:
            return CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16;
        case TOKEN_TCP_PAYLOAD32:
            return CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32;
        case TOKEN_UDP_PAYLOAD:
            return CYDIVERT_FILTER_FIELD_UDP_PAYLOAD;
        case TOKEN_UDP_PAYLOAD16:
            return CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16;
        case TOKEN_UDP_PAYLOAD32:
            return CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32;
        case TOKEN_OUTBOUND:
            return CYDIVERT_FILTER_FIELD_OUTBOUND;
        case TOKEN_INBOUND:
            return CYDIVERT_FILTER_FIELD_INBOUND;
        case TOKEN_FRAGMENT:
            return CYDIVERT_FILTER_FIELD_FRAGMENT;
        case TOKEN_IF_IDX:
            return CYDIVERT_FILTER_FIELD_IFIDX;
        case TOKEN_SUB_IF_IDX:
            return CYDIVERT_FILTER_FIELD_SUBIFIDX;
        case TOKEN_LOOPBACK:
            return CYDIVERT_FILTER_FIELD_LOOPBACK;
        case TOKEN_IMPOSTOR:
            return CYDIVERT_FILTER_FIELD_IMPOSTOR;
        case TOKEN_PROCESS_ID:
            return CYDIVERT_FILTER_FIELD_PROCESSID;
        case TOKEN_LOCAL_ADDR:
            return CYDIVERT_FILTER_FIELD_LOCALADDR;
        case TOKEN_REMOTE_ADDR:
            return CYDIVERT_FILTER_FIELD_REMOTEADDR;
        case TOKEN_LOCAL_PORT:
            return CYDIVERT_FILTER_FIELD_LOCALPORT;
        case TOKEN_REMOTE_PORT:
            return CYDIVERT_FILTER_FIELD_REMOTEPORT;
        case TOKEN_PROTOCOL:
            return CYDIVERT_FILTER_FIELD_PROTOCOL;
        case TOKEN_ENDPOINT_ID:
            return CYDIVERT_FILTER_FIELD_ENDPOINTID;
        case TOKEN_PARENT_ENDPOINT_ID:
            return CYDIVERT_FILTER_FIELD_PARENTENDPOINTID;
        case TOKEN_LAYER:
            return CYDIVERT_FILTER_FIELD_LAYER;
        case TOKEN_PRIORITY:
            return CYDIVERT_FILTER_FIELD_PRIORITY;
        case TOKEN_IP:
            return CYDIVERT_FILTER_FIELD_IP;
        case TOKEN_IPV6:
            return CYDIVERT_FILTER_FIELD_IPV6;
        case TOKEN_ICMP:
            return CYDIVERT_FILTER_FIELD_ICMP;
        case TOKEN_ICMPV6:
            return CYDIVERT_FILTER_FIELD_ICMPV6;
        case TOKEN_TCP:
            return CYDIVERT_FILTER_FIELD_TCP;
        case TOKEN_UDP:
            return CYDIVERT_FILTER_FIELD_UDP;
        case TOKEN_IP_HDR_LENGTH:
            return CYDIVERT_FILTER_FIELD_IP_HDRLENGTH;
        case TOKEN_IP_TOS:
            return CYDIVERT_FILTER_FIELD_IP_TOS;
        case TOKEN_IP_LENGTH:
            return CYDIVERT_FILTER_FIELD_IP_LENGTH;
        case TOKEN_IP_ID:
            return CYDIVERT_FILTER_FIELD_IP_ID;
        case TOKEN_IP_DF:
            return CYDIVERT_FILTER_FIELD_IP_DF;
        case TOKEN_IP_MF:
            return CYDIVERT_FILTER_FIELD_IP_MF;
        case TOKEN_IP_FRAG_OFF:
            return CYDIVERT_FILTER_FIELD_IP_FRAGOFF;
        case TOKEN_IP_TTL:
            return CYDIVERT_FILTER_FIELD_IP_TTL;
        case TOKEN_IP_PROTOCOL:
            return CYDIVERT_FILTER_FIELD_IP_PROTOCOL;
        case TOKEN_IP_CHECKSUM:
            return CYDIVERT_FILTER_FIELD_IP_CHECKSUM;
        case TOKEN_IP_SRC_ADDR:
            return CYDIVERT_FILTER_FIELD_IP_SRCADDR;
        case TOKEN_IP_DST_ADDR:
            return CYDIVERT_FILTER_FIELD_IP_DSTADDR;
        case TOKEN_IPV6_TRAFFIC_CLASS:
            return CYDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS;
        case TOKEN_IPV6_FLOW_LABEL:
            return CYDIVERT_FILTER_FIELD_IPV6_FLOWLABEL;
        case TOKEN_IPV6_LENGTH:
            return CYDIVERT_FILTER_FIELD_IPV6_LENGTH;
        case TOKEN_IPV6_NEXT_HDR:
            return CYDIVERT_FILTER_FIELD_IPV6_NEXTHDR;
        case TOKEN_IPV6_HOP_LIMIT:
            return CYDIVERT_FILTER_FIELD_IPV6_HOPLIMIT;
        case TOKEN_IPV6_SRC_ADDR:
            return CYDIVERT_FILTER_FIELD_IPV6_SRCADDR;
        case TOKEN_IPV6_DST_ADDR:
            return CYDIVERT_FILTER_FIELD_IPV6_DSTADDR;
        case TOKEN_ICMP_TYPE:
            return CYDIVERT_FILTER_FIELD_ICMP_TYPE;
        case TOKEN_ICMP_CODE:
            return CYDIVERT_FILTER_FIELD_ICMP_CODE;
        case TOKEN_ICMP_CHECKSUM:
            return CYDIVERT_FILTER_FIELD_ICMP_CHECKSUM;
        case TOKEN_ICMP_BODY:
            return CYDIVERT_FILTER_FIELD_ICMP_BODY;
        case TOKEN_ICMPV6_TYPE:
            return CYDIVERT_FILTER_FIELD_ICMPV6_TYPE;
        case TOKEN_ICMPV6_CODE:
            return CYDIVERT_FILTER_FIELD_ICMPV6_CODE;
        case TOKEN_ICMPV6_CHECKSUM:
            return CYDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM;
        case TOKEN_ICMPV6_BODY:
            return CYDIVERT_FILTER_FIELD_ICMPV6_BODY;
        case TOKEN_TCP_SRC_PORT:
            return CYDIVERT_FILTER_FIELD_TCP_SRCPORT;
        case TOKEN_TCP_DST_PORT:
            return CYDIVERT_FILTER_FIELD_TCP_DSTPORT;
        case TOKEN_TCP_SEQ_NUM:
            return CYDIVERT_FILTER_FIELD_TCP_SEQNUM;
        case TOKEN_TCP_ACK_NUM:
            return CYDIVERT_FILTER_FIELD_TCP_ACKNUM;
        case TOKEN_TCP_HDR_LENGTH:
            return CYDIVERT_FILTER_FIELD_TCP_HDRLENGTH;
        case TOKEN_TCP_URG:
            return CYDIVERT_FILTER_FIELD_TCP_URG;
        case TOKEN_TCP_ACK:
            return CYDIVERT_FILTER_FIELD_TCP_ACK;
        case TOKEN_TCP_PSH:
            return CYDIVERT_FILTER_FIELD_TCP_PSH;
        case TOKEN_TCP_RST:
            return CYDIVERT_FILTER_FIELD_TCP_RST;
        case TOKEN_TCP_SYN:
            return CYDIVERT_FILTER_FIELD_TCP_SYN;
        case TOKEN_TCP_FIN:
            return CYDIVERT_FILTER_FIELD_TCP_FIN;
        case TOKEN_TCP_WINDOW:
            return CYDIVERT_FILTER_FIELD_TCP_WINDOW;
        case TOKEN_TCP_CHECKSUM:
            return CYDIVERT_FILTER_FIELD_TCP_CHECKSUM;
        case TOKEN_TCP_URG_PTR:
            return CYDIVERT_FILTER_FIELD_TCP_URGPTR;
        case TOKEN_TCP_PAYLOAD_LENGTH:
            return CYDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH;
        case TOKEN_UDP_SRC_PORT:
            return CYDIVERT_FILTER_FIELD_UDP_SRCPORT;
        case TOKEN_UDP_DST_PORT:
            return CYDIVERT_FILTER_FIELD_UDP_DSTPORT;
        case TOKEN_UDP_LENGTH:
            return CYDIVERT_FILTER_FIELD_UDP_LENGTH;
        case TOKEN_UDP_CHECKSUM:
            return CYDIVERT_FILTER_FIELD_UDP_CHECKSUM;
        case TOKEN_UDP_PAYLOAD_LENGTH:
            return CYDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH;
        default:
            return UINT32_MAX;
    }
}

/*
 * Emit a test.
 */
static void CyDivertEmitTest(PEXPR test, UINT16 offset,
    PCYDIVERT_FILTER object)
{
    PEXPR var = test->arg[0], val = test->arg[1];
    switch (test->kind)
    {
        case TOKEN_EQ:
            object->test = CYDIVERT_FILTER_TEST_EQ;
            break;
        case TOKEN_NEQ:
            object->test = CYDIVERT_FILTER_TEST_NEQ;
            break;
        case TOKEN_LT:
            object->test = CYDIVERT_FILTER_TEST_LT;
            break;
        case TOKEN_LEQ:
            object->test = CYDIVERT_FILTER_TEST_LEQ;
            break;
        case TOKEN_GT:
            object->test = CYDIVERT_FILTER_TEST_GT;
            break;
        case TOKEN_GEQ:
            object->test = CYDIVERT_FILTER_TEST_GEQ;
            break;
        default:
            return;
    }
    object->field = CyDivertKindToField(var->kind);
    object->neg = (val->neg? 1: 0);
    object->arg[0] = val->val[0];
    object->arg[1] = val->val[1];
    object->arg[2] = val->val[2];
    object->arg[3] = val->val[3];
    switch (var->kind)
    {
        case TOKEN_PACKET:
        case TOKEN_PACKET16:
        case TOKEN_PACKET32:
        case TOKEN_TCP_PAYLOAD:
        case TOKEN_TCP_PAYLOAD16:
        case TOKEN_TCP_PAYLOAD32:
        case TOKEN_UDP_PAYLOAD:
        case TOKEN_UDP_PAYLOAD16:
        case TOKEN_UDP_PAYLOAD32:
            object->arg[1] = var->val[0];
            break;
        default:
            break;
    }
    switch (test->succ)
    {
        case CYDIVERT_FILTER_RESULT_ACCEPT:
        case CYDIVERT_FILTER_RESULT_REJECT:
            object->success = test->succ;
            break;
        default:
            object->success = offset - test->succ;
            break;
    }
    switch (test->fail)
    {
        case CYDIVERT_FILTER_RESULT_ACCEPT:
        case CYDIVERT_FILTER_RESULT_REJECT:
            object->failure = test->fail;
            break;
        default:
            object->failure = offset - test->fail;
            break;
    }
    return;
}

/*
 * Emit a filter object.
 */
static void CyDivertEmitFilter(PEXPR *stack, UINT len, UINT16 label,
    PCYDIVERT_FILTER object, UINT *obj_len)
{
    UINT i;
    switch (label)
    {
        case CYDIVERT_FILTER_RESULT_ACCEPT:
        case CYDIVERT_FILTER_RESULT_REJECT:
            object[0].field   = CYDIVERT_FILTER_FIELD_ZERO;
            object[0].test    = CYDIVERT_FILTER_TEST_EQ;
            object[0].neg     = 0;
            object[0].arg[0]  = 0;
            object[0].arg[1]  = 0;
            object[0].arg[2]  = 0;
            object[0].arg[3]  = 0;
            object[0].success = label;
            object[0].failure = label;
            *obj_len = 1;
            return;
        default:
            break;
    }
    *obj_len = len + 1;
    for (i = 0; i <= len; i++)
    {
        CyDivertEmitTest(stack[len - i], label, object + i);
    }
}

/*
 * Analyze a filter object.
 */
static UINT64 CyDivertAnalyzeFilter(CYDIVERT_LAYER layer,
    PCYDIVERT_FILTER filter, UINT length)
{
    BOOL result;
    UINT64 flags = 0;

    // False filter?
    result = CyDivertCondExecFilter(filter, length,
        CYDIVERT_FILTER_FIELD_ZERO, 0);
    if (!result)
    {
        return 0;
    }

    if (layer == CYDIVERT_LAYER_NETWORK ||
        layer == CYDIVERT_LAYER_NETWORK_FORWARD)
    {
        // Inbound?
        result = CyDivertCondExecFilter(filter, length,
            CYDIVERT_FILTER_FIELD_INBOUND, 1);
        if (result)
        {
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_OUTBOUND, 0);
        }
        flags |= (result? CYDIVERT_FILTER_FLAG_INBOUND: 0);

        // Outbound?
        result = CyDivertCondExecFilter(filter, length,
            CYDIVERT_FILTER_FIELD_OUTBOUND, 1);
        if (result)
        {
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_INBOUND, 0);
        }
        flags |= (result? CYDIVERT_FILTER_FLAG_OUTBOUND: 0);
    }

    if (layer != CYDIVERT_LAYER_REFLECT)
    {
        // IPv4? 
        result = CyDivertCondExecFilter(filter, length,
            CYDIVERT_FILTER_FIELD_IP, 1);
        if (result)
        {   
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_IPV6, 0);
        }
        flags |= (result? CYDIVERT_FILTER_FLAG_IP: 0);

        // Ipv6? 
        result = CyDivertCondExecFilter(filter, length,
            CYDIVERT_FILTER_FIELD_IPV6, 1);
        if (result)
        {   
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_IP, 0);
        }
        flags |= (result? CYDIVERT_FILTER_FLAG_IPV6: 0);
    }

    // Events:
    switch (layer)
    {
        case CYDIVERT_LAYER_FLOW:
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_EVENT, CYDIVERT_EVENT_FLOW_DELETED);
            flags |= (result? CYDIVERT_FILTER_FLAG_EVENT_FLOW_DELETED: 0);
            break;

        case CYDIVERT_LAYER_SOCKET:
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_EVENT, CYDIVERT_EVENT_SOCKET_BIND);
            flags |= (result? CYDIVERT_FILTER_FLAG_EVENT_SOCKET_BIND: 0);
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_EVENT, CYDIVERT_EVENT_SOCKET_CONNECT);
            flags |= (result? CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CONNECT: 0);
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_EVENT, CYDIVERT_EVENT_SOCKET_CLOSE);
            flags |= (result? CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CLOSE: 0);
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_EVENT, CYDIVERT_EVENT_SOCKET_LISTEN);
            flags |= (result? CYDIVERT_FILTER_FLAG_EVENT_SOCKET_LISTEN: 0);
            result = CyDivertCondExecFilter(filter, length,
                CYDIVERT_FILTER_FIELD_EVENT, CYDIVERT_EVENT_SOCKET_ACCEPT);
            flags |= (result? CYDIVERT_FILTER_FLAG_EVENT_SOCKET_ACCEPT: 0);
            break;

        default:
            break;
    }

    return flags;
}

/*
 * Execute a filter object with respect to an assumption/condition.
 * FALSE = definite reject; TRUE = maybe accept.
 */
static BOOL CyDivertCondExecFilter(PCYDIVERT_FILTER filter, UINT length,
    UINT8 field, UINT32 arg)
{
    INT16 ip;
    UINT16 succ, fail;
    BOOLEAN result[CYDIVERT_FILTER_MAXLEN];
    BOOLEAN result_succ, result_fail, result_test;

    if (length == 0)
    {
        return TRUE;
    }

    for (ip = (INT16)(length-1); ip >= 0; ip--)
    {
        succ = filter[ip].success;
        switch (succ)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
                result_succ = TRUE;
                break;
            case CYDIVERT_FILTER_RESULT_REJECT:
                result_succ = FALSE;
                break;
            default:
                result_succ = (succ > ip && succ < length? result[succ]: TRUE);
                break;
        }

        fail = filter[ip].failure;
        switch (fail)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
                result_fail = TRUE;
                break;
            case CYDIVERT_FILTER_RESULT_REJECT:
                result_fail = FALSE;
                break;
            default:
                result_fail = (fail > ip && fail < length? result[fail]: TRUE);
                break;
        }

        if (result_succ && result_fail)
        {
            result[ip] = TRUE;
        }
        else if (!result_succ && !result_fail)
        {
            result[ip] = FALSE;
        }
        else if (filter[ip].field == field)
        {
            if (filter[ip].neg || filter[ip].arg[1] != 0 ||
                filter[ip].arg[2] != 0 || filter[ip].arg[3] != 0)
            {
                result[ip] = TRUE;
            }
            else
            {
                switch (filter[ip].test)
                {
                    case CYDIVERT_FILTER_TEST_EQ:
                        result_test = (arg == filter[ip].arg[0]);
                        break;
                    case CYDIVERT_FILTER_TEST_NEQ:
                        result_test = (arg != filter[ip].arg[0]);
                        break;
                    case CYDIVERT_FILTER_TEST_LT:
                        result_test = (arg < filter[ip].arg[0]);
                        break;
                    case CYDIVERT_FILTER_TEST_LEQ:
                        result_test = (arg <= filter[ip].arg[0]);
                        break;
                    case CYDIVERT_FILTER_TEST_GT:
                        result_test = (arg > filter[ip].arg[0]);
                        break;
                    case CYDIVERT_FILTER_TEST_GEQ:
                        result_test = (arg >= filter[ip].arg[0]);
                        break;
                    default:
                        result[ip] = TRUE;
                        continue;
                }
                result[ip] = (result_test? result_succ: result_fail);
            }
        }
        else
        {
            result[ip] = TRUE;
        }
    }

    return result[0];
}

/*
 * Compile a filter string into an executable filter object.
 */
static ERROR CyDivertCompileFilter(const char *filter, HANDLE pool,
    CYDIVERT_LAYER layer, PCYDIVERT_FILTER object, UINT *obj_len)
{
    TOKEN *tokens;
    PEXPR *stack;
    PEXPR expr;
    UINT i, max_depth, pos;
    INT16 label;
    const SIZE_T tokens_size = 5 * CYDIVERT_FILTER_MAXLEN;
    ERROR error;

    // Check for pre-compiled filter object:
    if (filter[0] == '@')
    {
        CYDIVERT_STREAM stream;
        stream.data     = (char *)filter;
        stream.pos      = 0;
        stream.max      = UINT_MAX;
        stream.overflow = FALSE;

        if (!CyDivertDeserializeFilter(&stream, object, obj_len))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return MAKE_ERROR(CYDIVERT_ERROR_BAD_OBJECT, 0);
        }
        return MAKE_ERROR(CYDIVERT_ERROR_NONE, 0);
    }

    tokens = (TOKEN *)HeapAlloc(pool, 0, tokens_size * sizeof(TOKEN));
    stack  = (PEXPR *)HeapAlloc(pool, 0,
        CYDIVERT_FILTER_MAXLEN * sizeof(PEXPR));
    if (tokens == NULL || stack == NULL)
    {
        return MAKE_ERROR(CYDIVERT_ERROR_NO_MEMORY, 0);
    }

    // Tokenize the filter string:
    error = CyDivertTokenizeFilter(filter, layer, tokens, tokens_size-1);
    if (IS_ERROR(error))
    {
        return error;
    }

    // Parse the filter into an expression:
    i = 0;
    max_depth = 1024;
    expr = CyDivertParseFilter(pool, tokens, &i, max_depth, FALSE, &error);
    if (expr == NULL)
    {
        return error;
    }
    if (tokens[i].kind != TOKEN_END)
    {
        pos = tokens[i].pos;
        return MAKE_ERROR(CYDIVERT_ERROR_UNEXPECTED_TOKEN, pos);
    }

    // Construct the filter tree:
    label = 0;
    label = CyDivertFlattenExpr(expr, &label, CYDIVERT_FILTER_RESULT_ACCEPT,
        CYDIVERT_FILTER_RESULT_REJECT, stack);
    if (label < 0)
    {
        return MAKE_ERROR(CYDIVERT_ERROR_TOO_LONG, 0);
    }

    // Emit the final object.
    if (object != NULL)
    {
        CyDivertEmitFilter(stack, label, label, object, obj_len);
    }

    return MAKE_ERROR(CYDIVERT_ERROR_NONE, 0);
}

/*
 * Convert a error code into a user readable string.
 */
static const char *CyDivertErrorString(UINT code)
{
    switch (code)
    {
        case CYDIVERT_ERROR_NONE:
            return "No error";
        case CYDIVERT_ERROR_NO_MEMORY:
            return "Out of memory";
        case CYDIVERT_ERROR_TOO_DEEP:
            return "Filter expression too deep";
        case CYDIVERT_ERROR_TOO_LONG:
            return "Filter expression too long";
        case CYDIVERT_ERROR_BAD_TOKEN:
            return "Filter expression contains a bad token";
        case CYDIVERT_ERROR_BAD_TOKEN_FOR_LAYER:
            return "Filter expression contains a bad token for layer";
        case CYDIVERT_ERROR_UNEXPECTED_TOKEN:
            return "Filter expression parse error";
        case CYDIVERT_ERROR_INDEX_OOB:
            return "Filter expression array index is out-of-bounds";
        case CYDIVERT_ERROR_OUTPUT_TOO_SHORT:
            return "Filter object buffer is too short";
        case CYDIVERT_ERROR_BAD_OBJECT:
            return "Filter object is invalid";
        case CYDIVERT_ERROR_ASSERTION_FAILED:
            return "Internal assertion failed";
        default:
            return "Unknown error";
    }
}

/*
 * Compile the given filter string.
 */
BOOL CyDivertHelperCompileFilter(const char *filter_str, CYDIVERT_LAYER layer,
    char *object, UINT obj_len, const char **error, UINT *error_pos)
{
    HANDLE pool;
    ERROR err;

    if (filter_str == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pool = HeapCreate(HEAP_NO_SERIALIZE, CYDIVERT_MIN_POOL_SIZE,
        CYDIVERT_MAX_POOL_SIZE);
    if (pool == NULL)
    {
        return FALSE;
    }

    SetLastError(ERROR_SUCCESS);
    if (object == NULL)
    {
        err = CyDivertCompileFilter(filter_str, pool, layer, NULL, NULL);
    }
    else
    {
        CYDIVERT_FILTER *filter_obj = HeapAlloc(pool, 0,
            CYDIVERT_FILTER_MAXLEN * sizeof(CYDIVERT_FILTER));
        UINT filter_obj_len;
        err = CYDIVERT_ERROR_NO_MEMORY;
        if (filter_obj != NULL)
        {
            err = CyDivertCompileFilter(filter_str, pool, layer, filter_obj,
                &filter_obj_len);
            if (!IS_ERROR(err))
            {
                CYDIVERT_STREAM stream;
                stream.data     = object;
                stream.pos      = 0;
                stream.max      = obj_len;
                stream.overflow = FALSE;
            
                CyDivertSerializeFilter(&stream, filter_obj, filter_obj_len);
                if (stream.overflow)
                {
                    SetLastError(ERROR_INSUFFICIENT_BUFFER);
                    err = MAKE_ERROR(CYDIVERT_ERROR_OUTPUT_TOO_SHORT, 0);
                }
            }
        }
    }
    HeapDestroy(pool);

    if (error != NULL)
    {
        *error = CyDivertErrorString(GET_CODE(err));
    }
    if (error_pos != NULL)
    {
        *error_pos = GET_POS(err);
    }
    return !IS_ERROR(err);
}

/*
 * Get packet/payload data.
 */
static BOOL CyDivertGetData(const VOID *packet, UINT packet_len, INT min,
    INT max, INT idx, PVOID data, UINT size)
{
    idx += (idx < 0? max: min);
    if (idx < min || idx > (max - (INT)size))
    {
        return FALSE;
    }

    memcpy(data, (UINT8 *)packet + idx, size);
    return TRUE;
}

/*
 * Evaluate the given filter with the given packet as input.
 */
BOOL CyDivertHelperEvalFilter(const char *filter, const VOID *packet,
    UINT packet_len, const CYDIVERT_ADDRESS *addr)
{
    ERROR err;
    DWORD error;
    CYDIVERT_PACKET info;
    PCYDIVERT_IPHDR ip_header = NULL;
    PCYDIVERT_IPV6HDR ipv6_header = NULL;
    PCYDIVERT_ICMPHDR icmp_header = NULL;
    PCYDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PCYDIVERT_TCPHDR tcp_header = NULL;
    PCYDIVERT_UDPHDR udp_header = NULL;
    const CYDIVERT_DATA_NETWORK *network_data = NULL;
    const CYDIVERT_DATA_FLOW *flow_data = NULL;
    const CYDIVERT_DATA_SOCKET *socket_data = NULL;
    const CYDIVERT_DATA_REFLECT *reflect_data = NULL;
    BOOL fragment = FALSE;
    UINT8 protocol = 0;
    UINT header_len = 0, payload_len = 0;
    int result;
    HANDLE pool;
    CYDIVERT_FILTER *object;
    UINT obj_len;

    if (filter == NULL || addr == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    switch (addr->Layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
            if (packet == NULL)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (!CyDivertHelperParsePacketEx((PVOID)packet, packet_len, &info))
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            protocol      = info.Protocol;
            ip_header     = info.IPHeader;
            ipv6_header   = info.IPv6Header;
            icmp_header   = info.ICMPHeader;
            icmpv6_header = info.ICMPv6Header;
            tcp_header    = info.TCPHeader;
            udp_header    = info.UDPHeader;
            payload_len   = info.PayloadLength;
            header_len    = info.HeaderLength;
            fragment      = info.Fragment;
            if ((addr->IPv6 && ipv6_header == NULL) ||
                (!addr->IPv6 && ip_header == NULL))
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            break;
        case CYDIVERT_LAYER_FLOW:
        case CYDIVERT_LAYER_SOCKET:
            if (packet != NULL)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            break;
        case CYDIVERT_LAYER_REFLECT:
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }
    switch (addr->Layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
            network_data = &addr->Network;
            break;
        case CYDIVERT_LAYER_FLOW:
            flow_data = &addr->Flow;
            break;
        case CYDIVERT_LAYER_SOCKET:
            socket_data = &addr->Socket;
            break;
        case CYDIVERT_LAYER_REFLECT:
            reflect_data = &addr->Reflect;
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }

    pool = HeapCreate(HEAP_NO_SERIALIZE, CYDIVERT_MIN_POOL_SIZE,
        CYDIVERT_MAX_POOL_SIZE);
    if (pool == NULL)
    {
        return FALSE;
    }
    object = HeapAlloc(pool, 0,
        CYDIVERT_FILTER_MAXLEN * sizeof(CYDIVERT_FILTER));
    if (object == NULL)
    {
        goto CyDivertHelperEvalFilterError;
    }
    err = CyDivertCompileFilter(filter, pool, addr->Layer, object, &obj_len);
    if (IS_ERROR(err))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        goto CyDivertHelperEvalFilterError;
    }

    result = CyDivertExecuteFilter(
        object,
        addr->Layer,
        addr->Timestamp,
        addr->Event,
        (addr->IPv6 != 0? FALSE: TRUE),
        (addr->Outbound != 0? TRUE: FALSE),
        (addr->Loopback != 0? TRUE: FALSE),
        (addr->Impostor != 0? TRUE: FALSE),
        fragment,
        network_data,
        flow_data,
        socket_data,
        reflect_data,
        ip_header,
        ipv6_header,
        icmp_header,
        icmpv6_header,
        tcp_header,
        udp_header,
        protocol,
        packet,
        packet_len,
        header_len,
        payload_len);

    HeapDestroy(pool);
    if (result < 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    else if (result == 0)
    {
        SetLastError(0);
        return FALSE;
    }
    else
    {
        return TRUE;
    }

CyDivertHelperEvalFilterError:
    error = GetLastError();
    HeapDestroy(pool);
    SetLastError(error);
    return FALSE;
}

/*
 * Get a char from a stream.
 */
static char CyDivertGetChar(PCYDIVERT_STREAM stream)
{
    char c;
    if (stream->pos >= stream->max)
    {
        stream->overflow = TRUE;
        return EOF;
    }
    c = stream->data[stream->pos];
    stream->pos++;
    return c;
}

/*
 * Decode a digit.
 */
static BOOL CyDivertDecodeDigit(char c, UINT8 *digit, BOOL *final)
{
    if (c >= '0' && c <= '9')
    {
        *digit = c - '0';
        *final = FALSE;
        return TRUE;
    }
    if (c >= 'A' && c <= 'V')
    {
        *digit = c - 'A' + 10;
        *final = FALSE;
        return TRUE;
    }
    if (c >= 'W' && c <= 'Z')
    {
        *digit = c - 'W';
        *final = TRUE;
        return TRUE;
    }
    if (c >= 'a' && c <= 'z')
    {
        *digit = c - 'a' + 4;
        *final = TRUE;
        return TRUE;
    }
    if (c == '+')
    {
        *digit = 30;
        *final = TRUE;
        return TRUE;
    }
    if (c == '=')
    {
        *digit = 31;
        *final = TRUE;
        return TRUE;
    }
    return FALSE;
}

/*
 * Deserialize a number.
 */
static BOOL CyDivertDeserializeNumber(PCYDIVERT_STREAM stream, UINT max_len,
    UINT32 *result)
{
    UINT32 i, val = 0;
    UINT8 digit;
    BOOL final;
    char c;

    for (i = 0; i < max_len; i++)
    {
        if ((val & 0xF8000000) != 0)
        {
            return FALSE;       // Overflow
        }
        val <<= 5;
        c = CyDivertGetChar(stream);
        if (!CyDivertDecodeDigit(c, &digit, &final))
        {
            return FALSE;
        }
        val += digit;
        if (final)
        {
            *result = val;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Deserialize a label.
 */
static BOOL CyDivertDeserializeLabel(PCYDIVERT_STREAM stream, UINT16 *label)
{
    UINT32 val;

    switch (CyDivertGetChar(stream))
    {
        case 'A':
            *label = CYDIVERT_FILTER_RESULT_ACCEPT;
            return TRUE;
        case 'X':
            *label = CYDIVERT_FILTER_RESULT_REJECT;
            return TRUE;
        case 'L':
            if (!CyDivertDeserializeNumber(stream, 2, &val) ||
                    val > CYDIVERT_FILTER_MAXLEN)
            {
                return FALSE;
            }
            *label = (UINT16)val;
            return TRUE;
        default:
            return FALSE;
    }
}

/*
 * Deserialize a test.
 */
static BOOL CyDivertDeserializeTest(PCYDIVERT_STREAM stream,
    PCYDIVERT_FILTER filter)
{
    UINT32 val;
    UINT16 success, failure;
    UINT i;

    if (CyDivertGetChar(stream) != '_')
    {
        return FALSE;
    }

    if (!CyDivertDeserializeNumber(stream, 2, &val) ||
            val > CYDIVERT_FILTER_FIELD_MAX)
    {
        return FALSE;
    }
    filter->field = (UINT16)val;

    if (!CyDivertDeserializeNumber(stream, 2, &val) ||
            val > CYDIVERT_FILTER_TEST_MAX)
    {
        return FALSE;
    }
    filter->test = (UINT16)val;

    if (!CyDivertDeserializeNumber(stream, 1, &val) || val > 1)
    {
        return FALSE;
    }
    filter->neg = (UINT16)val;

    if (!CyDivertDeserializeNumber(stream, 7, &filter->arg[0]))
    {
        return FALSE;
    }

    switch (filter->field)
    {
        case CYDIVERT_FILTER_FIELD_IPV6_SRCADDR:
        case CYDIVERT_FILTER_FIELD_IPV6_DSTADDR:
        case CYDIVERT_FILTER_FIELD_LOCALADDR:
        case CYDIVERT_FILTER_FIELD_REMOTEADDR:
            for (i = 1; i < 4; i++)
            {
                if (!CyDivertDeserializeNumber(stream, 7, &filter->arg[i]))
                {
                    return FALSE;
                }
            }
            break;
        case CYDIVERT_FILTER_FIELD_ENDPOINTID:
        case CYDIVERT_FILTER_FIELD_PARENTENDPOINTID:
        case CYDIVERT_FILTER_FIELD_TIMESTAMP:
            if (!CyDivertDeserializeNumber(stream, 7, &filter->arg[1]))
            {
                return FALSE;
            }
            filter->arg[2] = filter->arg[3] = 0;
            break;
        case CYDIVERT_FILTER_FIELD_IP_SRCADDR:
        case CYDIVERT_FILTER_FIELD_IP_DSTADDR:
            filter->arg[1] = 0x0000FFFF;
            filter->arg[2] = filter->arg[3] = 0;
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
            if (!CyDivertDeserializeNumber(stream, 7, &val))
            {
                return FALSE;
            }
            filter->arg[1] = (UINT32)((INT)val - UINT16_MAX);
            filter->arg[2] = filter->arg[3] = 0;
            break;
        default:
            filter->arg[1] = filter->arg[2] = filter->arg[3] = 0;
            break;
    }

    if (!CyDivertDeserializeLabel(stream, &success) ||
        !CyDivertDeserializeLabel(stream, &failure))
    {
        return FALSE;
    }
    filter->success = success;
    filter->failure = failure;
    return TRUE;
}

/*
 * Deserialize a filter header.
 */
static BOOL CyDivertDeserializeFilterHeader(PCYDIVERT_STREAM stream,
    UINT *length)
{
    UINT32 version, length32;

    if (CyDivertGetChar(stream) != '@' ||
        CyDivertGetChar(stream) != 'W' ||
        CyDivertGetChar(stream) != 'i' ||
        CyDivertGetChar(stream) != 'n' ||
        CyDivertGetChar(stream) != 'D' ||
        CyDivertGetChar(stream) != 'i' ||
        CyDivertGetChar(stream) != 'v' ||
        CyDivertGetChar(stream) != '_')
    {
        return FALSE;
    }

    if (!CyDivertDeserializeNumber(stream, 4, &version) || (version != 0))
    {
        return FALSE;
    }

    if (!CyDivertDeserializeNumber(stream, 2, &length32) ||
            length32 == 0 || length32 > CYDIVERT_FILTER_MAXLEN)
    {
        return FALSE;
    }
    *length = length32;

    return TRUE;
}

/*
 * Deserialize a filter.
 */
static BOOL CyDivertDeserializeFilter(PCYDIVERT_STREAM stream,
    PCYDIVERT_FILTER filter, UINT *length)
{
    UINT i;

    if (!CyDivertDeserializeFilterHeader(stream, length))
    {
        return FALSE;
    }

    for (i = 0; i < *length; i++)
    {
        if (!CyDivertDeserializeTest(stream, filter + i))
        {
            return FALSE;
        }
        switch (filter[i].success)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (filter[i].success <= i || filter[i].success >= *length)
                {
                    return FALSE;
                }
        }
        switch (filter[i].failure)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (filter[i].failure <= i || filter[i].failure >= *length)
                {
                    return FALSE;
                }
        }
    }

    if (CyDivertGetChar(stream) != '\0')
    {
        return FALSE;
    }

    return TRUE;
}

/*
 * Decompile a test into an expression.
 */
static PEXPR CyDivertDecompileTest(HANDLE pool, PCYDIVERT_FILTER test)
{
    KIND kind;
    PEXPR var, val, expr;
    UINT32 tmp[4];
    ERROR error;

    switch (test->field)
    {
        case CYDIVERT_FILTER_FIELD_ZERO:
            kind = TOKEN_ZERO; break;
        case CYDIVERT_FILTER_FIELD_EVENT:
            kind = TOKEN_EVENT; break;
        case CYDIVERT_FILTER_FIELD_RANDOM8:
            kind = TOKEN_RANDOM8; break;
        case CYDIVERT_FILTER_FIELD_RANDOM16:
            kind = TOKEN_RANDOM16; break;
        case CYDIVERT_FILTER_FIELD_RANDOM32:
            kind = TOKEN_RANDOM32; break;
        case CYDIVERT_FILTER_FIELD_PACKET:
            kind = TOKEN_PACKET; break;
        case CYDIVERT_FILTER_FIELD_PACKET16:
            kind = TOKEN_PACKET16; break;
        case CYDIVERT_FILTER_FIELD_PACKET32:
            kind = TOKEN_PACKET32; break;
        case CYDIVERT_FILTER_FIELD_LENGTH:
            kind = TOKEN_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_TIMESTAMP:
            kind = TOKEN_TIMESTAMP; break;
        case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD:
            kind = TOKEN_TCP_PAYLOAD; break;
        case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
            kind = TOKEN_TCP_PAYLOAD16; break;
        case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32:
            kind = TOKEN_TCP_PAYLOAD32; break;
        case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD:
            kind = TOKEN_UDP_PAYLOAD; break;
        case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
            kind = TOKEN_UDP_PAYLOAD16; break;
        case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32:
            kind = TOKEN_UDP_PAYLOAD32; break;
        case CYDIVERT_FILTER_FIELD_INBOUND:
            kind = TOKEN_INBOUND; break;
        case CYDIVERT_FILTER_FIELD_OUTBOUND:
            kind = TOKEN_OUTBOUND; break;
        case CYDIVERT_FILTER_FIELD_FRAGMENT:
            kind = TOKEN_FRAGMENT; break;
        case CYDIVERT_FILTER_FIELD_IFIDX:
            kind = TOKEN_IF_IDX; break;
        case CYDIVERT_FILTER_FIELD_SUBIFIDX:
            kind = TOKEN_SUB_IF_IDX; break;
        case CYDIVERT_FILTER_FIELD_IP:
            kind = TOKEN_IP; break;
        case CYDIVERT_FILTER_FIELD_IPV6:
            kind = TOKEN_IPV6; break;
        case CYDIVERT_FILTER_FIELD_ICMP:
            kind = TOKEN_ICMP; break;
        case CYDIVERT_FILTER_FIELD_TCP:
            kind = TOKEN_TCP; break;
        case CYDIVERT_FILTER_FIELD_UDP:
            kind = TOKEN_UDP; break;
        case CYDIVERT_FILTER_FIELD_ICMPV6:
            kind = TOKEN_ICMPV6; break;
        case CYDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            kind = TOKEN_IP_HDR_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_IP_TOS:
            kind = TOKEN_IP_TOS; break;
        case CYDIVERT_FILTER_FIELD_IP_LENGTH:
            kind = TOKEN_IP_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_IP_ID:
            kind = TOKEN_IP_ID; break;
        case CYDIVERT_FILTER_FIELD_IP_DF:
            kind = TOKEN_IP_DF; break;
        case CYDIVERT_FILTER_FIELD_IP_MF:
            kind = TOKEN_IP_MF; break;
        case CYDIVERT_FILTER_FIELD_IP_FRAGOFF:
            kind = TOKEN_IP_FRAG_OFF; break;
        case CYDIVERT_FILTER_FIELD_IP_TTL:
            kind = TOKEN_IP_TTL; break;
        case CYDIVERT_FILTER_FIELD_IP_PROTOCOL:
            kind = TOKEN_IP_PROTOCOL; break;
        case CYDIVERT_FILTER_FIELD_IP_CHECKSUM:
            kind = TOKEN_IP_CHECKSUM; break;
        case CYDIVERT_FILTER_FIELD_IP_SRCADDR:
            kind = TOKEN_IP_SRC_ADDR; break;
        case CYDIVERT_FILTER_FIELD_IP_DSTADDR:
            kind = TOKEN_IP_DST_ADDR; break;
        case CYDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            kind = TOKEN_IPV6_TRAFFIC_CLASS; break;
        case CYDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
            kind = TOKEN_IPV6_FLOW_LABEL; break;
        case CYDIVERT_FILTER_FIELD_IPV6_LENGTH:
            kind = TOKEN_IPV6_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            kind = TOKEN_IPV6_NEXT_HDR; break;
        case CYDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            kind = TOKEN_IPV6_HOP_LIMIT; break;
        case CYDIVERT_FILTER_FIELD_IPV6_SRCADDR:
            kind = TOKEN_IPV6_SRC_ADDR; break;
        case CYDIVERT_FILTER_FIELD_IPV6_DSTADDR:
            kind = TOKEN_IPV6_DST_ADDR; break;
        case CYDIVERT_FILTER_FIELD_ICMP_TYPE:
            kind = TOKEN_ICMP_TYPE; break;
        case CYDIVERT_FILTER_FIELD_ICMP_CODE:
            kind = TOKEN_ICMP_CODE; break;
        case CYDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            kind = TOKEN_ICMP_CHECKSUM; break;
        case CYDIVERT_FILTER_FIELD_ICMP_BODY:
            kind = TOKEN_ICMP_BODY; break;
        case CYDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            kind = TOKEN_ICMPV6_TYPE; break;
        case CYDIVERT_FILTER_FIELD_ICMPV6_CODE:
            kind = TOKEN_ICMPV6_CODE; break;
        case CYDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            kind = TOKEN_ICMPV6_CHECKSUM; break;
        case CYDIVERT_FILTER_FIELD_ICMPV6_BODY:
            kind = TOKEN_ICMPV6_BODY; break;
        case CYDIVERT_FILTER_FIELD_TCP_SRCPORT:
            kind = TOKEN_TCP_SRC_PORT; break;
        case CYDIVERT_FILTER_FIELD_TCP_DSTPORT:
            kind = TOKEN_TCP_DST_PORT; break;
        case CYDIVERT_FILTER_FIELD_TCP_SEQNUM:
            kind = TOKEN_TCP_SEQ_NUM; break;
        case CYDIVERT_FILTER_FIELD_TCP_ACKNUM:
            kind = TOKEN_TCP_ACK_NUM; break;
        case CYDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
            kind = TOKEN_TCP_HDR_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_TCP_URG:
            kind = TOKEN_TCP_URG; break;
        case CYDIVERT_FILTER_FIELD_TCP_ACK:
            kind = TOKEN_TCP_ACK; break;
        case CYDIVERT_FILTER_FIELD_TCP_PSH:
            kind = TOKEN_TCP_PSH; break;
        case CYDIVERT_FILTER_FIELD_TCP_RST:
            kind = TOKEN_TCP_RST; break;
        case CYDIVERT_FILTER_FIELD_TCP_SYN:
            kind = TOKEN_TCP_SYN; break;
        case CYDIVERT_FILTER_FIELD_TCP_FIN:
            kind = TOKEN_TCP_FIN; break;
        case CYDIVERT_FILTER_FIELD_TCP_WINDOW:
            kind = TOKEN_TCP_WINDOW; break;
        case CYDIVERT_FILTER_FIELD_TCP_CHECKSUM:
            kind = TOKEN_TCP_CHECKSUM; break;
        case CYDIVERT_FILTER_FIELD_TCP_URGPTR:
            kind = TOKEN_TCP_URG_PTR; break;
        case CYDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
            kind = TOKEN_TCP_PAYLOAD_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_UDP_SRCPORT:
            kind = TOKEN_UDP_SRC_PORT; break;
        case CYDIVERT_FILTER_FIELD_UDP_DSTPORT:
            kind = TOKEN_UDP_DST_PORT; break;
        case CYDIVERT_FILTER_FIELD_UDP_LENGTH:
            kind = TOKEN_UDP_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            kind = TOKEN_UDP_CHECKSUM; break;
        case CYDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
            kind = TOKEN_UDP_PAYLOAD_LENGTH; break;
        case CYDIVERT_FILTER_FIELD_LOOPBACK:
            kind = TOKEN_LOOPBACK; break;
        case CYDIVERT_FILTER_FIELD_IMPOSTOR:
            kind = TOKEN_IMPOSTOR; break;
        case CYDIVERT_FILTER_FIELD_PROCESSID:
            kind = TOKEN_PROCESS_ID; break;
        case CYDIVERT_FILTER_FIELD_LOCALADDR:
            kind = TOKEN_LOCAL_ADDR; break;
        case CYDIVERT_FILTER_FIELD_REMOTEADDR:
            kind = TOKEN_REMOTE_ADDR; break;
        case CYDIVERT_FILTER_FIELD_LOCALPORT:
            kind = TOKEN_LOCAL_PORT; break;
        case CYDIVERT_FILTER_FIELD_REMOTEPORT:
            kind = TOKEN_REMOTE_PORT; break;
        case CYDIVERT_FILTER_FIELD_PROTOCOL:
            kind = TOKEN_PROTOCOL; break;
        case CYDIVERT_FILTER_FIELD_ENDPOINTID:
            kind = TOKEN_ENDPOINT_ID; break;
        case CYDIVERT_FILTER_FIELD_PARENTENDPOINTID:
            kind = TOKEN_PARENT_ENDPOINT_ID; break;
        case CYDIVERT_FILTER_FIELD_LAYER:
            kind = TOKEN_LAYER; break;
        case CYDIVERT_FILTER_FIELD_PRIORITY:
            kind = TOKEN_PRIORITY; break;
        default:
            return NULL;
    }

    switch (kind)
    {
        case TOKEN_PACKET:
        case TOKEN_PACKET16:
        case TOKEN_PACKET32:
        case TOKEN_TCP_PAYLOAD:
        case TOKEN_TCP_PAYLOAD16:
        case TOKEN_TCP_PAYLOAD32:
        case TOKEN_UDP_PAYLOAD:
        case TOKEN_UDP_PAYLOAD16:
        case TOKEN_UDP_PAYLOAD32:
            var = CyDivertMakeArrayVar(pool, kind, test->arg[1], &error);
            if (var == NULL)
            {
                return NULL;
            }
            tmp[0] = test->arg[0];
            tmp[1] = tmp[2] = tmp[3] = 0;
            val = CyDivertMakeNumber(pool, tmp, &error);
            if (val == NULL)
            {
                return NULL;
            }
            break;
        default:
            var = CyDivertMakeVar(kind, &error);
            if (var == NULL)
            {
                return NULL;
            }
            val = CyDivertMakeNumber(pool, test->arg, &error);
            if (val == NULL)
            {
                return NULL;
            }
            if (test->neg)
            {
                val->neg = TRUE;
            }
            break;
    }

    switch (test->test)
    {
        case CYDIVERT_FILTER_TEST_EQ:
            kind = TOKEN_EQ; break;
        case CYDIVERT_FILTER_TEST_NEQ:
            kind = TOKEN_NEQ; break;
        case CYDIVERT_FILTER_TEST_LT:
            kind = TOKEN_LT; break;
        case CYDIVERT_FILTER_TEST_LEQ:
            kind = TOKEN_LEQ; break;
        case CYDIVERT_FILTER_TEST_GT:
            kind = TOKEN_GT; break;
        case CYDIVERT_FILTER_TEST_GEQ:
            kind = TOKEN_GEQ; break;
        default:
            return NULL;
    }

    expr = CyDivertMakeBinOp(pool, kind, var, val, &error);
    if (expr == NULL)
    {
        return NULL;
    }
    expr->succ = test->success;
    expr->fail = test->failure;
    return expr;
}

/*
 * Dereference an expression.
 */
static void CyDivertDerefExpr(PEXPR *exprs, UINT16 i)
{
    switch (i)
    {
        case CYDIVERT_FILTER_RESULT_ACCEPT:
        case CYDIVERT_FILTER_RESULT_REJECT:
            return;
        default:
            exprs[i]->count--;
            if (exprs[i]->count == 0)
            {
                exprs[i] = NULL;
            }
            return;
    }
}

/*
 * Apply an and/or simplification for CyDivertCoalesceAndOr().
 */
static PEXPR CyDivertSimplifyAndOr(HANDLE pool, PEXPR *exprs, PEXPR expr,
    BOOL and, UINT16 next, UINT16 other)
{
    PEXPR next_expr = exprs[next], new_expr;
    ERROR error;

    new_expr = CyDivertMakeBinOp(pool, (and? TOKEN_AND: TOKEN_OR), expr,
        next_expr, &error);
    if (new_expr == NULL)
    {
        return NULL;
    }
    new_expr->succ   = next_expr->succ;
    new_expr->fail   = next_expr->fail;
    new_expr->count  = expr->count;
    CyDivertDerefExpr(exprs, next);
    CyDivertDerefExpr(exprs, other);
    return new_expr;
}

/*
 * Detect and coalesce and/or (& (?:)) expression patterns.
 */
static PEXPR CyDivertCoalesceAndOr(HANDLE pool, PEXPR *exprs, UINT16 i,
    ERROR *error)
{
    PEXPR expr, next_expr, new_expr;
    BOOL singleton;
    static const EXPR true_expr  = {{{0}}, TOKEN_TRUE};
    static const EXPR false_expr = {{{0}}, TOKEN_FALSE};
    
    expr = exprs[i];
    while (TRUE)
    {
        if (expr == NULL || expr->count == 0)
        {
            return NULL;
        }

        singleton = FALSE;
        switch (expr->succ)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                next_expr = exprs[expr->succ];
                if (next_expr->count != 1)
                {
                    break;
                }
                singleton = TRUE;
                if (next_expr->fail == expr->fail)
                {
                    expr = CyDivertSimplifyAndOr(pool, exprs, expr,
                        /*and=*/TRUE, expr->succ, expr->fail);
                    continue;
                }
                else if (next_expr->succ == expr->fail)
                {
                    new_expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY,
                        sizeof(EXPR));
                    if (new_expr == NULL)
                    {
                        return NULL;
                    }
                    new_expr->kind   = TOKEN_QUESTION;
                    new_expr->arg[0] = expr;
                    new_expr->arg[1] = next_expr;
                    new_expr->arg[2] = (PEXPR)&true_expr;
                    new_expr->succ   = next_expr->succ;
                    new_expr->fail   = next_expr->fail;
                    new_expr->count  = expr->count;
                    CyDivertDerefExpr(exprs, expr->succ);
                    CyDivertDerefExpr(exprs, expr->fail);
                    expr = new_expr;
                    continue;
                }
                break;
        }
        switch (expr->fail)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                singleton = FALSE;
                break;
            default:
                next_expr = exprs[expr->fail];
                if (next_expr->count != 1)
                {
                    singleton = FALSE;
                    break;
                }
                if (next_expr->succ == expr->succ)
                {
                    expr = CyDivertSimplifyAndOr(pool, exprs, expr,
                        /*and=*/FALSE, expr->fail, expr->succ);
                    continue;
                }
                else if (next_expr->fail == expr->succ)
                {
                    new_expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY,
                        sizeof(EXPR));
                    if (new_expr == NULL)
                    {
                        return NULL;
                    }
                    new_expr->kind   = TOKEN_QUESTION;
                    new_expr->arg[0] = expr;
                    new_expr->arg[1] = (PEXPR)&false_expr;
                    new_expr->arg[2] = next_expr;
                    new_expr->succ   = next_expr->succ;
                    new_expr->fail   = next_expr->fail;
                    new_expr->count  = expr->count;
                    CyDivertDerefExpr(exprs, expr->succ);
                    CyDivertDerefExpr(exprs, expr->fail);
                    expr = new_expr;
                    continue;
                }
                break;
        }

        if (singleton)
        {
            // Both branches have count==1; simplify into a (?:) expression:
            PEXPR succ_expr, fail_expr;
            succ_expr = exprs[expr->succ];
            fail_expr = exprs[expr->fail];
            if (succ_expr->succ != fail_expr->succ ||
                succ_expr->fail != fail_expr->fail)
            {
                break;
            }
            new_expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
            if (new_expr == NULL)
            {
                return NULL;
            }
            new_expr->kind = TOKEN_QUESTION;
            new_expr->arg[0] = expr;
            new_expr->arg[1] = succ_expr;
            new_expr->arg[2] = fail_expr;
            new_expr->succ   = succ_expr->succ;
            new_expr->fail   = fail_expr->fail;
            new_expr->count  = expr->count;
            CyDivertDerefExpr(exprs, expr->succ);
            CyDivertDerefExpr(exprs, expr->fail);
            CyDivertDerefExpr(exprs, new_expr->succ);
            CyDivertDerefExpr(exprs, new_expr->fail);
            expr = new_expr;
            continue;
        }

        // No simplifications, so we are done.
        break;
    }

    exprs[i] = expr;
    return expr;
}

/*
 * Coalesce all remaining expressions.
 */
static PEXPR CyDivertCoalesceExpr(HANDLE pool, PEXPR *exprs, UINT16 i)
{
    PEXPR expr, succ_expr, fail_expr, new_expr;
    static const EXPR true_expr  = {{{0}}, TOKEN_TRUE};
    static const EXPR false_expr = {{{0}}, TOKEN_FALSE};

    switch (i)
    {
        case CYDIVERT_FILTER_RESULT_ACCEPT:
            return (PEXPR)&true_expr;
        case CYDIVERT_FILTER_RESULT_REJECT:
            return (PEXPR)&false_expr;
        default:
            break;
    }
    
    expr = exprs[i];
    if (expr == NULL)
    {
        return NULL;
    }

    if (expr->succ == expr->fail)
    {
        return CyDivertCoalesceExpr(pool, exprs, expr->succ);
    }

    succ_expr = CyDivertCoalesceExpr(pool, exprs, expr->succ);
    fail_expr = CyDivertCoalesceExpr(pool, exprs, expr->fail);
    if (succ_expr == NULL || fail_expr == NULL)
    {
        return NULL;
    }
    if (succ_expr->kind == TOKEN_TRUE && fail_expr->kind == TOKEN_FALSE)
    {
        return expr;
    }

    new_expr = (PEXPR)HeapAlloc(pool, HEAP_ZERO_MEMORY, sizeof(EXPR));
    if (new_expr == NULL)
    {
        return NULL;
    }

    new_expr->kind = TOKEN_QUESTION;
    new_expr->arg[0] = expr;
    new_expr->arg[1] = succ_expr;
    new_expr->arg[2] = fail_expr;
    return new_expr;
}

/*
 * Format a 32bit decimal number.
 */
static void CyDivertFormatDecNumber32(PCYDIVERT_STREAM stream, UINT32 val)
{
    UINT32 r = 1000000000ul, dig;
    BOOL zeroes = FALSE;

    while (r != 0)
    {
        dig = val / r;
        val = val % r;
        r = r / 10;
        if (dig == 0 && !zeroes && r != 0)
        {
            continue;
        }
        CyDivertPutChar(stream, '0' + dig);
        zeroes = TRUE;
    }
}

/*
 * Format a 128bit decimal number.
 */
static void CyDivertFormatDecNumber(PCYDIVERT_STREAM stream,
    const UINT32 *val0)
{
    UINT32 val[4];
    char buf[40];
    UINT i, j;

    if (val0[0] == 0 && val0[1] == 0 && val0[2] == 0 && val0[3] == 0)
    {
        CyDivertPutChar(stream, '0');
        return;
    }
    val[0] = val0[0];
    val[1] = val0[1];
    val[2] = val0[2];
    val[3] = val0[3];
    for (i = 0; i < sizeof(buf) &&
            (val[0] != 0 || val[1] != 0 || val[2] != 0 || val[3] != 0); i++)
    {
        buf[i] = '0' + CyDivertDivTen128(val);
    }
    for (j = 0; j < i; j++)
    {
        CyDivertPutChar(stream, buf[i - j - 1]);
    }
}

/*
 * Format a 128bit hexidecimal number.
 */
static void CyDivertFormatHexNumber(PCYDIVERT_STREAM stream,
    const UINT32 *val)
{
    INT i, s;
    UINT32 dig;
    BOOL zeroes = FALSE;

    for (i = 3; val[i] == 0 && i >= 1; i--)
        ;
    for (; i >= 0; i--)
    {
        s = 28;
        while (s >= 0)
        {
            dig = (val[i] & ((UINT32)0xF << s)) >> s;
            s -= 4;
            if (dig == 0 && !zeroes)
            {
                continue;
            }
            CyDivertPutChar(stream, (dig <= 9? '0' + dig: 'a' + (dig - 10)));
            zeroes = TRUE;
        }
    }
    if (!zeroes)
    {
        CyDivertPutChar(stream, '0');
    }
}

/*
 * Format an IPv4 address.
 */
static void CyDivertFormatIPv4Addr(PCYDIVERT_STREAM stream, UINT32 addr)
{
    CyDivertFormatDecNumber32(stream, (addr & 0xFF000000) >> 24);
    CyDivertPutChar(stream, '.');
    CyDivertFormatDecNumber32(stream, (addr & 0x00FF0000) >> 16);
    CyDivertPutChar(stream, '.');
    CyDivertFormatDecNumber32(stream, (addr & 0x0000FF00) >> 8);
    CyDivertPutChar(stream, '.');
    CyDivertFormatDecNumber32(stream, (addr & 0x000000FF) >> 0);
}

/*
 * Format an IPv6 address.
 */
static void CyDivertFormatIPv6Addr(PCYDIVERT_STREAM stream,
    const UINT32 *addr32)
{
    INT i, z_curr, z_count, z_start, z_max;
    UINT16 addr[8];
    UINT32 part[4] = {0};

    // IPv4 special case:
    if (addr32[3] == 0 && addr32[2] == 0 && addr32[1] == 0x0000FFFF)
    {
        CyDivertFormatIPv4Addr(stream, addr32[0]);
        return;
    }

    // Find zeroes:
    memcpy(addr, addr32, sizeof(addr));
    z_curr = 7;
    z_count = 0;
    z_start = z_max = -1;
    for (i = 7; i >= 0; i--)
    {
        if (addr[i] == 0)
        {
            z_count++;
            z_start = (z_count > z_max? z_curr: z_start);
            z_max = (z_count > z_max? z_count: z_max);
        }
        else
        {
            z_curr = i-1;
            z_count = 0;
        }
    }

    // Format address:
    for (i = 7; i >= 0; i--)
    {
        if (i == z_start)
        {
            CyDivertPutString(stream, (i == 7? "::": ":"));
            i -= (z_max-1);
            continue;
        }
        part[0] = (UINT32)addr[i];
        CyDivertFormatHexNumber(stream, part);
        CyDivertPutString(stream, (i != 0? ":": ""));
    }
}

/*
 * Format an IPv4 address.
 */
BOOL CyDivertHelperFormatIPv4Address(UINT32 addr, char *buffer, UINT bufLen)
{
    CYDIVERT_STREAM stream;
    stream.data     = buffer;
    stream.pos      = 0;
    stream.max      = bufLen;
    stream.overflow = FALSE;
    CyDivertFormatIPv4Addr(&stream, addr);
    CyDivertPutNul(&stream);
    if (stream.overflow)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

/*
 * Format an IPv6 address.
 */
BOOL CyDivertHelperFormatIPv6Address(const UINT32 *addr, char *buffer,
    UINT bufLen)
{
    CYDIVERT_STREAM stream;
    stream.data     = buffer;
    stream.pos      = 0;
    stream.max      = bufLen;
    stream.overflow = FALSE;
    CyDivertFormatIPv6Addr(&stream, addr);
    CyDivertPutNul(&stream);
    if (stream.overflow)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    return TRUE;
}

/*
 * Format a test expression.
 */
static void CyDivertFormatTestExpr(PCYDIVERT_STREAM stream, PEXPR expr,
    CYDIVERT_LAYER layer)
{
    PEXPR field = expr->arg[0], val = expr->arg[1];
    BOOL is_ipv4_addr = FALSE, is_ipv6_addr = FALSE, is_layer = FALSE,
        is_event = FALSE, is_hex = FALSE;

    switch (field->kind)
    {
        case TOKEN_ZERO:
        case TOKEN_INBOUND:
        case TOKEN_OUTBOUND:
        case TOKEN_FRAGMENT:
        case TOKEN_IP:
        case TOKEN_IPV6:
        case TOKEN_ICMP:
        case TOKEN_TCP:
        case TOKEN_UDP:
        case TOKEN_ICMPV6:
        case TOKEN_IP_DF:
        case TOKEN_IP_MF:
        case TOKEN_TCP_URG:
        case TOKEN_TCP_ACK:
        case TOKEN_TCP_PSH:
        case TOKEN_TCP_RST:
        case TOKEN_TCP_SYN:
        case TOKEN_TCP_FIN:
        case TOKEN_LOOPBACK:
        case TOKEN_IMPOSTOR:
            if (val->val[1] != 0 || val->val[2] != 0 || val->val[3] != 0 ||
                val->val[0] > 1)
            {
                break;
            }
            switch (expr->kind)
            {
                case TOKEN_EQ:
                    CyDivertPutString(stream, (val->val[0] == 0? "not ": ""));
                    CyDivertFormatExpr(stream, field, layer,
                        /*top_level=*/FALSE, /*and=*/FALSE);
                    return;
                case TOKEN_NEQ:
                    CyDivertPutString(stream, (val->val[0] != 0? "not ": ""));
                    CyDivertFormatExpr(stream, field, layer,
                        /*top_level=*/FALSE, /*and=*/FALSE);
                    return;
                default:
                    break;
            }
            break;
        case TOKEN_IP_SRC_ADDR:
        case TOKEN_IP_DST_ADDR:
            is_ipv4_addr = TRUE;
            break;
        case TOKEN_IPV6_SRC_ADDR:
        case TOKEN_IPV6_DST_ADDR:
        case TOKEN_LOCAL_ADDR:
        case TOKEN_REMOTE_ADDR:
            is_ipv6_addr = TRUE;
            break;
        case TOKEN_LAYER:
            is_layer = TRUE;
            break;
        case TOKEN_EVENT:
            is_event = TRUE;
            break;
        case TOKEN_PACKET:
        case TOKEN_PACKET16:
        case TOKEN_PACKET32:
        case TOKEN_IP_ID:
        case TOKEN_IP_CHECKSUM:
        case TOKEN_TCP_CHECKSUM:
        case TOKEN_TCP_PAYLOAD:
        case TOKEN_TCP_PAYLOAD16:
        case TOKEN_TCP_PAYLOAD32:
        case TOKEN_UDP_CHECKSUM:
        case TOKEN_UDP_PAYLOAD:
        case TOKEN_UDP_PAYLOAD16:
        case TOKEN_UDP_PAYLOAD32:
        case TOKEN_ICMP_CHECKSUM:
        case TOKEN_ICMPV6_CHECKSUM:
            is_hex = TRUE;
            break;
        default:
            break;
    }

    CyDivertFormatExpr(stream, field, layer, /*top_level=*/FALSE,
        /*and=*/FALSE);
    switch (expr->kind)
    {
        case TOKEN_EQ:
            CyDivertPutString(stream, " = "); break;
        case TOKEN_NEQ:
            CyDivertPutString(stream, " != "); break;
        case TOKEN_LT:
            CyDivertPutString(stream, " < "); break;
        case TOKEN_LEQ:
            CyDivertPutString(stream, " <= "); break;
        case TOKEN_GT:
            CyDivertPutString(stream, " > "); break;
        case TOKEN_GEQ:
            CyDivertPutString(stream, " >= "); break;
    }
    if (val->neg)
    {
        CyDivertPutChar(stream, '-');
    }
    if (is_ipv4_addr)
    {
        CyDivertFormatIPv4Addr(stream, val->val[0]);
    }
    else if (is_ipv6_addr)
    {
        CyDivertFormatIPv6Addr(stream, val->val);
    }
    else if (is_layer)
    {
        switch (val->val[0])
        {
            case CYDIVERT_LAYER_NETWORK:
                CyDivertPutString(stream, "NETWORK"); break;
            case CYDIVERT_LAYER_NETWORK_FORWARD:
                CyDivertPutString(stream, "NETWORK_FORWARD"); break;
            case CYDIVERT_LAYER_FLOW:
                CyDivertPutString(stream, "FLOW"); break;
            case CYDIVERT_LAYER_SOCKET:
                CyDivertPutString(stream, "SOCKET"); break;
            case CYDIVERT_LAYER_REFLECT:
                CyDivertPutString(stream, "REFLECT"); break;
            default:
                CyDivertFormatDecNumber32(stream, val->val[0]); break;
        }
    }
    else if (is_event)
    {
        switch (layer)
        {
            case CYDIVERT_LAYER_NETWORK:
            case CYDIVERT_LAYER_NETWORK_FORWARD:
                if (val->val[0] == CYDIVERT_EVENT_NETWORK_PACKET)
                {
                    CyDivertPutString(stream, "PACKET");
                }
                else
                {
                    CyDivertFormatDecNumber32(stream, val->val[0]);
                }
                break;
            case CYDIVERT_LAYER_FLOW:
                switch (val->val[0])
                {
                    case CYDIVERT_EVENT_FLOW_ESTABLISHED:
                        CyDivertPutString(stream, "ESTABLISHED"); break;
                    case CYDIVERT_EVENT_FLOW_DELETED:
                        CyDivertPutString(stream, "DELETED"); break;
                    default:
                        CyDivertFormatDecNumber32(stream, val->val[0]); break;
                }
                break;
            case CYDIVERT_LAYER_SOCKET:
                switch (val->val[0])
                {
                    case CYDIVERT_EVENT_SOCKET_BIND:
                        CyDivertPutString(stream, "BIND"); break;
                    case CYDIVERT_EVENT_SOCKET_CONNECT:
                        CyDivertPutString(stream, "CONNECT"); break;
                    case CYDIVERT_EVENT_SOCKET_LISTEN:
                        CyDivertPutString(stream, "LISTEN"); break;
                    case CYDIVERT_EVENT_SOCKET_ACCEPT:
                        CyDivertPutString(stream, "ACCEPT"); break;
                    case CYDIVERT_EVENT_SOCKET_CLOSE:
                        CyDivertPutString(stream, "CLOSE"); break;
                    default:
                        CyDivertFormatDecNumber32(stream, val->val[0]); break;
                }
                break;
            case CYDIVERT_LAYER_REFLECT:
                switch (val->val[0])
                {
                    case CYDIVERT_EVENT_REFLECT_OPEN:
                        CyDivertPutString(stream, "OPEN"); break;
                    case CYDIVERT_EVENT_REFLECT_CLOSE:
                        CyDivertPutString(stream, "CLOSE"); break;
                    default:
                        CyDivertFormatDecNumber32(stream, val->val[0]); break;
                }
                break;
            default:
                CyDivertFormatDecNumber32(stream, val->val[0]); break;
        }
    }
    else if (is_hex)
    {
        CyDivertPutString(stream, "0x");
        CyDivertFormatHexNumber(stream, val->val);
    }
    else
    {
        CyDivertFormatDecNumber(stream, val->val);
    }
}

/*
 * Format an expression.
 */
static void CyDivertFormatExpr(PCYDIVERT_STREAM stream, PEXPR expr,
    CYDIVERT_LAYER layer, BOOL top_level, BOOL and)
{
    INT idx;

    if (stream->pos >= stream->max)
    {
        return;
    }

    switch (expr->kind)
    {
        case TOKEN_AND:
            if (!top_level && !and)
            {
                CyDivertPutChar(stream, '(');
            }
            CyDivertFormatExpr(stream, expr->arg[0], layer,
                /*top_level=*/FALSE, /*and=*/TRUE);
            CyDivertPutString(stream, " and ");
            CyDivertFormatExpr(stream, expr->arg[1], layer,
                /*top_level=*/FALSE, /*and=*/TRUE);
            if (!top_level && !and)
            {
                CyDivertPutChar(stream, ')');
            }
            return;
        case TOKEN_OR:
            if (!top_level && and)
            {
                CyDivertPutChar(stream, '(');
            }
            CyDivertFormatExpr(stream, expr->arg[0], layer,
                /*top_level=*/FALSE, /*and=*/FALSE);
            CyDivertPutString(stream, " or ");
            CyDivertFormatExpr(stream, expr->arg[1], layer,
                /*top_level=*/FALSE, /*and=*/FALSE);
            if (!top_level && and)
            {
                CyDivertPutChar(stream, ')');
            }
            return;
        case TOKEN_QUESTION:
            CyDivertPutChar(stream, '(');
            CyDivertFormatExpr(stream, expr->arg[0], layer,
                /*top_level=*/TRUE, /*and=*/FALSE);
            CyDivertPutString(stream, "? ");
            CyDivertFormatExpr(stream, expr->arg[1], layer,
                /*top_level=*/TRUE, /*and=*/FALSE);
            CyDivertPutString(stream, ": ");
            CyDivertFormatExpr(stream, expr->arg[2], layer,
                /*top_level=*/TRUE, /*and=*/FALSE);
            CyDivertPutChar(stream, ')');
            return;
        case TOKEN_TRUE:
            CyDivertPutString(stream, "true");
            return;
        case TOKEN_FALSE:
            CyDivertPutString(stream, "false");
            return;
        case TOKEN_EQ:
        case TOKEN_NEQ:
        case TOKEN_LT:
        case TOKEN_LEQ:
        case TOKEN_GT:
        case TOKEN_GEQ:
            CyDivertFormatTestExpr(stream, expr, layer);
            return;
        case TOKEN_ZERO:
            CyDivertPutString(stream, "zero"); return;
        case TOKEN_EVENT:
            CyDivertPutString(stream, "event"); return;
        case TOKEN_RANDOM8:
            CyDivertPutString(stream, "random8"); return;
        case TOKEN_RANDOM16:
            CyDivertPutString(stream, "random16"); return;
        case TOKEN_RANDOM32:
            CyDivertPutString(stream, "random32"); return;
        case TOKEN_PACKET:
            CyDivertPutString(stream, "packet"); break;
        case TOKEN_PACKET16:
            CyDivertPutString(stream, "packet16"); break;
        case TOKEN_PACKET32:
            CyDivertPutString(stream, "packet32"); break;
        case TOKEN_LENGTH:
            CyDivertPutString(stream, "length"); return;
        case TOKEN_TIMESTAMP:
            CyDivertPutString(stream, "timestamp"); return;
        case TOKEN_TCP_PAYLOAD:
            CyDivertPutString(stream, "tcp.Payload"); break;
        case TOKEN_TCP_PAYLOAD16:
            CyDivertPutString(stream, "tcp.Payload16"); break;
        case TOKEN_TCP_PAYLOAD32:
            CyDivertPutString(stream, "tcp.Payload32"); break;
        case TOKEN_UDP_PAYLOAD:
            CyDivertPutString(stream, "udp.Payload"); break;
        case TOKEN_UDP_PAYLOAD16:
            CyDivertPutString(stream, "udp.Payload16"); break;
        case TOKEN_UDP_PAYLOAD32:
            CyDivertPutString(stream, "udp.Payload32"); break;
        case TOKEN_INBOUND:
            CyDivertPutString(stream, "inbound"); return;
        case TOKEN_OUTBOUND:
            CyDivertPutString(stream, "outbound"); return;
        case TOKEN_FRAGMENT:
            CyDivertPutString(stream, "fragment"); return;
        case TOKEN_IF_IDX:
            CyDivertPutString(stream, "ifIdx"); return;
        case TOKEN_SUB_IF_IDX:
            CyDivertPutString(stream, "subIfIdx"); return;
        case TOKEN_IP:
            CyDivertPutString(stream, "ip"); return;
        case TOKEN_IPV6:
            CyDivertPutString(stream, "ipv6"); return;
        case TOKEN_ICMP:
            CyDivertPutString(stream, "icmp"); return;
        case TOKEN_TCP:
            CyDivertPutString(stream, "tcp"); return;
        case TOKEN_UDP:
            CyDivertPutString(stream, "udp"); return;
        case TOKEN_ICMPV6:
            CyDivertPutString(stream, "icmpv6"); return;
        case TOKEN_IP_HDR_LENGTH:
            CyDivertPutString(stream, "ip.HdrLength"); return;
        case TOKEN_IP_TOS:
            CyDivertPutString(stream, "ip.TOS"); return;
        case TOKEN_IP_LENGTH:
            CyDivertPutString(stream, "ip.Length"); return;
        case TOKEN_IP_ID:
            CyDivertPutString(stream, "ip.Id"); return;
        case TOKEN_IP_DF:
            CyDivertPutString(stream, "ip.DF"); return;
        case TOKEN_IP_MF:
            CyDivertPutString(stream, "ip.MF"); return;
        case TOKEN_IP_FRAG_OFF:
            CyDivertPutString(stream, "ip.FragOff"); return;
        case TOKEN_IP_TTL:
            CyDivertPutString(stream, "ip.TTL"); return;
        case TOKEN_IP_PROTOCOL:
            CyDivertPutString(stream, "ip.Protocol"); return;
        case TOKEN_IP_CHECKSUM:
            CyDivertPutString(stream, "ip.Checksum"); return;
        case TOKEN_IP_SRC_ADDR:
            CyDivertPutString(stream, "ip.SrcAddr"); return;
        case TOKEN_IP_DST_ADDR:
            CyDivertPutString(stream, "ip.DstAddr"); return;
        case TOKEN_IPV6_TRAFFIC_CLASS:
            CyDivertPutString(stream, "ipv6.TrafficClass"); return;
        case TOKEN_IPV6_FLOW_LABEL:
            CyDivertPutString(stream, "ipv6.FlowLabel"); return;
        case TOKEN_IPV6_LENGTH:
            CyDivertPutString(stream, "ipv6.Length"); return;
        case TOKEN_IPV6_NEXT_HDR:
            CyDivertPutString(stream, "ipv6.NextHdr"); return;
        case TOKEN_IPV6_HOP_LIMIT:
            CyDivertPutString(stream, "ipv6.HopLimit"); return;
        case TOKEN_IPV6_SRC_ADDR:
            CyDivertPutString(stream, "ipv6.SrcAddr"); return;
        case TOKEN_IPV6_DST_ADDR:
            CyDivertPutString(stream, "ipv6.DstAddr"); return;
        case TOKEN_ICMP_TYPE:
            CyDivertPutString(stream, "icmp.Type"); return;
        case TOKEN_ICMP_CODE:
            CyDivertPutString(stream, "icmp.Code"); return;
        case TOKEN_ICMP_CHECKSUM:
            CyDivertPutString(stream, "icmp.Checksum"); return;
        case TOKEN_ICMP_BODY:
            CyDivertPutString(stream, "icmp.Body"); return;
        case TOKEN_ICMPV6_TYPE:
            CyDivertPutString(stream, "icmpv6.Type"); return;
        case TOKEN_ICMPV6_CODE:
            CyDivertPutString(stream, "icmpv6.Code"); return;
        case TOKEN_ICMPV6_CHECKSUM:
            CyDivertPutString(stream, "icmpv6.Checksum"); return;
        case TOKEN_ICMPV6_BODY:
            CyDivertPutString(stream, "icmpv6.Body"); return;
        case TOKEN_TCP_SRC_PORT:
            CyDivertPutString(stream, "tcp.SrcPort"); return;
        case TOKEN_TCP_DST_PORT:
            CyDivertPutString(stream, "tcp.DstPort"); return;
        case TOKEN_TCP_SEQ_NUM:
            CyDivertPutString(stream, "tcp.SeqNum"); return;
        case TOKEN_TCP_ACK_NUM:
            CyDivertPutString(stream, "tcp.AckNum"); return;
        case TOKEN_TCP_HDR_LENGTH:
            CyDivertPutString(stream, "tcp.HdrLength"); return;
        case TOKEN_TCP_URG:
            CyDivertPutString(stream, "tcp.Urg"); return;
        case TOKEN_TCP_ACK:
            CyDivertPutString(stream, "tcp.Ack"); return;
        case TOKEN_TCP_PSH:
            CyDivertPutString(stream, "tcp.Psh"); return;
        case TOKEN_TCP_RST:
            CyDivertPutString(stream, "tcp.Rst"); return;
        case TOKEN_TCP_SYN:
            CyDivertPutString(stream, "tcp.Syn"); return;
        case TOKEN_TCP_FIN:
            CyDivertPutString(stream, "tcp.Fin"); return;
        case TOKEN_TCP_WINDOW:
            CyDivertPutString(stream, "tcp.Window"); return;
        case TOKEN_TCP_CHECKSUM:
            CyDivertPutString(stream, "tcp.Checksum"); return;
        case TOKEN_TCP_URG_PTR:
            CyDivertPutString(stream, "tcp.UrgPtr"); return;
        case TOKEN_TCP_PAYLOAD_LENGTH:
            CyDivertPutString(stream, "tcp.PayloadLength"); return;
        case TOKEN_UDP_SRC_PORT:
            CyDivertPutString(stream, "udp.SrcPort"); return;
        case TOKEN_UDP_DST_PORT:
            CyDivertPutString(stream, "udp.DstPort"); return;
        case TOKEN_UDP_LENGTH:
            CyDivertPutString(stream, "udp.Length"); return;
        case TOKEN_UDP_CHECKSUM:
            CyDivertPutString(stream, "udp.Checksum"); return;
        case TOKEN_UDP_PAYLOAD_LENGTH:
            CyDivertPutString(stream, "udp.PayloadLength"); return;
        case TOKEN_LOOPBACK:
            CyDivertPutString(stream, "loopback"); return;
        case TOKEN_IMPOSTOR:
            CyDivertPutString(stream, "impostor"); return;
        case TOKEN_PROCESS_ID:
            CyDivertPutString(stream, "processId"); return;
        case TOKEN_LOCAL_ADDR:
            CyDivertPutString(stream, "localAddr"); return;
        case TOKEN_REMOTE_ADDR:
            CyDivertPutString(stream, "remoteAddr"); return;
        case TOKEN_LOCAL_PORT:
            CyDivertPutString(stream, "localPort"); return;
        case TOKEN_REMOTE_PORT:
            CyDivertPutString(stream, "remotePort"); return;
        case TOKEN_PROTOCOL:
            CyDivertPutString(stream, "protocol"); return;
        case TOKEN_ENDPOINT_ID:
            CyDivertPutString(stream, "endpointId"); return;
        case TOKEN_PARENT_ENDPOINT_ID:
            CyDivertPutString(stream, "parentEndpointId"); return;
        case TOKEN_LAYER:
            CyDivertPutString(stream, "layer"); return;
        case TOKEN_PRIORITY:
            CyDivertPutString(stream, "priority"); return;
        case TOKEN_NUMBER:
            CyDivertFormatDecNumber(stream, expr->val); return;
    }

    CyDivertPutChar(stream, '[');
    idx = (INT)expr->val[0];
    if (idx < 0)
    {
        CyDivertPutChar(stream, '-');
        idx = -idx;
    }
    CyDivertFormatDecNumber32(stream, (UINT32)idx);
    CyDivertPutString(stream, "b]");
}

/*
 * Format a filter string.
 */
BOOL CyDivertHelperFormatFilter(const char *filter, CYDIVERT_LAYER layer,
    char *buffer, UINT buflen)
{
    PEXPR exprs[CYDIVERT_FILTER_MAXLEN], expr;
    ERROR err;
    DWORD error;
    CYDIVERT_FILTER *object;
    UINT obj_len;
    INT i;
    HANDLE pool;
    CYDIVERT_STREAM stream;

    if (filter == NULL || buffer == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    pool = HeapCreate(HEAP_NO_SERIALIZE, CYDIVERT_MIN_POOL_SIZE,
        CYDIVERT_MAX_POOL_SIZE);
    if (pool == NULL)
    {
        return FALSE;
    }
    object = HeapAlloc(pool, 0,
        CYDIVERT_FILTER_MAXLEN * sizeof(CYDIVERT_FILTER));
    if (object == NULL)
    {
        goto CyDivertHelperFormatFilterError;
    }
    err = CyDivertCompileFilter(filter, pool, layer, object, &obj_len);
    if (IS_ERROR(err))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        goto CyDivertHelperFormatFilterError;
    }

    // Decompile all tests:
    for (i = (INT)obj_len-1; i >= 0; i--)
    {
        expr = CyDivertDecompileTest(pool, object + i);
        if (expr == NULL)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            goto CyDivertHelperFormatFilterError;
        }
        exprs[i] = expr;
        switch (expr->succ)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                exprs[expr->succ]->count++;
                break;
        }
        switch (expr->fail)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                exprs[expr->fail]->count++;
                break;
        }
    }
    exprs[0]->count++;

    // Coalesce (unflatten) tests into and/or expressions:
    for (i = (INT)obj_len-1; i >= 0; i--)
    {
        err = MAKE_ERROR(CYDIVERT_ERROR_NONE, 0);
        (PVOID)CyDivertCoalesceAndOr(pool, exprs, i, &err);
        if (IS_ERROR(err))
        {
            goto CyDivertHelperFormatFilterError;
        }
    }

    // Coalesce remaining expressions:
    expr = CyDivertCoalesceExpr(pool, exprs, 0);
    if (expr == NULL)
    {
        goto CyDivertHelperFormatFilterError;
    }

    // Format the final expression:
    stream.data     = buffer;
    stream.pos      = 0;
    stream.max      = buflen;
    stream.overflow = FALSE;
    CyDivertFormatExpr(&stream, expr, layer, /*top_level=*/TRUE,
        /*and=*/FALSE);
    CyDivertPutNul(&stream);

    // Clean-up:
    HeapDestroy(pool);
    if (!stream.overflow)
    {
        return TRUE;
    }
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;

CyDivertHelperFormatFilterError:
    error = GetLastError();
    HeapDestroy(pool);
    SetLastError(error);
    return FALSE;
}

/*
 * CyDivert packet hash function.
 */
UINT64 CyDivertHelperHashPacket(const VOID *pPacket, UINT packetLen,
    UINT64 seed)
{
    PCYDIVERT_IPHDR ip_header = NULL;
    PCYDIVERT_IPV6HDR ipv6_header = NULL;
    PCYDIVERT_ICMPHDR icmp_header = NULL;
    PCYDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PCYDIVERT_TCPHDR tcp_header = NULL;
    PCYDIVERT_UDPHDR udp_header = NULL;

    if (!CyDivertHelperParsePacket((PVOID)pPacket, packetLen, &ip_header,
            &ipv6_header, NULL, &icmp_header, &icmpv6_header, &tcp_header,
            &udp_header, NULL, NULL, NULL, NULL))
    {
        return 0;
    }
    return CyDivertHashPacket(seed, ip_header, ipv6_header, icmp_header,
        icmpv6_header, tcp_header, udp_header);
}

/*
 * Byte ordering.
 */
UINT16 CyDivertHelperNtohs(UINT16 x)
{
    return BYTESWAP16(x);
}
UINT16 CyDivertHelperHtons(UINT16 x)
{
    return BYTESWAP16(x);
}
UINT32 CyDivertHelperNtohl(UINT32 x)
{
    return BYTESWAP32(x);
}
UINT32 CyDivertHelperHtonl(UINT32 x)
{
    return BYTESWAP32(x);
}
UINT64 CyDivertHelperNtohll(UINT64 x)
{
    return BYTESWAP64(x);
}
UINT64 CyDivertHelperHtonll(UINT64 x)
{
    return BYTESWAP64(x);
}
static void CyDivertByteSwap128(const UINT *inAddr, UINT *outAddr)
{
    UINT32 tmp[4], i;   // tmp[] allows overlapping inAddr/outAddr
    for (i = 0; i < 4; i++)
    {
        tmp[3-i] = BYTESWAP32(inAddr[i]);
    }
    for (i = 0; i < 4; i++)
    {
        outAddr[i] = tmp[i];
    }
}
void CyDivertHelperNtohIPv6Address(const UINT *inAddr, UINT *outAddr)
{
    CyDivertByteSwap128(inAddr, outAddr);
}
void CyDivertHelperHtonIPv6Address(const UINT *inAddr, UINT *outAddr)
{
    CyDivertByteSwap128(inAddr, outAddr);
}

// Old names to be removed in next version
void CyDivertHelperNtohIpv6Address(const UINT *inAddr, UINT *outAddr)
{
    CyDivertByteSwap128(inAddr, outAddr);
}
void CyDivertHelperHtonIpv6Address(const UINT *inAddr, UINT *outAddr)
{
    CyDivertByteSwap128(inAddr, outAddr);
}
