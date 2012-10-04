--[[
	This file represents an interface to the WinSock2
	networking interfaces of the Windows OS.  The functions
	can be found in the .dll:
		ws2_32.dll


--]]

-- WinTypes.h
-- WinBase.h

-- mstcpip.h
-- ws2_32.dll
-- inaddr.h
-- in6addr.h
-- ws2tcpip.h
-- ws2def.h
-- winsock2.h

local ffi = require "ffi"
local bit = require "bit"
local lshift = bit.lshift
local rshift = bit.rshift
local band = bit.band
local bor = bit.bor
local bnot = bit.bnot
local bswap = bit.bswap

require "WinBase"




ffi.cdef[[
typedef uint8_t		u_char;
typedef uint16_t 	u_short;
typedef uint32_t    u_int;
typedef unsigned long   u_long;
typedef uint64_t 	u_int64;

typedef uintptr_t	SOCKET;

typedef uint16_t 	ADDRESS_FAMILY;

typedef unsigned int GROUP;


]]



INVALID_SOCKET 			= ffi.new("SOCKET", -1)
SOCKET_ERROR 			=  0xffffffff


INADDR_ANY             = 0x00000000
INADDR_LOOPBACK        = 0x7f000001
INADDR_BROADCAST       = 0xffffffff
INADDR_NONE            = 0xffffffff

INET_ADDRSTRLEN			= 16
INET6_ADDRSTRLEN		= 46

-- Socket Types
ffi.cdef[[
struct SocketType {
static const int SOCK_STREAM     = 1;    // stream socket
static const int SOCK_DGRAM      = 2;    // datagram socket
static const int SOCK_RAW        = 3;    // raw-protocol interface
static const int SOCK_RDM        = 4;    // reliably-delivered message
static const int SOCK_SEQPACKET  = 5;    // sequenced packet stream
};
]]


-- Address families
AF_UNSPEC 		= 0          -- unspecified */
AF_UNIX 		= 1            -- local to host (pipes, portals) */
AF_INET 		= 2            -- internetwork: UDP, TCP, etc. */
AF_IMPLINK 		= 3         -- arpanet imp addresses */
AF_PUP 			= 4            -- pup protocols: e.g. BSP */
AF_CHAOS 		= 5           -- mit CHAOS protocols */
AF_IPX 			= 6             -- IPX and SPX */
AF_NS 			= 6              -- XEROX NS protocols */
AF_ISO 			= 7             -- ISO protocols */
AF_OSI 			= AF_ISO        -- OSI is ISO */
AF_ECMA 		= 8            -- european computer manufacturers */
AF_DATAKIT 		= 9         -- datakit protocols */
AF_CCITT 		= 10          -- CCITT protocols, X.25 etc */
AF_SNA 			= 11           -- IBM SNA */
AF_DECnet 		= 12         -- DECnet */
AF_DLI 			= 13            -- Direct data link interface */
AF_LAT 			= 14            -- LAT */
AF_HYLINK 		= 15         -- NSC Hyperchannel */
AF_APPLETALK 	= 16      -- AppleTalk */
AF_NETBIOS 		= 17        -- NetBios-style addresses */
AF_VOICEVIEW 	= 18     -- VoiceView */
AF_FIREFOX 		= 19        -- FireFox */
AF_UNKNOWN1 	= 20       -- Somebody is using this! */
AF_BAN 			= 21            -- Banyan */
AF_INET6  		= 23              -- Internetwork Version 6
AF_IRDA   		= 26              -- IrDA

AF_MAX = 33



--
-- Protocols
--

IPPROTO_IP			= 0;		-- dummy for IP
IPPROTO_ICMP		= 1;		-- control message protocol
IPPROTO_IGMP		= 2;		-- group management protocol
IPPROTO_GGP			= 3;		-- gateway^2 (deprecated)
IPPROTO_TCP			= 6;		-- tcp
IPPROTO_PUP			= 12;		-- pup
IPPROTO_UDP			= 17;		-- user datagram protocol
IPPROTO_IDP			= 22;		-- xns idp
IPPROTO_RDP			= 27;
IPPROTO_IPV6		= 41;		-- IPv6 header
IPPROTO_ROUTING		= 43;		-- IPv6 Routing header
IPPROTO_FRAGMENT	= 44;		-- IPv6 fragmentation header
IPPROTO_ESP			= 50;		-- encapsulating security payload
IPPROTO_AH			= 51;		-- authentication header
IPPROTO_ICMPV6		= 58;		-- ICMPv6
IPPROTO_NONE		= 59;		-- IPv6 no next header
IPPROTO_DSTOPTS		= 60;		-- IPv6 Destination options
IPPROTO_ND			= 77;		-- UNOFFICIAL net disk proto
IPPROTO_ICLFXBM		= 78;
IPPROTO_PIM			= 103;
IPPROTO_PGM			= 113;
IPPROTO_RM			= IPPROTO_PGM;
IPPROTO_L2TP		= 115;
IPPROTO_SCTP		= 132;


IPPROTO_RAW          =   255             -- raw IP packet
IPPROTO_MAX          =   256

--
--  These are reserved for internal use by Windows.
--
IPPROTO_RESERVED_RAW = 257
IPPROTO_RESERVED_IPSEC = 258
IPPROTO_RESERVED_IPSECOFFLOAD = 259
IPPROTO_RESERVED_MAX = 260

--
-- Options for use with [gs]etsockopt at the IP level.
--
IP_OPTIONS         = 1;           -- set/get IP per-packet options
IP_MULTICAST_IF    = 2;           -- set/get IP multicast interface
IP_MULTICAST_TTL   = 3;           -- set/get IP multicast timetolive
IP_MULTICAST_LOOP  = 4;           -- set/get IP multicast loopback
IP_ADD_MEMBERSHIP  = 5;           -- add  an IP group membership
IP_DROP_MEMBERSHIP = 6;           -- drop an IP group membership
IP_TTL             = 7;           -- set/get IP Time To Live
IP_TOS             = 8;           -- set/get IP Type Of Service
IP_DONTFRAGMENT    = 9;           -- set/get IP Don't Fragment flag


--[[
/*
 * Commands for ioctlsocket(),  taken from the BSD file fcntl.h.
 *
 *
 * Ioctl's have the command encoded in the lower word,
 * and the size of any in or out parameters in the upper
 * word.  The high 2 bits of the upper word are used
 * to encode the in/out status of the parameter; for now
 * we restrict parameters to at most 128 bytes.
 */
--]]
local IOCPARM_MASK    = 0x7f            -- parameters must be < 128 bytes
local IOC_VOID        = 0x20000000      -- no parameters
local IOC_OUT         = 0x40000000      -- copy out parameters
local IOC_IN          = 0x80000000      -- copy in parameters
local IOC_INOUT       = bor(IOC_IN,IOC_OUT)

-- 0x20000000 distinguishes new and
-- old ioctl's
local function _IO(x,y)
	return bor(IOC_VOID, lshift(x,8), y)
end

local function _IOR(x,y,t)
	return bor(IOC_OUT, lshift(band(ffi.sizeof(t),IOCPARM_MASK), 16), lshift(x,8), y)
end

local function _IOW(x,y,t)
	return bor(IOC_IN, lshift(band(ffi.sizeof(t),IOCPARM_MASK),16), lshift(x,8), y)
end

FIONREAD    = _IOR(string.byte'f', 127, "uint32_t") -- get # bytes to read
FIONBIO     = _IOW(string.byte'f', 126, "uint32_t") -- set/clear non-blocking i/o
FIOASYNC    = _IOW(string.byte'f', 125, "uint32_t") -- set/clear async i/o


--
-- TCP/IP specific Ioctl codes.
--
SIO_GET_INTERFACE_LIST     = _IOR(string.byte't', 127, "uint32_t")
SIO_GET_INTERFACE_LIST_EX  = _IOR(string.byte't', 126, "uint32_t")
SIO_SET_MULTICAST_FILTER   = _IOW(string.byte't', 125, "uint32_t")
SIO_GET_MULTICAST_FILTER   = _IOW(string.byte't', bor(124, IOC_IN), "uint32_t")
SIOCSIPMSFILTER            = SIO_SET_MULTICAST_FILTER
SIOCGIPMSFILTER            = SIO_GET_MULTICAST_FILTER


-- Possible flags for the  iiFlags - bitmask.

IFF_UP              =0x00000001 -- Interface is up.
IFF_BROADCAST       =0x00000002 -- Broadcast is  supported.
IFF_LOOPBACK        =0x00000004 -- This is loopback interface.
IFF_POINTTOPOINT    =0x00000008 -- This is point-to-point interface.
IFF_MULTICAST       =0x00000010 -- Multicast is supported.


--
-- WinSock 2 extension -- manifest constants for WSASocket()
--
WSA_FLAG_OVERLAPPED           	= 0x01
WSA_FLAG_MULTIPOINT_C_ROOT    	= 0x02
WSA_FLAG_MULTIPOINT_C_LEAF    	= 0x04
WSA_FLAG_MULTIPOINT_D_ROOT    	= 0x08
WSA_FLAG_MULTIPOINT_D_LEAF    	= 0x10
WSA_FLAG_ACCESS_SYSTEM_SECURITY = 0x40

-- Error Codes
WSAEFAULT		= 10014
WSAEINVAL		= 10022
WSAEWOULDBLOCK	= 10035
WSAEINPROGRES	= 10036
WSAEALREADY		= 10037
WSAENOTSOCK		= 10038
WSAEAFNOSUPPORT = 10047
WSAECONNABORTED = 10053
WSAECONNRESET 	= 10054
WSAENOBUFS 		= 10055
WSAEISCONN		= 10056
WSAENOTCONN		= 10057
WSAESHUTDOWN	= 10058
WSAETOOMANYREFS = 10059
WSAETIMEDOUT	= 10060
WSAECONNREFUSED = 10061
WSAHOST_NOT_FOUND = 11001

--
--  Flags used in "hints" argument to getaddrinfo()
--      - AI_ADDRCONFIG is supported starting with Vista
--      - default is AI_ADDRCONFIG ON whether the flag is set or not
--        because the performance penalty in not having ADDRCONFIG in
--        the multi-protocol stack environment is severe;
--        this defaulting may be disabled by specifying the AI_ALL flag,
--        in that case AI_ADDRCONFIG must be EXPLICITLY specified to
--        enable ADDRCONFIG behavior
--


AI_PASSIVE                  =0x00000001  -- Socket address will be used in bind() call
AI_CANONNAME                =0x00000002  -- Return canonical name in first ai_canonname
AI_NUMERICHOST              =0x00000004  -- Nodename must be a numeric address string
AI_NUMERICSERV              =0x00000008  -- Servicename must be a numeric port number

AI_ALL                      =0x00000100  -- Query both IP6 and IP4 with AI_V4MAPPED
AI_ADDRCONFIG               =0x00000400  -- Resolution only if global address configured
AI_V4MAPPED                 =0x00000800  -- On v6 failure, query v4 and convert to V4MAPPED format

AI_NON_AUTHORITATIVE        =0x00004000  -- LUP_NON_AUTHORITATIVE
AI_SECURE                   =0x00008000  -- LUP_SECURE
AI_RETURN_PREFERRED_NAMES   =0x00010000  -- LUP_RETURN_PREFERRED_NAMES

AI_FQDN                     =0x00020000  -- Return the FQDN in ai_canonname
AI_FILESERVER               =0x00040000  -- Resolving fileserver name resolution


-- Flags for shutdown()
SD_RECEIVE	= 0
SD_SEND 	= 1
SD_BOTH		= 2

-- for get/setsockopt, the levels can be:
-- IPPROTO_XXX - IP, IPV6, RM, TCP, UDP
-- NSPROTO_IPX
-- SOL_APPLETALK
-- SOL_IRLMP
SOL_SOCKET     = 0xffff          -- options for socket level

-- Option flags per-socket.
SO_DEBUG        = 0x0001          -- turn on debugging info recording
SO_ACCEPTCONN   = 0x0002          -- socket has had listen()
SO_REUSEADDR    = 0x0004          -- allow local address reuse
SO_KEEPALIVE    = 0x0008          -- keep connections alive
SO_DONTROUTE    = 0x0010          -- just use interface addresses
SO_BROADCAST    = 0x0020          -- permit sending of broadcast msgs
SO_USELOOPBACK  = 0x0040          -- bypass hardware when possible
SO_LINGER       = 0x0080          -- linger on close if data present
SO_OOBINLINE    = 0x0100          -- leave received OOB data in line


SO_DONTLINGER 		= bnot(SO_LINGER)
SO_EXCLUSIVEADDRUSE = bnot(SO_REUSEADDR) -- disallow local address reuse


-- Additional options.

SO_SNDBUF     =  0x1001          -- send buffer size
SO_RCVBUF     =  0x1002          -- receive buffer size
SO_SNDLOWAT   =  0x1003          -- send low-water mark
SO_RCVLOWAT   =  0x1004          -- receive low-water mark
SO_SNDTIMEO   =  0x1005          -- send timeout
SO_RCVTIMEO   =  0x1006          -- receive timeout
SO_ERROR      =  0x1007          -- get error status and clear
SO_TYPE       =  0x1008          -- get socket type


--
-- TCP options.
--

TCP_NODELAY     = 0x0001
TCP_KEEPALIVE 	= 0x0003
TCP_BSDURGENT   = 0x7000

-- Event flag definitions for WSAPoll().

POLLRDNORM  = 0x0100
POLLRDBAND  = 0x0200
POLLIN      = bor(POLLRDNORM, POLLRDBAND)
POLLPRI     = 0x0400

POLLWRNORM  = 0x0010
POLLOUT     = POLLWRNORM
POLLWRBAND  = 0x0020

POLLERR     = 0x0001
POLLHUP     = 0x0002
POLLNVAL    = 0x0004



ffi.cdef[[

enum {
	IP_DEFAULT_MULTICAST_TTL  = 1,    /* normally limit m'casts to 1 hop  */
	IP_DEFAULT_MULTICAST_LOOP = 1,    /* normally hear sends if a member  */
	IP_MAX_MEMBERSHIPS        = 20,   /* per socket; must fit in one mbuf */
}


        // Options for connect and disconnect data and options.  Used only by
        // non-TCP/IP transports such as DECNet, OSI TP4, etc.
enum {
            SO_CONNDATA     = 0x7000,
            SO_CONNOPT      = 0x7001,
            SO_DISCDATA     = 0x7002,
            SO_DISCOPT      = 0x7003,
            SO_CONNDATALEN  = 0x7004,
            SO_CONNOPTLEN   = 0x7005,
            SO_DISCDATALEN  = 0x7006,
            SO_DISCOPTLEN   = 0x7007,
};

        /*
         * Option for opening sockets for synchronous access.
         */
enum {
	SO_OPENTYPE             = 0x7008,
	SO_SYNCHRONOUS_ALERT    = 0x10,
	SO_SYNCHRONOUS_NONALERT = 0x20,
};

/*
* Other NT-specific options.
*/
enum {
	SO_MAXDG        = 0x7009,
	SO_MAXPATHDG    = 0x700A,
	SO_UPDATE_ACCEPT_CONTEXT = 0x700B,
	SO_CONNECT_TIME = 0x700C,
};



/*
* WinSock 2 extension -- new options
*/
enum {
	SO_GROUP_ID       = 0x2001,      /* ID of a socket group */
	SO_GROUP_PRIORITY = 0x2002,      /* the relative priority within a group*/
	SO_MAX_MSG_SIZE   = 0x2003,      /* maximum message size */
	SO_PROTOCOL_INFOA = 0x2004,      /* WSAPROTOCOL_INFOA structure */
	SO_PROTOCOL_INFOW = 0x2005,      /* WSAPROTOCOL_INFOW structure */
	SO_PROTOCOL_INFO  = SO_PROTOCOL_INFOW,
	PVD_CONFIG        = 0x3001,       /* configuration info for service provider */
	SO_CONDITIONAL_ACCEPT = 0x3002,   /* enable true conditional accept: */
                                                   /*  connection is not ack-ed to the */
                                       /*  other side until conditional */
                                       /*  function returns CF_ACCEPT */
};


/*
* Maximum queue length specifiable by listen.
*/
enum {
	SOMAXCONN     =  0x7fffffff,
};

enum {
	MSG_OOB         =  0x0001,      /* process out-of-band data */
	MSG_PEEK        =  0x0002,      /* peek at incoming message */
	MSG_DONTROUTE   =  0x0004,      /* send without using routing tables */
	MSG_WAITALL     =  0x0008,      /* do not complete until packet is completely filled */
	MSG_PARTIAL     =  0x8000,      /* partial send or recv for message xport */
	MSG_INTERRUPT   =  0x10,           /* send/recv in the interrupt context */
	MSG_MAXIOVLEN   =  16,
};

/*
* Define constant based on rfc883, used by gethostbyxxxx() calls.
*/
enum {
	MAXGETHOSTSTRUCT  = 1024,
};

enum {
	WSADESCRIPTION_LEN =     256,
	WSASYS_STATUS_LEN  =     128,
};
]]

-- Basic socket definitions
--[[
 s_addr  S_un.S_addr /* can be used for most tcp & ip code */
 s_host  S_un.S_un_b.s_b2    // host on imp
 s_net   S_un.S_un_b.s_b1    // network
 s_imp   S_un.S_un_w.s_w2    // imp
 s_impno S_un.S_un_b.s_b4    // imp #
 s_lh    S_un.S_un_b.s_b3    // logical host
--]]

ffi.cdef[[
typedef struct in_addr {
	union {
		struct {
			uint8_t s_b1,s_b2,s_b3,s_b4;
			} S_un_b;
		struct {
			uint16_t s_w1,s_w2;
		} S_un_w;
		uint32_t S_addr;
	};
} IN_ADDR, *PIN_ADDR, *LPIN_ADDR;
]]

ffi.cdef[[
typedef struct sockaddr {
	ADDRESS_FAMILY	sa_family;
	uint8_t		sa_data[14];
} SOCKADDR, *PSOCKADDR, *LPSOCKADDR;


typedef struct sockaddr_in {
    int16_t		sin_family;
    uint16_t	sin_port;
    IN_ADDR 	sin_addr;
    uint8_t 	sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;
]]

sockaddr = ffi.typeof("struct sockaddr");




ffi.cdef[[
//
// IPv6 Internet address (RFC 2553)
// This is an 'on-wire' format structure.
//
typedef struct in6_addr {
    union {
        uint8_t       Byte[16];
        uint16_t      Word[8];
    } u;
} IN6_ADDR;
typedef struct in6_addr *PIN6_ADDR;
typedef struct in6_addr *LPIN6_ADDR;

typedef struct sockaddr_in6 {
        int16_t				sin6_family;
        uint16_t				sin6_port;
        uint32_t				sin6_flowinfo;
        struct  in6_addr 	sin6_addr;
        uint32_t  			sin6_scope_id;
} sockaddr_in6;

typedef struct sockaddr_in6 SOCKADDR_IN6;
typedef struct sockaddr_in6 *PSOCKADDR_IN6;
typedef struct sockaddr_in6 *LPSOCKADDR_IN6;


//
// Portable socket structure (RFC 2553).
//

enum {
	_SS_MAXSIZE = 128,	// Maximum size
	_SS_ALIGNSIZE = 8,	// (sizeof(__int64))

	_SS_PAD1SIZE = _SS_ALIGNSIZE - 2,
	_SS_PAD2SIZE = _SS_MAXSIZE - (2 + _SS_PAD1SIZE + _SS_ALIGNSIZE)
};


/*
struct sockaddr_storage {  
	sa_family_t ss_family;  
	unsigned long int __ss_align;  
	char __ss_padding[128 - 2 * sizeof(unsigned long int)]; // total length 128 
};

typedef struct sockaddr_storage {
	ADDRESS_FAMILY ss_family;
	char __ss_pad1[_SS_PAD1SIZE];
	int64_t __ss_align;
	char __ss_pad2[_SS_PAD2SIZE];
} SOCKADDR_STORAGE,  *PSOCKADDR_STORAGE;
__attribute__ ((aligned (8)));
*/


typedef struct sockaddr_storage {
	ADDRESS_FAMILY ss_family;
	uint8_t pad[_SS_MAXSIZE-2];
}SOCKADDR_STORAGE;
// __attribute__ ((aligned (8)))
typedef struct sockaddr_storage *PSOCKADDR_STORAGE;



]]


ffi.cdef[[
typedef struct hostent {
	char * h_name;
	char ** h_aliases;
	short h_addrtype;
	short h_length;
	char ** h_addr_list;
} HOSTENT,  *PHOSTENT,  *LPHOSTENT;
]]

ffi.cdef[[
typedef struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	size_t ai_addrlen;
	char* ai_canonname;
	struct sockaddr * ai_addr;
	struct addrinfo* ai_next;
} ADDRINFOA,  *PADDRINFOA;
]]

-- Structure Definitions
ffi.cdef[[
typedef DWORD		WSAEVENT, *LPWSAEVENT;

typedef	HANDLE 		WSAEVENT;
typedef	LPHANDLE	LPWSAEVENT;

typedef OVERLAPPED	WSAOVERLAPPED;
typedef struct _OVERLAPPED *    LPWSAOVERLAPPED;

enum {
	FD_SETSIZE = 64,
};

typedef struct fd_set {
        u_int fd_count;               /* how many are SET? */
        SOCKET  fd_array[FD_SETSIZE];   /* an array of SOCKETs */
} fd_set;

struct timeval {
	long    tv_sec;         /* seconds */
	long    tv_usec;        /* and microseconds */
};

typedef struct WSAData {
        WORD                wVersion;
        WORD                wHighVersion;
        char                szDescription[WSADESCRIPTION_LEN+1];
        char                szSystemStatus[WSASYS_STATUS_LEN+1];
        unsigned short      iMaxSockets;
        unsigned short      iMaxUdpDg;
        char *				lpVendorInfo;
} WSADATA, * LPWSADATA;

typedef struct WSAData64 {
	WORD                wVersion;
	WORD                wHighVersion;
	unsigned short      iMaxSockets;
	unsigned short      iMaxUdpDg;
	char *              lpVendorInfo;
	char                szDescription[WSADESCRIPTION_LEN+1];
	char                szSystemStatus[WSASYS_STATUS_LEN+1];
} WSADATA64, *LPWSADATA64;

/*
 * Structure used for manipulating linger option.
 */
struct  linger {
	u_short l_onoff;                /* option on/off */
	u_short l_linger;               /* linger time */
};


typedef struct __WSABUF {
	u_long len;
	char * buf;
} WSABUF,  *LPWSABUF;

typedef int SERVICETYPE;

typedef struct _flowspec {
	ULONG TokenRate;
	ULONG TokenBucketSize;
	ULONG PeakBandwidth;
	ULONG Latency;
	ULONG DelayVariation;
	SERVICETYPE ServiceType;
	ULONG MaxSduSize;
	ULONG MinimumPolicedSize;
} FLOWSPEC,  *PFLOWSPEC,  *LPFLOWSPEC;

typedef struct _QualityOfService {
	FLOWSPEC SendingFlowspec;
	FLOWSPEC ReceivingFlowspec;
	WSABUF ProviderSpecific;
} QOS,  *LPQOS;

enum {
	MAX_PROTOCOL_CHAIN = 7,
	WSAPROTOCOL_LEN  = 255,
};

typedef struct _WSAPROTOCOLCHAIN {
	int ChainLen;
	DWORD ChainEntries[MAX_PROTOCOL_CHAIN];
} WSAPROTOCOLCHAIN,  *LPWSAPROTOCOLCHAIN;
]]

ffi.cdef[[
typedef struct _WSAPROTOCOL_INFOA {
    DWORD dwServiceFlags1;
    DWORD dwServiceFlags2;
    DWORD dwServiceFlags3;
    DWORD dwServiceFlags4;
    DWORD dwProviderFlags;
    GUID ProviderId;
    DWORD dwCatalogEntryId;
    WSAPROTOCOLCHAIN ProtocolChain;
    int iVersion;
    int iAddressFamily;
    int iMaxSockAddr;
    int iMinSockAddr;
    int iSocketType;
    int iProtocol;
    int iProtocolMaxOffset;
    int iNetworkByteOrder;
    int iSecurityScheme;
    DWORD dwMessageSize;
    DWORD dwProviderReserved;
    CHAR   szProtocol[WSAPROTOCOL_LEN+1];
} WSAPROTOCOL_INFOA,  *LPWSAPROTOCOL_INFOA;
]]

ffi.cdef[[
/*
 * WSAMSG -- for WSASendMsg
 */
typedef struct _WSAMSG {
    LPSOCKADDR       name;
    INT              namelen;
    LPWSABUF         lpBuffers;
    ULONG            dwBufferCount;
    WSABUF           Control;
    ULONG            dwFlags;
} WSAMSG, *PWSAMSG, * LPWSAMSG;
]]


ffi.cdef[[
typedef int (* LPCONDITIONPROC)(
    LPWSABUF lpCallerId,
    LPWSABUF lpCallerData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    LPWSABUF lpCalleeId,
    LPWSABUF lpCalleeData,
    int * g,
    DWORD_PTR dwCallbackData
    );

typedef void (* LPWSAOVERLAPPED_COMPLETION_ROUTINE)(
    DWORD dwError,
    DWORD cbTransferred,
    LPWSAOVERLAPPED lpOverlapped,
    DWORD dwFlags
    );
]]




-- Berkeley Sockets calls
ffi.cdef[[
u_long	htonl(u_long hostlong);
u_short htons(u_short hostshort);
u_short ntohs(u_short netshort);
u_long	ntohl(u_long netlong);

unsigned long inet_addr(const char* cp);
char* inet_ntoa(struct   in_addr in);

int inet_pton(int Family, const char * szAddrString, const void * pAddrBuf);
const char * inet_ntop(int Family, const void *pAddr, intptr_t strptr, size_t len);

SOCKET socket(int af, int type, int protocol);

SOCKET accept(SOCKET s,struct sockaddr* addr,int* addrlen);

int bind(SOCKET s, const struct sockaddr* name, int namelen);

int closesocket(SOCKET s);

int connect(SOCKET s, const struct sockaddr * name, int namelen);

int getsockname(SOCKET s, struct sockaddr* name, int* namelen);

int getsockopt(SOCKET s, int level, int optname, char* optval,int* optlen);

int ioctlsocket(SOCKET s, long cmd, u_long* argp);

int listen(SOCKET s, int backlog);

int recv(SOCKET s, char* buf, int len, int flags);

int recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);

int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout);

int send(SOCKET s, const char* buf, int len, int flags);

int sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);

int setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen);

int shutdown(SOCKET s, int how);



int gethostname(char* name, int namelen);

struct hostent* gethostbyaddr(const char* addr,int len,int type);
struct hostent* gethostbyname(const char* name);

int GetNameInfoA(const struct sockaddr * sa, DWORD salen, char * host, DWORD hostlen, char * serv,DWORD servlen,int flags);
int getaddrinfo(const char* nodename,const char* servname,const struct addrinfo* hints,PADDRINFOA * res);
void freeaddrinfo(PADDRINFOA pAddrInfo);
]]







--[[
function FD_CLR(fd, set)
do {
    local __i;
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count ; __i++) {
        if (((fd_set FAR *)(set))->fd_array[__i] == fd) {
            while (__i < ((fd_set FAR *)(set))->fd_count-1) {
                ((fd_set FAR *)(set))->fd_array[__i] =
                    ((fd_set FAR *)(set))->fd_array[__i+1];
                __i++;
            }
            ((fd_set FAR *)(set))->fd_count--;
            break;
        }
    }
} while(0)
end

function FD_SET(fd, set)
do {
    u_int __i;
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count; __i++) {
        if (((fd_set FAR *)(set))->fd_array[__i] == (fd)) {
            break;
        }
    }
    if (__i == ((fd_set FAR *)(set))->fd_count) {
        if (((fd_set FAR *)(set))->fd_count < FD_SETSIZE) {
            ((fd_set FAR *)(set))->fd_array[__i] = (fd);
            ((fd_set FAR *)(set))->fd_count++;
        }
    }
} while(0)
end
--]]

function FD_ZERO(set)
	set.fd_count = 0
	
	return true
end
--[[
function FD_ISSET(fd, set)
	return __WSAFDIsSet((SOCKET)(fd), (fd_set FAR *)(set))
end
--]]

local wsadata_typename

if ffi.abi("64bit") then
	wsadata_typename = "WSADATA64"

	ffi.cdef[[
		int WSAStartup(WORD wVersionRequested, LPWSADATA64 lpWSAData);
	]]
else
	wsadata_typename = "WSADATA"

	ffi.cdef[[
		int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
	]]
end




ffi.cdef[[
typedef struct pollfd {
    SOCKET		fd;
    int16_t		events;
    int16_t		revents;
} WSAPOLLFD, *PWSAPOLLFD, *LPWSAPOLLFD;

int WSAPoll(LPWSAPOLLFD fdArray, ULONG fds, INT timeout);
]]
WSAPOLLFD = ffi.typeof("WSAPOLLFD")


ffi.cdef[[

SOCKET WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo,
    GROUP g, DWORD dwFlags);

BOOL AcceptEx (SOCKET sListenSocket, SOCKET sAcceptSocket,
	PVOID lpOutputBuffer,
    DWORD dwReceiveDataLength,
    DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength,
    LPDWORD lpdwBytesReceived,
    LPOVERLAPPED lpOverlapped);

int WSAGetLastError();

INT WSARecvEx(SOCKET s, CHAR *buf, INT len, INT *flags);



int WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);


int  WSASendMsg(SOCKET Handle, LPWSAMSG lpMsg, DWORD dwFlags,
    LPDWORD lpNumberOfBytesSent, LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

int WSASendDisconnect(SOCKET s, LPWSABUF lpOutboundDisconnectData);

int WSASendTo(SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr * lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

BOOL WSASetEvent(WSAEVENT hEvent);

INT WSAAddressToStringA(LPSOCKADDR lpsaAddress,
	DWORD dwAddressLength,
	LPWSAPROTOCOL_INFOA lpProtocolInfo,
    LPSTR lpszAddressString,
	LPDWORD lpdwAddressStringLength);

]]


-- General networking interfaces
ffi.cdef[[
//
// Old IPv6 socket address structure (retained for sockaddr_gen definition).
//

struct sockaddr_in6_old {
    int16_t sin6_family;          // AF_INET6.
    uint16_t sin6_port;           // Transport level port number.
    ULONG sin6_flowinfo;        // IPv6 flow information.
    IN6_ADDR sin6_addr;         // IPv6 address.
};

typedef union sockaddr_gen {
    struct sockaddr Address;
    struct sockaddr_in AddressIn;
    struct sockaddr_in6_old AddressIn6;
} sockaddr_gen;

//
// Structure to keep interface specific information
//

typedef struct _INTERFACE_INFO {
    ULONG iiFlags;              // Interface flags.
    sockaddr_gen iiAddress;     // Interface address.
    sockaddr_gen iiBroadcastAddress; // Broadcast address.
    sockaddr_gen iiNetmask;     // Network mask.
} INTERFACE_INFO, *LPINTERFACE_INFO;

int WSAIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);
]]



return {
	wsadata_typename = wsadata_typename,
	
	SocketType = ffi.new("struct SocketType");
}
