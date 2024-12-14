/*
===========================================================================
Copyright (C) 1999-2005 Id Software, Inc.

This file is part of Quake III Arena source code.

Quake III Arena source code is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the License,
or (at your option) any later version.

Quake III Arena source code is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Quake III Arena source code; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
===========================================================================
*/

#include "../qcommon/q_shared.h"
#include "../qcommon/qcommon.h"

#ifdef _WIN32
#	include <winsock2.h>
#	include <ws2tcpip.h>
#	include <afunix.h>
#	if WINVER < 0x501
#		ifdef __MINGW32__
			// wspiapi.h isn't available on MinGW, so if it's
			// present it's because the end user has added it
			// and we should look for it in our tree
#			include "wspiapi.h"
#		else
#			include <wspiapi.h>
#		endif
#	else
#		include <ws2spi.h>
#	endif

typedef int socklen_t;
#	ifdef ADDRESS_FAMILY
#		define sa_family_t	ADDRESS_FAMILY
#	else
typedef unsigned short sa_family_t;
#	endif

#ifndef EAGAIN
#	define EAGAIN			WSAEWOULDBLOCK
#	define EADDRNOTAVAIL	WSAEADDRNOTAVAIL
#	define EAFNOSUPPORT		WSAEAFNOSUPPORT
#	define ECONNRESET		WSAECONNRESET
#endif
typedef u_long	ioctlarg_t;
#	define socketError			WSAGetLastError( )
#	define setSocketError(err)	WSASetLastError(err)

static WSADATA	winsockdata;
static qboolean	winsockInitialized = qfalse;

#else

#	if MAC_OS_X_VERSION_MIN_REQUIRED == 1020
		// needed for socklen_t on OSX 10.2
#		define _BSD_SOCKLEN_T_
#	endif

#	include <sys/socket.h>
#	include <errno.h>
#	include <netdb.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <net/if.h>
#	include <sys/ioctl.h>
#	include <sys/types.h>
#	include <sys/time.h>
#	include <sys/un.h>
#	include <unistd.h>
#	if !defined(__sun) && !defined(__sgi)
#		include <ifaddrs.h>
#	endif

#	ifdef __sun
#		include <sys/filio.h>
#	endif

typedef int SOCKET;
#	define INVALID_SOCKET		-1
#	define SOCKET_ERROR			-1
#	define closesocket			close
#	define ioctlsocket			ioctl
typedef int	ioctlarg_t;
#	define socketError			errno
#	define setSocketError(err)	errno = err

#endif

PanSelector NET_PathSelInit(void);
void NET_PathSelDestroy(void);
PanReplySelector NET_ReplyPathSelInit(void);
void NET_ReplyPathSelDestroy(void);

static qboolean usingSocks = qfalse;
static int networkingEnabled = 0;

static cvar_t	*net_enabled;

static cvar_t	*net_socksEnabled;
static cvar_t	*net_socksServer;
static cvar_t	*net_socksPort;
static cvar_t	*net_socksUsername;
static cvar_t	*net_socksPassword;

static cvar_t	*net_ip;
static cvar_t	*net_ip6;
static cvar_t	*net_scion;
static cvar_t	*net_port;
static cvar_t	*net_port6;
static cvar_t	*net_scion_port;
static cvar_t	*net_mcast6addr;
static cvar_t	*net_mcast6iface;

static cvar_t	*net_dropsim;
static cvar_t	*net_oobTimeout;

static struct sockaddr	socksRelayAddr;

static SOCKET	ip_socket = INVALID_SOCKET;
static SOCKET	ip6_socket = INVALID_SOCKET;
static SOCKET	socks_socket = INVALID_SOCKET;
static SOCKET	multicast6_socket = INVALID_SOCKET;

// SCION server side connection (not connected)
static PanListenConn	scion_server_conn = PAN_INVALID_HANDLE;
static PanListenAdapter	scion_server_adapter = PAN_INVALID_HANDLE;
static SOCKET			scion_server_socket = INVALID_SOCKET;

// SCION client side connection (connected to scion_client_remote)
static netadr_t			scion_client_remote = {0};
static PanConn			scion_client_conn = PAN_INVALID_HANDLE;
static PanConnAdapter	scion_client_adapter = PAN_INVALID_HANDLE;
static SOCKET			scion_client_socket = INVALID_SOCKET;

#define PAN_BUFFER_SIZE 2048

#ifdef PAN_UNIX_STREAM

// Buffer for reassembling packets received from the PAN Unix stream socket.
// Initialize/reset by setting everything to zero.
typedef struct
{
	uint32_t msglen; // expected packet length
	uint32_t recvd;  // number of bytes in buffer
	byte packet[PAN_BUFFER_SIZE];
} stream_buffer_t;

static stream_buffer_t scion_server_buffer = { 0, 0, {0} };
static stream_buffer_t scion_client_buffer = { 0, 0, {0} };

#endif // PAN_UNIX_STREAM

// Pool of temporary SCION sockets for out-of-band messages that cannot be
// handled by scion_server or scion_client connections.
#define MAX_OOB_CONNECTIONS 32
typedef struct
{
	netadr_t		adr;		// remote address, NA_BAD if slot is not in use
	int				last;		// time the connection was last used
	PanConn			conn;		// PAN connection
	PanConnAdapter	adapter;	// Unix socket adapter
	SOCKET			socket;		// Unix socket
#ifdef PAN_UNIX_STREAM
	stream_buffer_t buffer;
#endif
} scion_oob_t;

static scion_oob_t scion_oob[MAX_OOB_CONNECTIONS] = {0};

// Keep track of currently joined multicast group.
static struct ipv6_mreq curgroup;
// And the currently bound address.
static struct sockaddr_in6 boundto;

#ifndef IF_NAMESIZE
  #define IF_NAMESIZE 16
#endif

// use an admin local address per default so that network admins can decide on how to handle quake3 traffic.
#define NET_MULTICAST_IP6 "ff04::696f:7175:616b:6533"

#define	MAX_IPS		32

typedef struct
{
	char ifname[IF_NAMESIZE];

	netadrtype_t type;
	sa_family_t family;
	struct sockaddr_storage addr;
	struct sockaddr_storage netmask;
} nip_localaddr_t;

static nip_localaddr_t localIP[MAX_IPS];
static int numIP;


//=============================================================================


/*
====================
NET_ErrorString
====================
*/
char *NET_ErrorString( void ) {
#ifdef _WIN32
	//FIXME: replace with FormatMessage?
	switch( socketError ) {
		case WSAEINTR: return "WSAEINTR";
		case WSAEBADF: return "WSAEBADF";
		case WSAEACCES: return "WSAEACCES";
		case WSAEDISCON: return "WSAEDISCON";
		case WSAEFAULT: return "WSAEFAULT";
		case WSAEINVAL: return "WSAEINVAL";
		case WSAEMFILE: return "WSAEMFILE";
		case WSAEWOULDBLOCK: return "WSAEWOULDBLOCK";
		case WSAEINPROGRESS: return "WSAEINPROGRESS";
		case WSAEALREADY: return "WSAEALREADY";
		case WSAENOTSOCK: return "WSAENOTSOCK";
		case WSAEDESTADDRREQ: return "WSAEDESTADDRREQ";
		case WSAEMSGSIZE: return "WSAEMSGSIZE";
		case WSAEPROTOTYPE: return "WSAEPROTOTYPE";
		case WSAENOPROTOOPT: return "WSAENOPROTOOPT";
		case WSAEPROTONOSUPPORT: return "WSAEPROTONOSUPPORT";
		case WSAESOCKTNOSUPPORT: return "WSAESOCKTNOSUPPORT";
		case WSAEOPNOTSUPP: return "WSAEOPNOTSUPP";
		case WSAEPFNOSUPPORT: return "WSAEPFNOSUPPORT";
		case WSAEAFNOSUPPORT: return "WSAEAFNOSUPPORT";
		case WSAEADDRINUSE: return "WSAEADDRINUSE";
		case WSAEADDRNOTAVAIL: return "WSAEADDRNOTAVAIL";
		case WSAENETDOWN: return "WSAENETDOWN";
		case WSAENETUNREACH: return "WSAENETUNREACH";
		case WSAENETRESET: return "WSAENETRESET";
		case WSAECONNABORTED: return "WSWSAECONNABORTEDAEINTR";
		case WSAECONNRESET: return "WSAECONNRESET";
		case WSAENOBUFS: return "WSAENOBUFS";
		case WSAEISCONN: return "WSAEISCONN";
		case WSAENOTCONN: return "WSAENOTCONN";
		case WSAESHUTDOWN: return "WSAESHUTDOWN";
		case WSAETOOMANYREFS: return "WSAETOOMANYREFS";
		case WSAETIMEDOUT: return "WSAETIMEDOUT";
		case WSAECONNREFUSED: return "WSAECONNREFUSED";
		case WSAELOOP: return "WSAELOOP";
		case WSAENAMETOOLONG: return "WSAENAMETOOLONG";
		case WSAEHOSTDOWN: return "WSAEHOSTDOWN";
		case WSASYSNOTREADY: return "WSASYSNOTREADY";
		case WSAVERNOTSUPPORTED: return "WSAVERNOTSUPPORTED";
		case WSANOTINITIALISED: return "WSANOTINITIALISED";
		case WSAHOST_NOT_FOUND: return "WSAHOST_NOT_FOUND";
		case WSATRY_AGAIN: return "WSATRY_AGAIN";
		case WSANO_RECOVERY: return "WSANO_RECOVERY";
		case WSANO_DATA: return "WSANO_DATA";
		default: return "NO ERROR";
	}
#else
	return strerror(socketError);
#endif
}

static void NetadrToSockadr( const netadr_t *a, struct sockaddr *s ) {
	if( a->type == NA_BROADCAST ) {
		((struct sockaddr_in *)s)->sin_family = AF_INET;
		((struct sockaddr_in *)s)->sin_port = a->port;
		((struct sockaddr_in *)s)->sin_addr.s_addr = INADDR_BROADCAST;
	}
	else if( a->type == NA_IP ) {
		((struct sockaddr_in *)s)->sin_family = AF_INET;
		((struct sockaddr_in *)s)->sin_addr.s_addr = *(int *)&a->ip;
		((struct sockaddr_in *)s)->sin_port = a->port;
	}
	else if( a->type == NA_IP6 ) {
		((struct sockaddr_in6 *)s)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)s)->sin6_addr = * ((struct in6_addr *) &a->ip6);
		((struct sockaddr_in6 *)s)->sin6_port = a->port;
		((struct sockaddr_in6 *)s)->sin6_scope_id = a->scope_id;
	}
	else if(a->type == NA_MULTICAST6)
	{
		((struct sockaddr_in6 *)s)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)s)->sin6_addr = curgroup.ipv6mr_multiaddr;
		((struct sockaddr_in6 *)s)->sin6_port = a->port;
	}
}


static void SockadrToNetadr( struct sockaddr *s, netadr_t *a ) {
	if (s->sa_family == AF_INET) {
		a->type = NA_IP;
		*(int *)&a->ip = ((struct sockaddr_in *)s)->sin_addr.s_addr;
		a->port = ((struct sockaddr_in *)s)->sin_port;
	}
	else if(s->sa_family == AF_INET6)
	{
		a->type = NA_IP6;
		memcpy(a->ip6, &((struct sockaddr_in6 *)s)->sin6_addr, sizeof(a->ip6));
		a->port = ((struct sockaddr_in6 *)s)->sin6_port;
		a->scope_id = ((struct sockaddr_in6 *)s)->sin6_scope_id;
	}
}


static qboolean ParsePanProxyHdr(byte *header, netadr_t *addr)
{
	memcpy(addr->isd, header, 2);
	memcpy(addr->asn, &header[2], 6);

	uint32_t addr_len = *(uint32_t*)&header[8];

	if (addr_len == 4)
	{
		addr->type = NA_SCION_IP;
		memcpy(addr->ip, &header[12], 4);
		memset(addr->ip6, 0, 16);
	}
	else if (addr_len == 16)
	{
		addr->type = NA_SCION_IP6;
		memset(addr->ip, 0, 4);
		memcpy(addr->ip6, &header[12], 16);
		addr->scope_id = 0;
	}
	else
	{
		Com_Printf("Invalid PAN proxy header\n");
		addr->type = NA_BAD;
		return qfalse;
	}

	// Port is stored as little endian in proxy header and as big-endian in netadr_t
	addr->port = ((uint16_t)header[28] << 8) | (uint16_t)header[29];

	return qtrue;
}


static struct addrinfo *SearchAddrInfo(struct addrinfo *hints, sa_family_t family)
{
	while(hints)
	{
		if(hints->ai_family == family)
			return hints;

		hints = hints->ai_next;
	}

	return NULL;
}

/*
=============
Sys_StringToSockaddr
=============
*/
static qboolean Sys_StringToSockaddr(const char *s, struct sockaddr *sadr, int sadr_len, sa_family_t family)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *search = NULL;
	struct addrinfo *hintsp;
	int retval;

	memset(sadr, '\0', sizeof(*sadr));
	memset(&hints, '\0', sizeof(hints));

	hintsp = &hints;
	hintsp->ai_family = family;
	hintsp->ai_socktype = SOCK_DGRAM;

	retval = getaddrinfo(s, NULL, hintsp, &res);

	if(!retval)
	{
		if(family == AF_UNSPEC)
		{
			// Decide here and now which protocol family to use
			if(net_enabled->integer & NET_PRIOV6)
			{
				if(net_enabled->integer & NET_ENABLEV6)
					search = SearchAddrInfo(res, AF_INET6);

				if(!search && (net_enabled->integer & NET_ENABLEV4))
					search = SearchAddrInfo(res, AF_INET);
			}
			else
			{
				if(net_enabled->integer & NET_ENABLEV4)
					search = SearchAddrInfo(res, AF_INET);

				if(!search && (net_enabled->integer & NET_ENABLEV6))
					search = SearchAddrInfo(res, AF_INET6);
			}
		}
		else
			search = SearchAddrInfo(res, family);

		if(search)
		{
			if(search->ai_addrlen > sadr_len)
				search->ai_addrlen = sadr_len;

			memcpy(sadr, search->ai_addr, search->ai_addrlen);
			freeaddrinfo(res);

			return qtrue;
		}
		else
			Com_Printf("Sys_StringToSockaddr: Error resolving %s: No address of required type found.\n", s);
	}
	else
		Com_Printf("Sys_StringToSockaddr: Error resolving %s: %s\n", s, gai_strerror(retval));

	if(res)
		freeaddrinfo(res);

	return qfalse;
}

/*
=============
Sys_SockaddrToString
=============
*/
static void Sys_SockaddrToString(char *dest, int destlen, struct sockaddr *input)
{
	socklen_t inputlen;

	if (input->sa_family == AF_INET6)
		inputlen = sizeof(struct sockaddr_in6);
	else
		inputlen = sizeof(struct sockaddr_in);

	if(getnameinfo(input, inputlen, dest, destlen, NULL, 0, NI_NUMERICHOST) && destlen > 0)
		*dest = '\0';
}

/*
=============
Sys_StringToAdr

Does not support SCION addresses.
=============
*/
qboolean Sys_StringToAdr(const char *s, netadr_t *a, netadrtype_t family)
{
	assert(family != NA_SCION_IP && family != NA_SCION_IP6);

	struct sockaddr_storage sadr;
	sa_family_t fam;

	switch(family)
	{
		case NA_IP:
			fam = AF_INET;
		break;
		case NA_IP6:
			fam = AF_INET6;
		break;
		default:
			fam = AF_UNSPEC;
		break;
	}
	if( !Sys_StringToSockaddr(s, (struct sockaddr *) &sadr, sizeof(sadr), fam ) ) {
		return qfalse;
	}

	SockadrToNetadr( (struct sockaddr *) &sadr, a );
	return qtrue;
}

/*
===================
NET_CompareBaseAdrMask

Compare without port, and up to the bit number given in netmask.
===================
*/
qboolean NET_CompareBaseAdrMask(const netadr_t *a, const netadr_t *b, int netmask)
{
	byte cmpmask, *addra, *addrb;
	int curbyte;

	if (a->type != b->type)
		return qfalse;

	if (a->type == NA_LOOPBACK)
		return qtrue;

	if (a->type == NA_SCION_IP || a->type == NA_SCION_IP6)
	{
		if (memcmp(a->isd, b->isd, 2) || memcmp(a->asn, b->asn, 6))
			return qfalse;
	}

	if(a->type == NA_IP || a->type == NA_SCION_IP)
	{
		addra = (byte *) &a->ip;
		addrb = (byte *) &b->ip;

		if(netmask < 0 || netmask > 32)
			netmask = 32;
	}
	else if(a->type == NA_IP6 || a->type == NA_SCION_IP6)
	{
		addra = (byte *) &a->ip6;
		addrb = (byte *) &b->ip6;

		if(netmask < 0 || netmask > 128)
			netmask = 128;
	}
	else
	{
		Com_Printf ("NET_CompareBaseAdr: bad address type\n");
		return qfalse;
	}

	curbyte = netmask >> 3;

	if(curbyte && memcmp(addra, addrb, curbyte))
			return qfalse;

	netmask &= 0x07;
	if(netmask)
	{
		cmpmask = (1 << netmask) - 1;
		cmpmask <<= 8 - netmask;

		if((addra[curbyte] & cmpmask) == (addrb[curbyte] & cmpmask))
			return qtrue;
	}
	else
		return qtrue;

	return qfalse;
}


/*
===================
NET_CompareBaseAdr

Compares without the port
===================
*/
qboolean NET_CompareBaseAdr(const netadr_t *a, const netadr_t *b)
{
	return NET_CompareBaseAdrMask(a, b, -1);
}

const char	*NET_AdrToString (const netadr_t *a)
{
	static	char	s[NET_ADDRSTRMAXLEN];

	if (a->type == NA_LOOPBACK)
		Com_sprintf (s, sizeof(s), "loopback");
	else if (a->type == NA_BOT)
		Com_sprintf (s, sizeof(s), "bot");
	else if (a->type == NA_IP || a->type == NA_IP6)
	{
		struct sockaddr_storage sadr;

		memset(&sadr, 0, sizeof(sadr));
		NetadrToSockadr(a, (struct sockaddr *) &sadr);
		Sys_SockaddrToString(s, sizeof(s), (struct sockaddr *) &sadr);
	}
	else if (a->type == NA_SCION_IP || a->type == NA_SCION_IP6)
	{
		ssize_t offset = 0;
		const ssize_t len = sizeof(s);

		// big endian ASN to integer in host byte order
		uint64_t asn = 0;
		for (int i = 0; i < sizeof(a->asn); ++i)
			asn |= (uint64_t)(a->asn[i]) << ((sizeof(a->asn) - i - 1) * 8);

		int ret = 0;
		if (asn < (1ull << 32))
		{
			// decimal ASN
			ret = Com_sprintf(s, len, "%hu-%u,",
				(uint16_t)(a->isd[0] << 8) | (uint16_t)a->isd[1],
				(uint32_t)asn);
			if (ret > 0) offset += ret;
		}
		else
		{
			// hexadecimal ASN
			ret = Com_sprintf(s + offset, len, "%hu-%hx:%hx:%hx,",
				(uint16_t)(a->isd[0] << 8) | (uint16_t)a->isd[1],
				(uint16_t)(asn >> 32),
				(uint16_t)(asn >> 16),
				(uint16_t)(asn));
			if (ret > 0) offset += ret;
		}

		if (a->type == NA_SCION_IP)
		{
			ret = Com_sprintf(s + offset, len - offset, "%hhu.%hhu.%hhu.%hhu",
				a->ip[0], a->ip[1], a->ip[2], a->ip[3]);
			if (ret > 0) offset += ret;
		}
		else
		{
			ret = Com_sprintf(s + offset, len - offset,
				"[%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx]",
				ntohs(*(uint16_t*)&a->ip[ 0]), ntohs(*(uint16_t*)&a->ip[ 2]),
				ntohs(*(uint16_t*)&a->ip[ 4]), ntohs(*(uint16_t*)&a->ip[ 6]),
				ntohs(*(uint16_t*)&a->ip[ 8]), ntohs(*(uint16_t*)&a->ip[10]),
				ntohs(*(uint16_t*)&a->ip[12]), ntohs(*(uint16_t*)&a->ip[14]));
			if (ret > 0) offset += ret;
		}
	}

	return s;
}

const char	*NET_AdrToStringwPort (const netadr_t *a)
{
	static	char	s[NET_ADDRSTRMAXLEN];

	if (a->type == NA_LOOPBACK)
		Com_sprintf (s, sizeof(s), "loopback");
	else if (a->type == NA_BOT)
		Com_sprintf (s, sizeof(s), "bot");
	else if(a->type == NA_IP)
		Com_sprintf(s, sizeof(s), "%s:%hu", NET_AdrToString(a), ntohs(a->port));
	else if(a->type == NA_IP6 || a->type == NA_SCION_IP || a->type == NA_SCION_IP6)
		Com_sprintf(s, sizeof(s), "[%s]:%hu", NET_AdrToString(a), ntohs(a->port));

	return s;
}


qboolean	NET_CompareAdr(const netadr_t *a, const netadr_t *b)
{
	if(!NET_CompareBaseAdr(a, b))
		return qfalse;

	if (a->type == NA_IP || a->type == NA_IP6 || a->type == NA_SCION_IP || a->type == NA_SCION_IP6)
	{
		if (a->port == b->port)
			return qtrue;
	}
	else
		return qtrue;

	return qfalse;
}


qboolean	NET_IsLocalAddress(const netadr_t *adr)
{
	return adr->type == NA_LOOPBACK;
}

//=============================================================================

/*
====================
NET_GetLocalForPan

Get the local address for PAN connections.
====================
*/
void NET_GetLocalForPan(char *addr, int size, qboolean withPort)
{
	int port = withPort ? net_scion_port->integer : 0;
	if (strchr(net_scion->string, ':'))
	{
		// Probably an IPv6 address
		Com_sprintf(addr, size, "[%s]:%d", net_scion->string, port);
	}
	else
	{
		// Probably an IPv4 address
		Com_sprintf(addr, size, "%s:%d", net_scion->string, port);
	}
}

/*
==================
NET_AddressToPan

Create an address handle for the PAN API from a netadr.
==================
*/
PanUDPAddr NET_AddressToPan(const netadr_t *to)
{
	uint8_t ia[8];
	memcpy(&ia[0], to->isd, 2);
	memcpy(&ia[2], to->asn, 6);
	if (to->type == NA_SCION_IP)
		return PanUDPAddrNew((uint64_t*)ia, to->ip, 4, ShortSwap(to->port));
	else
		return PanUDPAddrNew((uint64_t*)ia, to->ip6, 16, ShortSwap(to->port));
}

/*
====================
NET_PanUnixSocket

Create a Unix domain socket pair for asynchronous communication with PAN.
====================
*/
static qboolean NET_PanUnixSocket(
	uintptr_t conn, const char *pan_addr, const char *local_addr,
	uintptr_t *pan_sock, SOCKET *sock, qboolean listen)
{
	PanError err = PAN_ERR_OK;
	ioctlarg_t _true = 1;

	// Create PAN end of Unix socket pair
	if (listen) {
		err = PanNewListenAdapter(conn, pan_addr, local_addr, pan_sock);
		if (err) {
			Com_Printf("WARNING: NET_PanUnixSocket: PanNewListenSockAdapter failed (%d)\n", err);
			return qfalse;
		}
	} else {
		err = PanNewConnAdapter(conn, pan_addr, local_addr, pan_sock);
		if (err) {
			Com_Printf("WARNING: NET_PanUnixSocket: PanNewConnSockAdapter failed (%d)\n", err);
			goto pan_cleanup;
		}
	}

	// Create C end of Unix socket pair
#ifndef PAN_UNIX_STREAM
	*sock = socket(PF_UNIX, SOCK_DGRAM, 0);
#else
	*sock = socket(PF_UNIX, SOCK_STREAM, 0);
#endif
	if (*sock == INVALID_SOCKET) {
		Com_Printf("WARNING: NET_PanUnixSocket: socket: %s\n", NET_ErrorString());
		goto pan_cleanup;
	}

	// Bind C socket
	unlink(local_addr);
	struct sockaddr_un local;
	local.sun_family = AF_UNIX;
	Q_strncpyz (local.sun_path, local_addr, sizeof(local.sun_path));
	if (bind(*sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
		Com_Printf("WARNING: NET_PanUnixSocket: bind: %s\n", NET_ErrorString());
		goto socket_cleanup;
	}

	// Connect our socket to the PAN socket so we can use plain send()
	struct sockaddr_un sockaddr;
	sockaddr.sun_family = AF_UNIX;
	Q_strncpyz (sockaddr.sun_path, pan_addr, sizeof(sockaddr.sun_path));
	if (connect(*sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR) {
		Com_Printf("WARNING: NET_PanUnixSocket: connect: %s\n", NET_ErrorString());
		goto socket_cleanup;
	}

	// Make domain socket non-blocking
	if (ioctlsocket(*sock, FIONBIO, &_true) == SOCKET_ERROR) {
		Com_Printf("WARNING: NET_PanUnixSocket: ioctl FIONBIO: %s\n", NET_ErrorString());
		goto socket_cleanup;
	}

	return qtrue;

socket_cleanup:
	closesocket(*sock);
	*sock = INVALID_SOCKET;
pan_cleanup:
	if (listen)
		PanListenAdapterClose(*pan_sock);
	else
		PanConnAdapterClose(*pan_sock);
	PanDeleteHandle(*pan_sock);
	*pan_sock = PAN_INVALID_HANDLE;
	return qfalse;
}

/*
====================
NET_ClearOOBSlot
====================
*/
static void NET_ClearOOBSlot(int i)
{
	char path[MAX_OSPATH] = {0};

	if (scion_oob[i].adr.type == NA_BAD)
		return;

	if (scion_oob[i].socket)
	{
		closesocket(scion_oob[i].socket);
		Com_sprintf(path, sizeof(path), "%s/ioquake3_%d_oob_%d.sock", Sys_TempPath(), Sys_PID(), i);
		unlink(path);
	}
	if (scion_oob[i].adapter)
	{
		PanConnAdapterClose(scion_oob[i].adapter);
		PanDeleteHandle(scion_oob[i].adapter);
	}
	if (scion_oob[i].conn)
	{
		// conn has already been closed by PanConnAdapterClose
		PanDeleteHandle(scion_oob[i].conn);
	}

	Com_Memset(&scion_oob[i], 0, sizeof(scion_oob_t));
}

/*
====================
NET_OpenOOBConn
====================
*/
static int NET_OpenOOBConn(const netadr_t *to)
{
	PanError err = PAN_ERR_OK;
	char local[NET_ADDRSTRMAXLEN] = {0};
	char pan_addr[MAX_OSPATH] = {0};
	char loc_addr[MAX_OSPATH] = {0};

	if (to->type != NA_SCION_IP && to->type != NA_SCION_IP6)
		return -1;

	// Find a free slot or clear out the least recently used
	scion_oob_t *slot = NULL;
	int i = 0, lru = 0;
	for (; i < MAX_OOB_CONNECTIONS; ++i)
	{
		if (scion_oob[i].adr.type == NA_BAD)
		{
			slot = &scion_oob[i];
			break;
		}
		if (scion_oob[i].last < scion_oob[lru].last)
			lru = i;
	}
	if (!slot) {
		i = lru;
		NET_ClearOOBSlot(i);
		slot = &scion_oob[i];
	}

	// Open connection
	slot->adr = *to;
	slot->last = Sys_Milliseconds();
	NET_GetLocalForPan(local, sizeof(local), qfalse);
	PanUDPAddr addr = NET_AddressToPan(to);
	err = PanDialUDP(local, addr, PAN_INVALID_HANDLE, PAN_INVALID_HANDLE, &slot->conn);
	PanDeleteHandle(addr);
	if (err)
	{
		NET_ClearOOBSlot(i);
		Com_Printf("WARNING: NET_OpenOOBConn: PanDialUDP failed (%d)\n", err);
		return -1;
	}
	PanUDPAddr boundto = PanConnLocalAddr(slot->conn);
	char *str = PanUDPAddrToString(boundto);
	if (str) Com_Printf("Opened OOB connection from %s to %s\n", str, NET_AdrToStringwPort(to));
	free(str);

	const char *tmp = Sys_TempPath();
	int pid = Sys_PID();
	Com_sprintf(pan_addr, sizeof(pan_addr), "%s/ioquake3_%d_oob_pan_%d.sock", tmp, pid, i);
	Com_sprintf(loc_addr, sizeof(loc_addr), "%s/ioquake3_%d_oob_%d.sock", tmp, pid, i);
	if (!NET_PanUnixSocket(slot->conn, pan_addr, loc_addr, &slot->adapter, &slot->socket, qfalse))
	{
		NET_ClearOOBSlot(i);
		return -1;
	}

	return i;
};

/*
====================
NET_PanListenUDP

Listen on a SCION UDP socket.
====================
*/
static PanListenConn NET_PanListenUDP(char *listen_addr)
{
	PanListenConn listen_conn = PAN_INVALID_HANDLE;

	PanError err = PanListenUDP(listen_addr, NET_ReplyPathSelInit(), &listen_conn);
	if (err)
	{
		Com_Printf("WARNING: NET_PanListenUDP: PanListenUDP failed (%d)\n", err);
		return PAN_INVALID_HANDLE;
	}

	PanUDPAddr boundto = PanListenConnLocalAddr(listen_conn);
	char *str = PanUDPAddrToString(boundto);
	if (str) Com_Printf("Opened SCION server socket: %s\n", str);
	free(str);
	PanDeleteHandle(boundto);

	return listen_conn;
}

/*
====================
NET_ScionServerStart

Start listening for SCION packets on the server port.
====================
*/
void NET_ScionServerStart(void)
{
	char local[NET_ADDRSTRMAXLEN] = {0};
	char pan_addr[MAX_OSPATH] = {0};
	char loc_addr[MAX_OSPATH] = {0};

	if(!(net_enabled->integer & NET_ENABLE_SCION))
		return;

	if (scion_server_conn == PAN_INVALID_HANDLE)
	{
		NET_GetLocalForPan(local, sizeof(local), qtrue);
		scion_server_conn = NET_PanListenUDP(local);
		if (scion_server_conn == PAN_INVALID_HANDLE)
		{
			Com_Printf( "WARNING: Couldn't bind to a SCION address.\n");
			return;
		}
	}

	if (scion_server_adapter == PAN_INVALID_HANDLE && scion_server_socket == INVALID_SOCKET)
	{
		const char *tmp = Sys_TempPath();
		int pid = Sys_PID();
		Com_sprintf(pan_addr, sizeof(pan_addr), "%s/ioquake3_%d_server_pan.sock", tmp, pid);
		Com_sprintf(loc_addr, sizeof(loc_addr), "%s/ioquake3_%d_server.sock", tmp, pid);
		if (!NET_PanUnixSocket(scion_server_conn, pan_addr, loc_addr,
				&scion_server_adapter, &scion_server_socket, qtrue)) {
			Com_Printf( "WARNING: Couldn't create PAN domain socket pair.\n");
			PanListenConnClose(scion_server_conn);
			PanDeleteHandle(scion_server_conn);
			scion_server_conn = PAN_INVALID_HANDLE;
		}
	}
}

/*
====================
NET_ScionServerStop

Stop listening for SCION packets on the server port.
====================
*/
void NET_ScionServerStop(void)
{
	char path[MAX_OSPATH] = {0};

	if (scion_server_socket != INVALID_SOCKET) {
		closesocket( scion_server_socket );
		scion_server_socket = INVALID_SOCKET;
		Com_sprintf(path, sizeof(path), "%s/ioquake3_%d_server.sock", Sys_TempPath(), Sys_PID());
		unlink(path);
	}

	if (scion_server_adapter != PAN_INVALID_HANDLE) {
		PanListenAdapterClose( scion_server_adapter );
		PanDeleteHandle ( scion_server_adapter );
		scion_server_adapter = PAN_INVALID_HANDLE;
	}

	if (scion_server_conn != PAN_INVALID_HANDLE) {
		// conn has already been closed by PanListenAdapterClose
		PanDeleteHandle(scion_server_conn);
		scion_server_conn = PAN_INVALID_HANDLE;
		NET_ReplyPathSelDestroy();
	}
}

/*
====================
NET_ScionClientConnect

Open a PAN connection to a server for the client subsystem.
====================
*/
qboolean NET_ScionClientConnect(const netadr_t *to)
{
	PanError err = PAN_ERR_OK;
	char local[NET_ADDRSTRMAXLEN] = {0};
	char pan_addr[MAX_OSPATH];
	char loc_addr[MAX_OSPATH];

	if (!(net_enabled->integer & NET_ENABLE_SCION))
		return qfalse;
	if (scion_client_conn != PAN_INVALID_HANDLE)
		NET_ScionClientClose();

	PanUDPAddr remote = NET_AddressToPan(to);
	if (remote == PAN_INVALID_HANDLE)
		return qfalse;

	PanSelector sel = NET_PathSelInit();
	if (sel == PAN_INVALID_HANDLE)
	{
		PanDeleteHandle(remote);
		return qfalse;
	}

	// Dial SCION
	NET_GetLocalForPan(local, sizeof(local), qtrue);
	err = PanDialUDP(local, remote, PAN_INVALID_HANDLE, sel, &scion_client_conn);
	PanDeleteHandle(remote);
	if (err) {
		Com_Printf("WARNING: NET_ScionClientConnect: PanDialUDP failed (%d)\n", err);
		return qfalse;
	}
	PanUDPAddr boundto = PanConnLocalAddr(scion_client_conn);
	char *str = PanUDPAddrToString(boundto);
	if (str) Com_Printf("Opened SCION client connection from %s to %s\n", str, NET_AdrToStringwPort(to));
	free(str);

	// Create Unix socket pair for dialed PAN connection.
	const char *tmp = Sys_TempPath();
	int pid = Sys_PID();
	Com_sprintf(pan_addr, sizeof(pan_addr), "%s/ioquake3_client_pan_%d.sock", tmp, pid);
	Com_sprintf(loc_addr, sizeof(loc_addr), "%s/ioquake3_client_%d.sock", tmp, pid);
	if (!NET_PanUnixSocket(scion_client_conn, pan_addr, loc_addr,
		 &scion_client_adapter, &scion_client_socket, qfalse)) {
		PanConnClose(scion_client_conn);
		PanDeleteHandle(scion_client_conn);
		scion_client_conn = PAN_INVALID_HANDLE;
		return qfalse;
	}

	scion_client_remote = *to;
	return qtrue;
}

/*
====================
NET_ScionClientClose

Disconnect the client subsystem's PAN connection.
====================
*/
void NET_ScionClientClose(void)
{
	char path[MAX_OSPATH] = {0};

	if (scion_client_socket) {
		closesocket(scion_client_socket);
		scion_client_socket = INVALID_SOCKET;
		Com_sprintf(path, sizeof(path), "%s/ioquake3_client_%d.sock", Sys_TempPath(), Sys_PID());
		unlink(path);
	}

	if (scion_client_adapter != PAN_INVALID_HANDLE) {
		PanConnAdapterClose(scion_client_adapter);
		PanDeleteHandle(scion_client_adapter);
		scion_client_adapter = PAN_INVALID_HANDLE;
	}

	if ( scion_client_conn != PAN_INVALID_HANDLE ) {
		// conn has already been closed by PanConnAdapterClose
		PanDeleteHandle(scion_client_conn);
		scion_client_conn = PAN_INVALID_HANDLE;
	}

	NET_PathSelDestroy();

	Com_Memset(&scion_client_remote, 0, sizeof(scion_client_remote));
}

//=============================================================================

#ifdef PAN_UNIX_STREAM
/*
==================
NET_RecvPktFromStream

Receive a packet from a PAN Unix stream socket. Returns SOCKET_ERROR and sets
errno to EAGAIN if no complete packet was avaialble yet.
==================
*/
int NET_RecvPktFromStream(SOCKET sock, void *pkt, int maxlen, stream_buffer_t *buffer)
{
	int ret = 0;
	uint32_t rem = 0;

	// Receive length header
	if (buffer->msglen == 0)
	{
		rem = PAN_STREAM_HDR_SIZE - buffer->recvd;
		ret = recv(sock, (char*)(&buffer->packet[buffer->recvd]), rem, 0);
		if (ret < 0) return SOCKET_ERROR;

		buffer->recvd += (uint32_t)ret;
		if (buffer->recvd < PAN_STREAM_HDR_SIZE)
		{
			setSocketError(EAGAIN);
			return SOCKET_ERROR;
		}

		memcpy(&buffer->msglen, buffer->packet, PAN_STREAM_HDR_SIZE);
		if (buffer->msglen > MIN(maxlen, PAN_BUFFER_SIZE))
		{
			Com_Printf("ERROR: Oversize packet\n");
			exit(1);
		}
		buffer->recvd = 0;
	}

	// Receive packet
	rem = buffer->msglen - buffer->recvd;
	ret = recv(sock, (char*)&buffer->packet[buffer->recvd], rem, 0);
	if (ret < 0) return SOCKET_ERROR;

	buffer->recvd += (uint32_t)ret;
	if (buffer->recvd < buffer->msglen)
	{
		setSocketError(EAGAIN);
		return SOCKET_ERROR;
	}

	memcpy(pkt, buffer->packet, buffer->recvd);
	ret = (int)buffer->recvd;
	buffer->msglen = 0;
	buffer->recvd = 0;

	return ret;
}
#endif // PAN_UNIX_STREAM

/*
==================
NET_GetPacket

Receive one packet
==================
*/
qboolean NET_GetPacket(netadr_t *net_from, msg_t *net_message, fd_set *fdr)
{
	int						ret;
	struct sockaddr_storage	from;
	socklen_t				fromlen;
	int						err;

	if(ip_socket != INVALID_SOCKET && FD_ISSET(ip_socket, fdr))
	{
		fromlen = sizeof(from);
		ret = recvfrom( ip_socket, (void *)net_message->data, net_message->maxsize, 0, (struct sockaddr *) &from, &fromlen );

		if (ret == SOCKET_ERROR)
		{
			err = socketError;

		#ifdef WIN32
			if (err != WSAEWOULDBLOCK)
		#else
			if (err != EAGAIN && err != ECONNRESET)
		#endif
				Com_Printf( "NET_GetPacket: %s\n", NET_ErrorString() );
		}
		else
		{

			memset( ((struct sockaddr_in *)&from)->sin_zero, 0, 8 );

			if ( usingSocks && memcmp( &from, &socksRelayAddr, fromlen ) == 0 ) {
				if ( ret < 10 || net_message->data[0] != 0 || net_message->data[1] != 0 || net_message->data[2] != 0 || net_message->data[3] != 1 ) {
					return qfalse;
				}
				net_from->type = NA_IP;
				net_from->ip[0] = net_message->data[4];
				net_from->ip[1] = net_message->data[5];
				net_from->ip[2] = net_message->data[6];
				net_from->ip[3] = net_message->data[7];
				net_from->port = *(short *)&net_message->data[8];
				net_message->readcount = 10;
			}
			else {
				SockadrToNetadr( (struct sockaddr *) &from, net_from );
				net_message->readcount = 0;
			}

			if( ret >= net_message->maxsize ) {
				Com_Printf( "Oversize packet from %s\n", NET_AdrToString (net_from) );
				return qfalse;
			}

			net_message->cursize = ret;
			return qtrue;
		}
	}

	if(ip6_socket != INVALID_SOCKET && FD_ISSET(ip6_socket, fdr))
	{
		fromlen = sizeof(from);
		ret = recvfrom(ip6_socket, (void *)net_message->data, net_message->maxsize, 0, (struct sockaddr *) &from, &fromlen);

		if (ret == SOCKET_ERROR)
		{
			err = socketError;

		#ifdef WIN32
			if (err != WSAEWOULDBLOCK)
		#else
			if (err != EAGAIN && err != ECONNRESET)
		#endif
				Com_Printf( "NET_GetPacket: %s\n", NET_ErrorString() );
		}
		else
		{
			SockadrToNetadr((struct sockaddr *) &from, net_from);
			net_message->readcount = 0;

			if(ret >= net_message->maxsize)
			{
				Com_Printf( "Oversize packet from %s\n", NET_AdrToString (net_from) );
				return qfalse;
			}

			net_message->cursize = ret;
			return qtrue;
		}
	}

	if(multicast6_socket != INVALID_SOCKET && multicast6_socket != ip6_socket && FD_ISSET(multicast6_socket, fdr))
	{
		fromlen = sizeof(from);
		ret = recvfrom(multicast6_socket, (void *)net_message->data, net_message->maxsize, 0, (struct sockaddr *) &from, &fromlen);

		if (ret == SOCKET_ERROR)
		{
			err = socketError;

		#ifdef WIN32
			if (err != WSAEWOULDBLOCK)
		#else
			if (err != EAGAIN && err != ECONNRESET)
		#endif
				Com_Printf( "NET_GetPacket: %s\n", NET_ErrorString() );
		}
		else
		{
			SockadrToNetadr((struct sockaddr *) &from, net_from);
			net_message->readcount = 0;

			if(ret >= net_message->maxsize)
			{
				Com_Printf( "Oversize packet from %s\n", NET_AdrToString (net_from) );
				return qfalse;
			}

			net_message->cursize = ret;
			return qtrue;
		}
	}

	if(scion_server_socket != INVALID_SOCKET && FD_ISSET(scion_server_socket, fdr))
	{
		byte packet[PAN_BUFFER_SIZE];

	#ifdef PAN_UNIX_STREAM
		ret = NET_RecvPktFromStream(scion_server_socket, packet, sizeof(packet), &scion_server_buffer);
	#else
		ret = recv(scion_server_socket, packet, sizeof(packet), 0);
	#endif
		if (ret == SOCKET_ERROR)
		{
			err = socketError;

		#ifdef WIN32
			if (err != WSAEWOULDBLOCK)
		#else
			if (err != EAGAIN && err != ECONNRESET)
		#endif
				Com_Printf("NET_GetPacket: %s\n", NET_ErrorString());

			return qfalse;
		}
		else
		{
			if (ret < PAN_ADDR_HDR_SIZE) {
				Com_Printf("Received invalid header from PAN unix socket\n");
				return qfalse;
			}

			int size = ret - PAN_ADDR_HDR_SIZE;
			memcpy(net_message->data, packet + PAN_ADDR_HDR_SIZE, size);
			if (!ParsePanProxyHdr(packet, net_from))
				return qfalse;

			net_message->readcount = 0;

			if (size >= net_message->maxsize) {
				Com_Printf("Oversize packet from %s\n", NET_AdrToString(net_from));
				return qfalse;
			}

			net_message->cursize = size;
			return qtrue;
		}
	}

	if(scion_client_socket != INVALID_SOCKET && FD_ISSET(scion_client_socket, fdr))
	{
	#ifdef PAN_UNIX_STREAM
		ret = NET_RecvPktFromStream(scion_client_socket,
			(void*)net_message->data, net_message->maxsize, &scion_client_buffer);
	#else
		ret = recv(scion_client_socket, (void*)net_message->data, net_message->maxsize, 0);
	#endif
		if (ret == SOCKET_ERROR)
		{
			err = socketError;

		#ifdef WIN32
			if (err != WSAEWOULDBLOCK)
		#else
			if (err != EAGAIN && err != ECONNRESET)
		#endif
				Com_Printf("NET_GetPacket: %s\n", NET_ErrorString());
		}
		else
		{
			*net_from = scion_client_remote;
			net_message->readcount = 0;

			if (ret >= net_message->maxsize) {
				Com_Printf("Oversize packet from %s\n", NET_AdrToString(net_from));
				return qfalse;
			}

			net_message->cursize = ret;
			return qtrue;
		}
	}

	for (int i = 0; i < MAX_OOB_CONNECTIONS; ++i)
	{
		if (scion_oob[i].adr.type == NA_BAD)
			continue;
		if (FD_ISSET(scion_oob[i].socket, fdr))
		{
		#ifdef PAN_UNIX_STREAM
			ret = NET_RecvPktFromStream(scion_oob[i].socket,
				(void*)net_message->data, net_message->maxsize, &scion_oob[i].buffer);
		#else
			ret = recv(scion_oob[i].socket, (void*)net_message->data, net_message->maxsize, 0);
		#endif
			if (ret == SOCKET_ERROR)
			{
				err = socketError;

			#ifdef WIN32
				if (err != WSAEWOULDBLOCK)
			#else
				if (err != EAGAIN && err != ECONNRESET)
			#endif
					Com_Printf("NET_GetPacket: %s\n", NET_ErrorString());
			}
			else
			{
				*net_from = scion_oob[i].adr;
				net_message->readcount = 0;

				if (ret >= net_message->maxsize) {
					Com_Printf("Oversize packet from %s\n", NET_AdrToString(net_from));
					return qfalse;
				}

				net_message->cursize = ret;
				return qtrue;
			}
		}
	}

	return qfalse;
}

//=============================================================================

static char socksBuf[4096];

#ifdef PAN_UNIX_STREAM
/*
==================
Sys_SendPktOnStream

Send a packet on a PAN Unix stream socket. Packet boundaries are preserved by
prepending a 4-byte length header.
==================
*/
int Sys_SendPktOnStream(SOCKET sock, const void *data, int length)
{
	int ret = 0;
	char hdr[PAN_STREAM_HDR_SIZE];
	memcpy(hdr, &length, PAN_STREAM_HDR_SIZE);

	ret = send(sock, hdr, PAN_STREAM_HDR_SIZE, 0);
	if (ret < 0) return ret;
	if (ret < PAN_STREAM_HDR_SIZE)
	{
		Com_Printf("ERROR: PAN Unix stream overflow\n");
		exit(1);
	}

	ret = send(sock, data, length, 0);
	if (ret < length)
	{
		Com_Printf("ERROR: PAN Unix stream overflow\n");
		exit(1);
	}

	return ret;
}
#endif // PAN_UNIX_STREAM

/*
==================
Sys_SendPktPanClientSock

Send a packet on a PAN Unix client socket. Sending on a client socket requires
prepending a path context pointer (pctx) which this function takes care of.
Sending on a PAN Unix server socket requires additional headers and is not
implemented here.
==================
*/
int Sys_SendPktPanClientSock(SOCKET client_sock, PanContext pctx, const void *data, int length)
{
	static char buffer[PAN_BUFFER_SIZE];

	if (length > (PAN_BUFFER_SIZE - PAN_CTX_HDR_SIZE))
	{
		errno = EMSGSIZE;
		return -1;
	}
	memcpy(buffer, &pctx, PAN_CTX_HDR_SIZE);
	memcpy(buffer + PAN_CTX_HDR_SIZE, data, length);

	int msgLen = length + PAN_CTX_HDR_SIZE;
	#ifdef PAN_UNIX_STREAM
		return Sys_SendPktOnStream(client_sock, buffer, msgLen);
	#else
		return send(client_sock, buffer, msgLen, 0);
	#endif
}

/*
==================
Sys_SendPacket
==================
*/
void Sys_SendPacket(int length, const void *data, const netadr_t *to, path_context_t *pctx)
{
	int ret = SOCKET_ERROR;

	if (to->type != NA_BROADCAST && to->type != NA_IP && to->type != NA_IP6 &&
		to->type != NA_MULTICAST6 && to->type != NA_SCION_IP && to->type != NA_SCION_IP6)
	{
		Com_Error( ERR_FATAL, "Sys_SendPacket: bad address type" );
		return;
	}

	if ((to->type == NA_IP && ip_socket == INVALID_SOCKET) ||
		(to->type == NA_BROADCAST && ip_socket == INVALID_SOCKET) ||
		(to->type == NA_IP6 && ip6_socket == INVALID_SOCKET) ||
		(to->type == NA_MULTICAST6 && ip6_socket == INVALID_SOCKET))
		return;

	if(to->type == NA_MULTICAST6 && (net_enabled->integer & NET_DISABLEMCAST))
		return;

	if (to->type == NA_SCION_IP || to->type == NA_SCION_IP6)
	{
		if (!(net_enabled->integer & NET_ENABLE_SCION))
			return;

		qboolean sent = qfalse;
		if (scion_client_socket && NET_CompareBaseAdr(to, &scion_client_remote))
		{
			ret = Sys_SendPktPanClientSock(scion_client_socket, (PanContext)pctx, data, length);
			sent = qtrue;
		}
		if (!sent)
		{
			for (int i = 0; i < MAX_OOB_CONNECTIONS; ++i)
			{
				if (scion_oob[i].adr.type == NA_BAD)
					continue;
				if (NET_CompareAdr(to, &scion_oob[i].adr))
				{
					scion_oob[i].last = Sys_Milliseconds();
					ret = Sys_SendPktPanClientSock(scion_oob[i].socket, (PanContext)pctx, data, length);
					sent = qtrue;
				}
			}
		}
		if (!sent && scion_server_conn)
		{
			PanUDPAddr addr = NET_AddressToPan(to);
			if (PanListenConnWriteToWithCtx(scion_server_conn, (PanContext)pctx, data, length, addr, &ret) == PAN_ERR_OK)
				sent = qtrue;
			PanDeleteHandle(addr);
		}
		if (!sent)
		{
			int i = NET_OpenOOBConn(to);
			if (i >= 0)
			{
				ret = Sys_SendPktPanClientSock(scion_oob[i].socket, (PanContext)pctx, data, length);
				sent = qtrue;
			}
		}
		if (!sent)
		{
			Com_Printf("Sys_SendPacket: Can't send SCION packet to %s\n", NET_AdrToStringwPort(to));
		}
	}
	else
	{
		struct sockaddr_storage	addr;
		memset(&addr, 0, sizeof(addr));
		NetadrToSockadr( to, (struct sockaddr *) &addr );

		if( usingSocks && to->type == NA_IP ) {
			socksBuf[0] = 0;	// reserved
			socksBuf[1] = 0;
			socksBuf[2] = 0;	// fragment (not fragmented)
			socksBuf[3] = 1;	// address type: IPV4
			*(int *)&socksBuf[4] = ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
			*(short *)&socksBuf[8] = ((struct sockaddr_in *)&addr)->sin_port;
			memcpy( &socksBuf[10], data, length );
			ret = sendto( ip_socket, socksBuf, length+10, 0, &socksRelayAddr, sizeof(socksRelayAddr) );
		}
		else {
			if(addr.ss_family == AF_INET)
				ret = sendto( ip_socket, data, length, 0, (struct sockaddr *) &addr, sizeof(struct sockaddr_in) );
			else if(addr.ss_family == AF_INET6)
				ret = sendto( ip6_socket, data, length, 0, (struct sockaddr *) &addr, sizeof(struct sockaddr_in6) );
		}
	}

	if( ret == SOCKET_ERROR ) {
		int err = socketError;

		// wouldblock is silent
		if( err == EAGAIN ) {
			return;
		}

		// some PPP links do not allow broadcasts and return an error
		if( ( err == EADDRNOTAVAIL ) && ( ( to->type == NA_BROADCAST ) ) ) {
			return;
		}

		Com_Printf( "Sys_SendPacket: %s\n", NET_ErrorString() );
	}
}

/*
==================
Sys_SendScionPacketVia

Send a SCION packet via the given path.
==================
*/
qboolean Sys_SendScionPacketVia(int length, const void *data, const netadr_t *to, PanPath path)
{
	PanError err = PAN_ERR_OK;

	if (scion_client_conn && NET_CompareBaseAdr(to, &scion_client_remote))
	{
		err = PanConnWriteVia(scion_client_conn, data, length, path, NULL);
	}
	else if (scion_server_conn)
	{
		PanUDPAddr addr = NET_AddressToPan(to);
		if (addr == PAN_INVALID_HANDLE) return qfalse;
		err = PanListenConnWriteToVia(scion_server_conn, data, length, addr, path, NULL);
		PanDeleteHandle(addr);
	}

	if (err)
	{
		Com_Printf("Sys_SendScionPacketVia: Can't send SCION packet to %s\n",
			NET_AdrToStringwPort(to));
		return qfalse;
	}
	else
		return qtrue;
};

//=============================================================================

/*
==================
Sys_IsLANAddress

LAN clients will have their rate var ignored
==================
*/
qboolean Sys_IsLANAddress( const netadr_t *adr ) {
	int			index, run, addrsize;
	qboolean	differed;
	const byte *compareadr, *comparemask, *compareip;

	if( adr->type == NA_LOOPBACK ) {
		return qtrue;
	}
	if (adr->type == NA_SCION_IP || adr->type == NA_SCION_IP6) {
		return qfalse;
	}

	if( adr->type == NA_IP )
	{
		// RFC1918:
		// 10.0.0.0        -   10.255.255.255  (10/8 prefix)
		// 172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
		// 192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
		if(adr->ip[0] == 10)
			return qtrue;
		if(adr->ip[0] == 172 && (adr->ip[1]&0xf0) == 16)
			return qtrue;
		if(adr->ip[0] == 192 && adr->ip[1] == 168)
			return qtrue;

		if(adr->ip[0] == 127)
			return qtrue;
	}
	else if(adr->type == NA_IP6)
	{
		if(adr->ip6[0] == 0xfe && (adr->ip6[1] & 0xc0) == 0x80)
			return qtrue;
		if((adr->ip6[0] & 0xfe) == 0xfc)
			return qtrue;
	}

	// Now compare against the networks this computer is member of.
	for(index = 0; index < numIP; index++)
	{
		if(localIP[index].type == adr->type)
		{
			if(adr->type == NA_IP)
			{
				compareip = (byte *) &((struct sockaddr_in *) &localIP[index].addr)->sin_addr.s_addr;
				comparemask = (byte *) &((struct sockaddr_in *) &localIP[index].netmask)->sin_addr.s_addr;
				compareadr = adr->ip;

				addrsize = sizeof(adr->ip);
			}
			else
			{
				// TODO? should we check the scope_id here?

				compareip = (byte *) &((struct sockaddr_in6 *) &localIP[index].addr)->sin6_addr;
				comparemask = (byte *) &((struct sockaddr_in6 *) &localIP[index].netmask)->sin6_addr;
				compareadr = adr->ip6;

				addrsize = sizeof(adr->ip6);
			}

			differed = qfalse;
			for(run = 0; run < addrsize; run++)
			{
				if((compareip[run] & comparemask[run]) != (compareadr[run] & comparemask[run]))
				{
					differed = qtrue;
					break;
				}
			}

			if(!differed)
				return qtrue;

		}
	}

	return qfalse;
}

/*
==================
Sys_ShowIP
==================
*/
void Sys_ShowIP(void) {
	int i;
	char addrbuf[NET_ADDRSTRMAXLEN];

	for(i = 0; i < numIP; i++)
	{
		Sys_SockaddrToString(addrbuf, sizeof(addrbuf), (struct sockaddr *) &localIP[i].addr);

		if(localIP[i].type == NA_IP)
			Com_Printf( "IP: %s\n", addrbuf);
		else if(localIP[i].type == NA_IP6)
			Com_Printf( "IP6: %s\n", addrbuf);
	}
}


//=============================================================================


/*
====================
NET_IPSocket
====================
*/
SOCKET NET_IPSocket( char *net_interface, int port, int *err ) {
	SOCKET				newsocket;
	struct sockaddr_in	address;
	ioctlarg_t			_true = 1;
	int					i = 1;

	*err = 0;

	if( net_interface ) {
		Com_Printf( "Opening IP socket: %s:%i\n", net_interface, port );
	}
	else {
		Com_Printf( "Opening IP socket: 0.0.0.0:%i\n", port );
	}

	if( ( newsocket = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP ) ) == INVALID_SOCKET ) {
		*err = socketError;
		Com_Printf( "WARNING: NET_IPSocket: socket: %s\n", NET_ErrorString() );
		return newsocket;
	}
	// make it non-blocking
	if( ioctlsocket( newsocket, FIONBIO, &_true ) == SOCKET_ERROR ) {
		Com_Printf( "WARNING: NET_IPSocket: ioctl FIONBIO: %s\n", NET_ErrorString() );
		*err = socketError;
		closesocket(newsocket);
		return INVALID_SOCKET;
	}

	// make it broadcast capable
	if( setsockopt( newsocket, SOL_SOCKET, SO_BROADCAST, (char *) &i, sizeof(i) ) == SOCKET_ERROR ) {
		Com_Printf( "WARNING: NET_IPSocket: setsockopt SO_BROADCAST: %s\n", NET_ErrorString() );
	}

	if( !net_interface || !net_interface[0]) {
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = INADDR_ANY;
	}
	else
	{
		if(!Sys_StringToSockaddr( net_interface, (struct sockaddr *)&address, sizeof(address), AF_INET))
		{
			closesocket(newsocket);
			return INVALID_SOCKET;
		}
	}

	if( port == PORT_ANY ) {
		address.sin_port = 0;
	}
	else {
		address.sin_port = htons( (short)port );
	}

	if( bind( newsocket, (void *)&address, sizeof(address) ) == SOCKET_ERROR ) {
		Com_Printf( "WARNING: NET_IPSocket: bind: %s\n", NET_ErrorString() );
		*err = socketError;
		closesocket( newsocket );
		return INVALID_SOCKET;
	}

	return newsocket;
}

/*
====================
NET_IP6Socket
====================
*/
SOCKET NET_IP6Socket( char *net_interface, int port, struct sockaddr_in6 *bindto, int *err ) {
	SOCKET				newsocket;
	struct sockaddr_in6	address;
	ioctlarg_t			_true = 1;

	*err = 0;

	if( net_interface )
	{
		// Print the name in brackets if there is a colon:
		if(Q_CountChar(net_interface, ':'))
			Com_Printf( "Opening IP6 socket: [%s]:%i\n", net_interface, port );
		else
			Com_Printf( "Opening IP6 socket: %s:%i\n", net_interface, port );
	}
	else
		Com_Printf( "Opening IP6 socket: [::]:%i\n", port );

	if( ( newsocket = socket( PF_INET6, SOCK_DGRAM, IPPROTO_UDP ) ) == INVALID_SOCKET ) {
		*err = socketError;
		Com_Printf( "WARNING: NET_IP6Socket: socket: %s\n", NET_ErrorString() );
		return newsocket;
	}

	// make it non-blocking
	if( ioctlsocket( newsocket, FIONBIO, &_true ) == SOCKET_ERROR ) {
		Com_Printf( "WARNING: NET_IP6Socket: ioctl FIONBIO: %s\n", NET_ErrorString() );
		*err = socketError;
		closesocket(newsocket);
		return INVALID_SOCKET;
	}

#ifdef IPV6_V6ONLY
	{
		int i = 1;

		// ipv4 addresses should not be allowed to connect via this socket.
		if(setsockopt(newsocket, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &i, sizeof(i)) == SOCKET_ERROR)
		{
			// win32 systems don't seem to support this anyways.
			Com_DPrintf("WARNING: NET_IP6Socket: setsockopt IPV6_V6ONLY: %s\n", NET_ErrorString());
		}
	}
#endif

	if( !net_interface || !net_interface[0]) {
		address.sin6_family = AF_INET6;
		address.sin6_addr = in6addr_any;
	}
	else
	{
		if(!Sys_StringToSockaddr( net_interface, (struct sockaddr *)&address, sizeof(address), AF_INET6))
		{
			closesocket(newsocket);
			return INVALID_SOCKET;
		}
	}

	if( port == PORT_ANY ) {
		address.sin6_port = 0;
	}
	else {
		address.sin6_port = htons( (short)port );
	}

	if( bind( newsocket, (void *)&address, sizeof(address) ) == SOCKET_ERROR ) {
		Com_Printf( "WARNING: NET_IP6Socket: bind: %s\n", NET_ErrorString() );
		*err = socketError;
		closesocket( newsocket );
		return INVALID_SOCKET;
	}

	if(bindto)
		*bindto = address;

	return newsocket;
}

/*
====================
NET_SetMulticast
Set the current multicast group
====================
*/
void NET_SetMulticast6(void)
{
	struct sockaddr_in6 addr;

	if(!*net_mcast6addr->string || !Sys_StringToSockaddr(net_mcast6addr->string, (struct sockaddr *) &addr, sizeof(addr), AF_INET6))
	{
		Com_Printf("WARNING: NET_JoinMulticast6: Incorrect multicast address given, "
			   "please set cvar %s to a sane value.\n", net_mcast6addr->name);

		Cvar_SetValue(net_enabled->name, net_enabled->integer | NET_DISABLEMCAST);

		return;
	}

	memcpy(&curgroup.ipv6mr_multiaddr, &addr.sin6_addr, sizeof(curgroup.ipv6mr_multiaddr));

	if(*net_mcast6iface->string)
	{
#ifdef _WIN32
		curgroup.ipv6mr_interface = net_mcast6iface->integer;
#else
		curgroup.ipv6mr_interface = if_nametoindex(net_mcast6iface->string);
#endif
	}
	else
		curgroup.ipv6mr_interface = 0;
}

/*
====================
NET_JoinMulticast
Join an ipv6 multicast group
====================
*/
void NET_JoinMulticast6(void)
{
	int err;

	if(ip6_socket == INVALID_SOCKET || multicast6_socket != INVALID_SOCKET || (net_enabled->integer & NET_DISABLEMCAST))
		return;

	if(IN6_IS_ADDR_MULTICAST(&boundto.sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&boundto.sin6_addr))
	{
		// The way the socket was bound does not prohibit receiving multi-cast packets. So we don't need to open a new one.
		multicast6_socket = ip6_socket;
	}
	else
	{
		if((multicast6_socket = NET_IP6Socket(net_mcast6addr->string, ntohs(boundto.sin6_port), NULL, &err)) == INVALID_SOCKET)
		{
			// If the OS does not support binding to multicast addresses, like WinXP, at least try with the normal file descriptor.
			multicast6_socket = ip6_socket;
		}
	}

	if(curgroup.ipv6mr_interface)
	{
		if (setsockopt(multicast6_socket, IPPROTO_IPV6, IPV6_MULTICAST_IF,
					(char *) &curgroup.ipv6mr_interface, sizeof(curgroup.ipv6mr_interface)) < 0)
		{
			Com_Printf("NET_JoinMulticast6: Couldn't set scope on multicast socket: %s\n", NET_ErrorString());

			if(multicast6_socket != ip6_socket)
			{
				closesocket(multicast6_socket);
				multicast6_socket = INVALID_SOCKET;
				return;
			}
		}
	}

	if (setsockopt(multicast6_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *) &curgroup, sizeof(curgroup)))
	{
		Com_Printf("NET_JoinMulticast6: Couldn't join multicast group: %s\n", NET_ErrorString());

		if(multicast6_socket != ip6_socket)
		{
			closesocket(multicast6_socket);
			multicast6_socket = INVALID_SOCKET;
			return;
		}
	}
}

void NET_LeaveMulticast6()
{
	if(multicast6_socket != INVALID_SOCKET)
	{
		if(multicast6_socket != ip6_socket)
			closesocket(multicast6_socket);
		else
			setsockopt(multicast6_socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP, (char *) &curgroup, sizeof(curgroup));

		multicast6_socket = INVALID_SOCKET;
	}
}

/*
====================
NET_OpenSocks
====================
*/
void NET_OpenSocks( int port ) {
	struct sockaddr_in	address;
	struct hostent		*h;
	int					len;
	qboolean			rfc1929;
	unsigned char		buf[64];

	usingSocks = qfalse;

	Com_Printf( "Opening connection to SOCKS server.\n" );

	if ( ( socks_socket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) ) == INVALID_SOCKET ) {
		Com_Printf( "WARNING: NET_OpenSocks: socket: %s\n", NET_ErrorString() );
		return;
	}

	h = gethostbyname( net_socksServer->string );
	if ( h == NULL ) {
		Com_Printf( "WARNING: NET_OpenSocks: gethostbyname: %s\n", NET_ErrorString() );
		return;
	}
	if ( h->h_addrtype != AF_INET ) {
		Com_Printf( "WARNING: NET_OpenSocks: gethostbyname: address type was not AF_INET\n" );
		return;
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = *(int *)h->h_addr_list[0];
	address.sin_port = htons( (short)net_socksPort->integer );

	if ( connect( socks_socket, (struct sockaddr *)&address, sizeof( address ) ) == SOCKET_ERROR ) {
		Com_Printf( "NET_OpenSocks: connect: %s\n", NET_ErrorString() );
		return;
	}

	// send socks authentication handshake
	if ( *net_socksUsername->string || *net_socksPassword->string ) {
		rfc1929 = qtrue;
	}
	else {
		rfc1929 = qfalse;
	}

	buf[0] = 5;		// SOCKS version
	// method count
	if ( rfc1929 ) {
		buf[1] = 2;
		len = 4;
	}
	else {
		buf[1] = 1;
		len = 3;
	}
	buf[2] = 0;		// method #1 - method id #00: no authentication
	if ( rfc1929 ) {
		buf[2] = 2;		// method #2 - method id #02: username/password
	}
	if ( send( socks_socket, (void *)buf, len, 0 ) == SOCKET_ERROR ) {
		Com_Printf( "NET_OpenSocks: send: %s\n", NET_ErrorString() );
		return;
	}

	// get the response
	len = recv( socks_socket, (void *)buf, 64, 0 );
	if ( len == SOCKET_ERROR ) {
		Com_Printf( "NET_OpenSocks: recv: %s\n", NET_ErrorString() );
		return;
	}
	if ( len != 2 || buf[0] != 5 ) {
		Com_Printf( "NET_OpenSocks: bad response\n" );
		return;
	}
	switch( buf[1] ) {
	case 0:	// no authentication
		break;
	case 2: // username/password authentication
		break;
	default:
		Com_Printf( "NET_OpenSocks: request denied\n" );
		return;
	}

	// do username/password authentication if needed
	if ( buf[1] == 2 ) {
		int		ulen;
		int		plen;

		// build the request
		ulen = strlen( net_socksUsername->string );
		plen = strlen( net_socksPassword->string );

		buf[0] = 1;		// username/password authentication version
		buf[1] = ulen;
		if ( ulen ) {
			memcpy( &buf[2], net_socksUsername->string, ulen );
		}
		buf[2 + ulen] = plen;
		if ( plen ) {
			memcpy( &buf[3 + ulen], net_socksPassword->string, plen );
		}

		// send it
		if ( send( socks_socket, (void *)buf, 3 + ulen + plen, 0 ) == SOCKET_ERROR ) {
			Com_Printf( "NET_OpenSocks: send: %s\n", NET_ErrorString() );
			return;
		}

		// get the response
		len = recv( socks_socket, (void *)buf, 64, 0 );
		if ( len == SOCKET_ERROR ) {
			Com_Printf( "NET_OpenSocks: recv: %s\n", NET_ErrorString() );
			return;
		}
		if ( len != 2 || buf[0] != 1 ) {
			Com_Printf( "NET_OpenSocks: bad response\n" );
			return;
		}
		if ( buf[1] != 0 ) {
			Com_Printf( "NET_OpenSocks: authentication failed\n" );
			return;
		}
	}

	// send the UDP associate request
	buf[0] = 5;		// SOCKS version
	buf[1] = 3;		// command: UDP associate
	buf[2] = 0;		// reserved
	buf[3] = 1;		// address type: IPV4
	*(int *)&buf[4] = INADDR_ANY;
	*(short *)&buf[8] = htons( (short)port );		// port
	if ( send( socks_socket, (void *)buf, 10, 0 ) == SOCKET_ERROR ) {
		Com_Printf( "NET_OpenSocks: send: %s\n", NET_ErrorString() );
		return;
	}

	// get the response
	len = recv( socks_socket, (void *)buf, 64, 0 );
	if( len == SOCKET_ERROR ) {
		Com_Printf( "NET_OpenSocks: recv: %s\n", NET_ErrorString() );
		return;
	}
	if( len < 2 || buf[0] != 5 ) {
		Com_Printf( "NET_OpenSocks: bad response\n" );
		return;
	}
	// check completion code
	if( buf[1] != 0 ) {
		Com_Printf( "NET_OpenSocks: request denied: %i\n", buf[1] );
		return;
	}
	if( buf[3] != 1 ) {
		Com_Printf( "NET_OpenSocks: relay address is not IPV4: %i\n", buf[3] );
		return;
	}
	((struct sockaddr_in *)&socksRelayAddr)->sin_family = AF_INET;
	((struct sockaddr_in *)&socksRelayAddr)->sin_addr.s_addr = *(int *)&buf[4];
	((struct sockaddr_in *)&socksRelayAddr)->sin_port = *(short *)&buf[8];
	memset( ((struct sockaddr_in *)&socksRelayAddr)->sin_zero, 0, 8 );

	usingSocks = qtrue;
}


/*
=====================
NET_AddLocalAddress
=====================
*/
static void NET_AddLocalAddress(char *ifname, struct sockaddr *addr, struct sockaddr *netmask)
{
	int addrlen;
	sa_family_t family;

	// only add addresses that have all required info.
	if(!addr || !netmask || !ifname)
		return;

	family = addr->sa_family;

	if(numIP < MAX_IPS)
	{
		if(family == AF_INET)
		{
			addrlen = sizeof(struct sockaddr_in);
			localIP[numIP].type = NA_IP;
		}
		else if(family == AF_INET6)
		{
			addrlen = sizeof(struct sockaddr_in6);
			localIP[numIP].type = NA_IP6;
		}
		else
			return;

		Q_strncpyz(localIP[numIP].ifname, ifname, sizeof(localIP[numIP].ifname));

		localIP[numIP].family = family;

		memcpy(&localIP[numIP].addr, addr, addrlen);
		memcpy(&localIP[numIP].netmask, netmask, addrlen);

		numIP++;
	}
}

#if defined(__linux__) || defined(__APPLE__) || defined(__BSD__)
static void NET_GetLocalAddress(void)
{
	struct ifaddrs *ifap, *search;

	numIP = 0;

	if(getifaddrs(&ifap))
		Com_Printf("NET_GetLocalAddress: Unable to get list of network interfaces: %s\n", NET_ErrorString());
	else
	{
		for(search = ifap; search; search = search->ifa_next)
		{
			// Only add interfaces that are up.
			if(ifap->ifa_flags & IFF_UP)
				NET_AddLocalAddress(search->ifa_name, search->ifa_addr, search->ifa_netmask);
		}

		freeifaddrs(ifap);

		Sys_ShowIP();
	}
}
#else
static void NET_GetLocalAddress( void ) {
	char				hostname[256];
	struct addrinfo	hint;
	struct addrinfo	*res = NULL;

	numIP = 0;

	if(gethostname( hostname, 256 ) == SOCKET_ERROR)
		return;

	Com_Printf( "Hostname: %s\n", hostname );

	memset(&hint, 0, sizeof(hint));

	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;

	if(!getaddrinfo(hostname, NULL, &hint, &res))
	{
		struct sockaddr_in mask4;
		struct sockaddr_in6 mask6;
		struct addrinfo *search;

		/* On operating systems where it's more difficult to find out the configured interfaces, we'll just assume a
		 * netmask with all bits set. */

		memset(&mask4, 0, sizeof(mask4));
		memset(&mask6, 0, sizeof(mask6));
		mask4.sin_family = AF_INET;
		memset(&mask4.sin_addr.s_addr, 0xFF, sizeof(mask4.sin_addr.s_addr));
		mask6.sin6_family = AF_INET6;
		memset(&mask6.sin6_addr, 0xFF, sizeof(mask6.sin6_addr));

		// add all IPs from returned list.
		for(search = res; search; search = search->ai_next)
		{
			if(search->ai_family == AF_INET)
				NET_AddLocalAddress("", search->ai_addr, (struct sockaddr *) &mask4);
			else if(search->ai_family == AF_INET6)
				NET_AddLocalAddress("", search->ai_addr, (struct sockaddr *) &mask6);
		}

		Sys_ShowIP();
	}

	if(res)
		freeaddrinfo(res);
}
#endif

/*
====================
NET_OpenIP
====================
*/
void NET_OpenIP( void ) {
	int		i;
	int		err;
	int		port;
	int		port6;

	port = net_port->integer;
	port6 = net_port6->integer;

	NET_GetLocalAddress();

	// automatically scan for a valid port, so multiple
	// dedicated servers can be started without requiring
	// a different net_port for each one

	if(net_enabled->integer & NET_ENABLEV6)
	{
		for( i = 0 ; i < 10 ; i++ )
		{
			ip6_socket = NET_IP6Socket(net_ip6->string, port6 + i, &boundto, &err);
			if (ip6_socket != INVALID_SOCKET)
			{
				Cvar_SetValue( "net_port6", port6 + i );
				break;
			}
			else
			{
				if(err == EAFNOSUPPORT)
					break;
			}
		}
		if(ip6_socket == INVALID_SOCKET)
			Com_Printf( "WARNING: Couldn't bind to a v6 ip address.\n");
	}

	if(net_enabled->integer & NET_ENABLEV4)
	{
		for( i = 0 ; i < 10 ; i++ ) {
			ip_socket = NET_IPSocket( net_ip->string, port + i, &err );
			if (ip_socket != INVALID_SOCKET) {
				Cvar_SetValue( "net_port", port + i );

				if (net_socksEnabled->integer)
					NET_OpenSocks( port + i );

				break;
			}
			else
			{
				if(err == EAFNOSUPPORT)
					break;
			}
		}

		if(ip_socket == INVALID_SOCKET)
			Com_Printf( "WARNING: Couldn't bind to a v4 ip address.\n");
	}
}


//===================================================================


/*
====================
NET_GetCvars
====================
*/
static qboolean NET_GetCvars( void ) {
	int modified;

#ifdef DEDICATED
	// I want server owners to explicitly turn on ipv6 support.
	net_enabled = Cvar_Get( "net_enabled", "1", CVAR_LATCH | CVAR_ARCHIVE );
#else
	/* End users have it enabled so they can connect to ipv6-only hosts, but ipv4 will be
	 * used if available due to ping */
	net_enabled = Cvar_Get( "net_enabled", "3", CVAR_LATCH | CVAR_ARCHIVE );
#endif
	modified = net_enabled->modified;
	net_enabled->modified = qfalse;

	net_ip = Cvar_Get( "net_ip", "0.0.0.0", CVAR_LATCH );
	modified += net_ip->modified;
	net_ip->modified = qfalse;

	net_ip6 = Cvar_Get( "net_ip6", "::", CVAR_LATCH );
	modified += net_ip6->modified;
	net_ip6->modified = qfalse;

	net_scion = Cvar_Get( "net_scion", "127.0.0.1", CVAR_LATCH );
	modified += net_scion->modified;
	net_scion->modified = qfalse;

	net_port = Cvar_Get( "net_port", va( "%i", PORT_SERVER ), CVAR_LATCH );
	modified += net_port->modified;
	net_port->modified = qfalse;

	net_port6 = Cvar_Get( "net_port6", va( "%i", PORT_SERVER ), CVAR_LATCH );
	modified += net_port6->modified;
	net_port6->modified = qfalse;

	net_scion_port = Cvar_Get( "net_scion_port", va( "%i", PORT_SERVER_SCION ), CVAR_LATCH );
	modified += net_scion_port->modified;
	net_scion_port->modified = qfalse;

	// Some cvars for configuring multicast options which facilitates scanning for servers on local subnets.
	net_mcast6addr = Cvar_Get( "net_mcast6addr", NET_MULTICAST_IP6, CVAR_LATCH | CVAR_ARCHIVE );
	modified += net_mcast6addr->modified;
	net_mcast6addr->modified = qfalse;

#ifdef _WIN32
	net_mcast6iface = Cvar_Get( "net_mcast6iface", "0", CVAR_LATCH | CVAR_ARCHIVE );
#else
	net_mcast6iface = Cvar_Get( "net_mcast6iface", "", CVAR_LATCH | CVAR_ARCHIVE );
#endif
	modified += net_mcast6iface->modified;
	net_mcast6iface->modified = qfalse;

	net_socksEnabled = Cvar_Get( "net_socksEnabled", "0", CVAR_LATCH | CVAR_ARCHIVE );
	modified += net_socksEnabled->modified;
	net_socksEnabled->modified = qfalse;

	net_socksServer = Cvar_Get( "net_socksServer", "", CVAR_LATCH | CVAR_ARCHIVE );
	modified += net_socksServer->modified;
	net_socksServer->modified = qfalse;

	net_socksPort = Cvar_Get( "net_socksPort", "1080", CVAR_LATCH | CVAR_ARCHIVE );
	modified += net_socksPort->modified;
	net_socksPort->modified = qfalse;

	net_socksUsername = Cvar_Get( "net_socksUsername", "", CVAR_LATCH | CVAR_ARCHIVE );
	modified += net_socksUsername->modified;
	net_socksUsername->modified = qfalse;

	net_socksPassword = Cvar_Get( "net_socksPassword", "", CVAR_LATCH | CVAR_ARCHIVE );
	modified += net_socksPassword->modified;
	net_socksPassword->modified = qfalse;

	net_dropsim = Cvar_Get("net_dropsim", "", CVAR_TEMP);
	net_oobTimeout = Cvar_Get("net_oobTimeout", "10000", CVAR_ARCHIVE);

	return modified ? qtrue : qfalse;
}


/*
====================
NET_Config
====================
*/
void NET_Config( qboolean enableNetworking ) {
	qboolean	modified;
	qboolean	stop;
	qboolean	start;
	netadr_t    scionServerAddress = {0};

	// get any latched changes to cvars
	modified = NET_GetCvars();

	if( !net_enabled->integer ) {
		enableNetworking = 0;
	}

	// if enable state is the same and no cvars were modified, we have nothing to do
	if( enableNetworking == networkingEnabled && !modified ) {
		return;
	}

	if( enableNetworking == networkingEnabled ) {
		if( enableNetworking ) {
			stop = qtrue;
			start = qtrue;
		}
		else {
			stop = qfalse;
			start = qfalse;
		}
	}
	else {
		if( enableNetworking ) {
			stop = qfalse;
			start = qtrue;
		}
		else {
			stop = qtrue;
			start = qfalse;
		}
		networkingEnabled = enableNetworking;
	}

	if( stop ) {
		if ( ip_socket != INVALID_SOCKET ) {
			closesocket( ip_socket );
			ip_socket = INVALID_SOCKET;
		}

		if(multicast6_socket != INVALID_SOCKET)
		{
			if(multicast6_socket != ip6_socket)
				closesocket(multicast6_socket);

			multicast6_socket = INVALID_SOCKET;
		}

		if ( ip6_socket != INVALID_SOCKET ) {
			closesocket( ip6_socket );
			ip6_socket = INVALID_SOCKET;
		}

		if ( socks_socket != INVALID_SOCKET ) {
			closesocket( socks_socket );
			socks_socket = INVALID_SOCKET;
		}

		if (net_enabled->integer & NET_ENABLE_SCION)
			scionServerAddress = scion_client_remote;

		for (int i = 0; i < MAX_OOB_CONNECTIONS; ++i)
			NET_ClearOOBSlot(i);
		NET_ScionServerStop();
		NET_ScionClientClose();
	}

	if( start )
	{
		if (net_enabled->integer)
		{
			NET_OpenIP();
			NET_SetMulticast6();
			if (Cvar_VariableValue("sv_running"))
				NET_ScionServerStart();
			if (scionServerAddress.type != NA_BAD)
				NET_ScionClientConnect(&scionServerAddress);
		}
	}
}

/*
====================
NET_Init
====================
*/
void NET_Init( void ) {
#ifdef _WIN32
	int		r;

	r = WSAStartup( MAKEWORD( 1, 1 ), &winsockdata );
	if( r ) {
		Com_Printf( "WARNING: Winsock initialization failed, returned %d\n", r );
		return;
	}

	winsockInitialized = qtrue;
	Com_Printf( "Winsock Initialized\n" );
#endif

	NET_Config( qtrue );

	Cmd_AddCommand ("net_restart", NET_Restart_f);
}


/*
====================
NET_Shutdown
====================
*/
void NET_Shutdown( void ) {
	if ( !networkingEnabled ) {
		return;
	}

	NET_Config( qfalse );

#ifdef _WIN32
	WSACleanup();
	winsockInitialized = qfalse;
#endif
}

/*
====================
NET_Event

Called from NET_Sleep which uses select() to determine which sockets have seen action.
====================
*/

void NET_Event(fd_set *fdr)
{
	byte bufData[MAX_MSGLEN + 1];
	netadr_t from = {0};
	msg_t netmsg;

	while(1)
	{
		MSG_Init(&netmsg, bufData, sizeof(bufData));

		if(NET_GetPacket(&from, &netmsg, fdr))
		{
			if(net_dropsim->value > 0.0f && net_dropsim->value <= 100.0f)
			{
				// com_dropsim->value percent of incoming packets get dropped.
				if(rand() < (int) (((double) RAND_MAX) / 100.0 * (double) net_dropsim->value))
					continue;          // drop this packet
			}

			if(com_sv_running->integer)
				Com_RunAndTimeServerPacket(&from, &netmsg);
			else
				CL_PacketEvent(&from, &netmsg);
		}
		else
			break;
	}
}

/*
====================
NET_Sleep

Sleeps msec or until something happens on the network
====================
*/
void NET_Sleep(int msec)
{
	struct timeval timeout;
	fd_set fdr;
	int retval;
	SOCKET highestfd = INVALID_SOCKET;

	if(msec < 0)
		msec = 0;

	FD_ZERO(&fdr);

	if(ip_socket != INVALID_SOCKET)
	{
		FD_SET(ip_socket, &fdr);

		highestfd = ip_socket;
	}
	if(ip6_socket != INVALID_SOCKET)
	{
		FD_SET(ip6_socket, &fdr);

		if(highestfd == INVALID_SOCKET || ip6_socket > highestfd)
			highestfd = ip6_socket;
	}
	if(scion_server_socket != INVALID_SOCKET)
	{
		FD_SET(scion_server_socket, &fdr);

		if(highestfd == INVALID_SOCKET || scion_server_socket > highestfd)
			highestfd = scion_server_socket;
	}
	if(scion_client_socket != INVALID_SOCKET)
	{
		FD_SET(scion_client_socket, &fdr);

		if(highestfd == INVALID_SOCKET || scion_client_socket > highestfd)
			highestfd = scion_client_socket;
	}
	for (int i = 0; i < MAX_OOB_CONNECTIONS; ++i)
	{
		if (scion_oob[i].adr.type == NA_BAD)
			continue;

		if (Sys_Milliseconds() - scion_oob[i].last > net_oobTimeout->integer)
			NET_ClearOOBSlot(i);
		else
		{
			FD_SET(scion_oob[i].socket, &fdr);
			if(highestfd == INVALID_SOCKET || scion_oob[i].socket > highestfd)
				highestfd = scion_oob[i].socket;
		}
	}

#ifdef _WIN32
	if(highestfd == INVALID_SOCKET)
	{
		// windows ain't happy when select is called without valid FDs
		SleepEx(msec, 0);
		return;
	}
#endif

	timeout.tv_sec = msec/1000;
	timeout.tv_usec = (msec%1000)*1000;

	retval = select(highestfd + 1, &fdr, NULL, NULL, &timeout);

	if(retval == SOCKET_ERROR)
		Com_Printf("Warning: select() syscall failed: %s\n", NET_ErrorString());
	else if(retval > 0)
		NET_Event(&fdr);
}

/*
====================
NET_Restart_f
====================
*/
void NET_Restart_f(void)
{
	NET_Config(qtrue);
}
