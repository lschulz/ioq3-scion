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

#include "q_shared.h"
#include "qcommon.h"
#include <pan/pan.h>

/*

packet header
-------------
4	outgoing sequence.  high bit will be set if this is a fragmented message
[2	qport (only for client to server)]
[2	fragment start byte]
[2	fragment length. if < FRAGMENT_SIZE, this is the last fragment]
SCION Extension: (1<<14) bit of fragment length is set on last fragment

if the sequence number is -1, the packet should be handled as an out-of-band
message instead of as part of a netcon.

All fragments will have the same sequence numbers.

The qport field is a workaround for bad address translating routers that
sometimes remap the client's source port on a packet during gameplay.

If the base part of the net address matches and the qport matches, then the
channel matches even if the IP port differs.  The IP port should be updated
to the new value before sending out any replies.

*/

#define	MAX_PACKETLEN			1400		// max size of a network packet
#define	FRAGMENT_SIZE			(MAX_PACKETLEN - 100)
#define MIN_FRAGMENT_SIZE       100
#define	PACKET_HEADER			10			// two ints and a short
#ifndef USE_LIBSODIUM
#define SCI_FRAGMENT_SIZE(chan)	(chan->pctx.mss - PACKET_HEADER)
#else
#define CRYPTO_OVERHEAD         (crypto_aead_chacha20poly1305_ABYTES + crypto_aead_chacha20poly1305_NPUBBYTES)
#define SCI_FRAGMENT_SIZE(chan)	MAX(MIN_FRAGMENT_SIZE, (chan->pctx.mss - PACKET_HEADER - (chan->encrypted ? CRYPTO_OVERHEAD : 0)))
#endif

#define	FRAGMENT_BIT		(1U<<31)
#define LAST_FRAGMENT_BIT	(1U<<14) // don't use sign bit to avoid sign extension

cvar_t		*showpackets;
cvar_t		*showdrop;
cvar_t		*qport;

static char *netsrcString[2] = {
	"client",
	"server"
};

qboolean NET_ClientSelectPath(path_context_t *pctx);
qboolean NET_ServerSelectPath(const netadr_t *remote, path_context_t *pctx);

/*
===============
Netchan_Init

===============
*/
void Netchan_Init( int port ) {
	port &= 0xffff;
	showpackets = Cvar_Get ("showpackets", "0", CVAR_TEMP );
	showdrop = Cvar_Get ("showdrop", "0", CVAR_TEMP );
	qport = Cvar_Get ("net_qport", va("%i", port), CVAR_INIT );
}

/*
==============
Netchan_Setup

called to open a channel to a remote system
==============
*/
void Netchan_Setup(netsrc_t sock, netchan_t *chan, const netadr_t *adr, int qport, int challenge, qboolean compat)
{
	Com_Memset (chan, 0, sizeof(*chan));

	chan->sock = sock;
	chan->remoteAddress = *adr;
	chan->qport = qport;
	chan->incomingSequence = 0;
	chan->outgoingSequence = 1;
	chan->challenge = challenge;

	if (chan->remoteAddress.type == NA_SCION_IP || chan->remoteAddress.type == NA_SCION_IP6)
	{
		chan->scionext = qtrue;
		if (compat) Com_DPrintf("Attempting to use legacy protocol over SCION\n");
	}

#ifdef USE_LIBSODIUM
	chan->encrypted = qfalse;
#endif

#ifdef LEGACY_PROTOCOL
	chan->compat = compat;
#endif
}

#ifdef USE_LIBSODIUM
/*
=================
Netchan_InitSession

Initialize an encrypted connection after the channel has been set up (Netchan_Setup).
=================
*/
qboolean Netchan_InitSession(
	netchan_t *chan, const byte *publicKey, const byte *secretKey, const char *remoteKeyBase64)
{
	byte remoteKey[crypto_kx_PUBLICKEYBYTES];
	size_t binLen = 0;

	if (sodium_base642bin(remoteKey, sizeof(remoteKey), remoteKeyBase64, strlen(remoteKeyBase64),
		NULL, &binLen, NULL, sodium_base64_VARIANT_ORIGINAL))
		return qfalse;
	if (binLen != sizeof(remoteKey))
		return qfalse;

	if (chan->sock == NS_CLIENT)
	{
		if (crypto_kx_client_session_keys(chan->rxKey, chan->txKey, publicKey, secretKey, remoteKey))
			return qfalse;
	}
	else
	{
		if (crypto_kx_server_session_keys(chan->rxKey, chan->txKey, publicKey, secretKey, remoteKey))
			return qfalse;
	}

	randombytes_buf(chan->nonce, sizeof(chan->nonce));
	chan->encrypted = qtrue;

	Com_Printf("Set up encrypted netchan to %s\n", NET_AdrToStringwPort(&chan->remoteAddress));
	return qtrue;
}

/*
=================
Netchan_SendEncrypted

Encrypt and transmit a packet.
=================
*/
static void Netchan_SendEncrypted(netchan_t *chan, int length, const void *data, const netadr_t *to)
{
	byte buf[MAX_PACKETLEN];
	sodium_increment(chan->nonce, sizeof(chan->nonce));

	unsigned long long hdrLen = 4; // sequence number from server
	if (chan->sock == NS_CLIENT) hdrLen = 6; // sequence number and qport from client

	// Copy unencrypted but authenticated header bytes
	memcpy(buf, data, hdrLen);

	// Encrypt message and add authentication tag
	unsigned long long outlen = sizeof(buf) - hdrLen;
	int res = crypto_aead_chacha20poly1305_encrypt(
		buf + hdrLen, &outlen,			// output
		data + hdrLen, length - hdrLen,	// plaintext
		data, hdrLen,					// additional data
		NULL, chan->nonce, chan->txKey);
	if (res)
		Com_Error(ERR_DROP, "Netchan_SendEncrypted: length = %i", length);

	// Append nonce to message
	unsigned long long total = outlen + hdrLen + sizeof(chan->nonce);
	if (total > MAX_PACKETLEN)
		Com_Error(ERR_DROP, "Netchan_SendEncrypted: length = %i", length);
	memcpy(buf + hdrLen + outlen, chan->nonce, sizeof(chan->nonce));

	NET_SendPacket(chan->sock, total, buf, to, &chan->pctx);
}
#endif // USE_LIBSODIUM

/*
=================
Netchan_TransmitNextFragment

Send one fragment of the current message
=================
*/
void Netchan_TransmitNextFragment( netchan_t *chan ) {
	msg_t		send;
	byte		send_buf[MAX_PACKETLEN];
	int			fragmentLength;
	int			outgoingSequence;

	// write the packet header
	MSG_InitOOB (&send, send_buf, sizeof(send_buf));				// <-- only do the oob here

	outgoingSequence = chan->outgoingSequence | FRAGMENT_BIT;
	MSG_WriteLong(&send, outgoingSequence);

	// send the qport if we are a client
	if ( chan->sock == NS_CLIENT ) {
		MSG_WriteShort( &send, qport->integer );
	}

#ifdef LEGACY_PROTOCOL
	if(!chan->compat)
#endif
		MSG_WriteLong(&send, NETCHAN_GENCHECKSUM(chan->challenge, chan->outgoingSequence));

	// copy the reliable message to the packet first
	MSG_WriteShort(&send, chan->unsentFragmentStart);

	fragmentLength = chan->scionext ? SCI_FRAGMENT_SIZE(chan) : FRAGMENT_SIZE;
	if (chan->unsentFragmentStart + fragmentLength >= chan->unsentLength)
	{
		// last fragment
		fragmentLength = chan->unsentLength - chan->unsentFragmentStart;
		if (chan->scionext)
		{
			chan->outgoingSequence++;
			chan->unsentFragments = qfalse;
		}
	}
	int fragLen = fragmentLength;
	if (chan->scionext && !chan->unsentFragments)
		fragLen |= LAST_FRAGMENT_BIT;
	MSG_WriteShort(&send, fragLen);
	MSG_WriteData(&send, chan->unsentBuffer + chan->unsentFragmentStart, fragmentLength);

	// send the datagram
#ifdef USE_LIBSODIUM
	if (chan->encrypted)
		Netchan_SendEncrypted(chan, send.cursize, send.data, &chan->remoteAddress);
	else
#endif
		NET_SendPacket(chan->sock, send.cursize, send.data, &chan->remoteAddress, &chan->pctx);

	// Store send time and size of this packet for rate control
	chan->lastSentTime = Sys_Milliseconds();
	chan->lastSentSize = send.cursize;

	if ( showpackets->integer ) {
		Com_Printf ("%s send %4i : s=%i fragment=%i,%i\n"
			, netsrcString[ chan->sock ]
			, send.cursize
			, chan->outgoingSequence
			, chan->unsentFragmentStart, fragmentLength);
	}

	chan->unsentFragmentStart += fragmentLength;

	if (!chan->scionext)
	{
		// this exit condition is a little tricky, because a packet
		// that is exactly the fragment length still needs to send
		// a second packet of zero length so that the other side
		// can tell there aren't more to follow
		if ( chan->unsentFragmentStart == chan->unsentLength && fragmentLength != FRAGMENT_SIZE ) {
			chan->outgoingSequence++;
			chan->unsentFragments = qfalse;
		}
	}
}

/*
===============
Netchan_Transmit

Sends a message to a connection, fragmenting if necessary
A 0 length will still generate a packet.
================
*/
void Netchan_Transmit( netchan_t *chan, int length, const byte *data ) {
	msg_t		send;
	byte		send_buf[MAX_PACKETLEN];
	int			fragment_size = FRAGMENT_SIZE;

	if (chan->scionext) {
		qboolean res = qfalse;
		if (chan->sock == NS_CLIENT)
			res = NET_ClientSelectPath(&chan->pctx);
		else
			res = NET_ServerSelectPath(&chan->remoteAddress, &chan->pctx);
		if (!res) {
			Com_Printf("ERROR: No path to destination %s\n", NET_AdrToString(&chan->remoteAddress));
			return;
		}
		fragment_size = SCI_FRAGMENT_SIZE(chan);
	}

	if ( length > MAX_MSGLEN ) {
		Com_Error( ERR_DROP, "Netchan_Transmit: length = %i", length );
	}
	chan->unsentFragmentStart = 0;

	// fragment large reliable messages
	if ( length >= fragment_size ) {
		chan->unsentFragments = qtrue;
		chan->unsentLength = length;
		Com_Memcpy( chan->unsentBuffer, data, length );

		// only send the first fragment now
		Netchan_TransmitNextFragment( chan );

		return;
	}

	// write the packet header
	MSG_InitOOB (&send, send_buf, sizeof(send_buf));

	MSG_WriteLong( &send, chan->outgoingSequence );

	// send the qport if we are a client
	if(chan->sock == NS_CLIENT)
		MSG_WriteShort(&send, qport->integer);

#ifdef LEGACY_PROTOCOL
	if(!chan->compat)
#endif
		MSG_WriteLong(&send, NETCHAN_GENCHECKSUM(chan->challenge, chan->outgoingSequence));

	chan->outgoingSequence++;

	MSG_WriteData( &send, data, length );

	// send the datagram
#ifdef USE_LIBSODIUM
	if (chan->encrypted)
		Netchan_SendEncrypted(chan, send.cursize, send.data, &chan->remoteAddress);
	else
#endif
		NET_SendPacket(chan->sock, send.cursize, send.data, &chan->remoteAddress, &chan->pctx);

	// Store send time and size of this packet for rate control
	chan->lastSentTime = Sys_Milliseconds();
	chan->lastSentSize = send.cursize;

	if ( showpackets->integer ) {
		Com_Printf( "%s send %4i : s=%i ack=%i\n"
			, netsrcString[ chan->sock ]
			, send.cursize
			, chan->outgoingSequence - 1
			, chan->incomingSequence );
	}
}

/*
=================
Netchan_Process

Returns qfalse if the message should not be processed due to being
out of order or a fragment.

Msg must be large enough to hold MAX_MSGLEN, because if this is the
final fragment of a multi-part message, the entire thing will be
copied out.
=================
*/
qboolean Netchan_Process( netchan_t *chan, msg_t *msg ) {
	int			sequence;
	int			fragmentStart, fragmentLength;
	qboolean	fragmented;
	qboolean	lastFragment = qfalse;

	// XOR unscramble all data in the packet after the header
//	Netchan_UnScramblePacket( msg );

#ifdef USE_LIBSODIUM
	if (chan->encrypted) {
		unsigned long long hdrLen = 6; // sequence number and port from client
		if (chan->sock == NS_CLIENT) hdrLen = 4; // sequence number from server
		const unsigned long long hdrAndNonce = hdrLen + crypto_aead_chacha20poly1305_NPUBBYTES;

		if (msg->cursize < hdrAndNonce)
			return qfalse;

		// Ciphertext follows unencrypted header
		unsigned long long clen = msg->cursize - hdrAndNonce;
		byte *ciphertext = msg->data + hdrLen;

		// Nonce is at the end of the packet
		byte *nonce = msg->data + msg->cursize - crypto_aead_chacha20poly1305_NPUBBYTES;

		// Decrypt directly into the message buffer
		unsigned long long outlen = msg->maxsize - hdrLen;
		int ret = crypto_aead_chacha20poly1305_decrypt(ciphertext, &outlen, NULL,
			ciphertext, clen, msg->data, hdrLen, nonce, chan->rxKey);
		if (ret) {
			Com_Printf("WARNING: Netchan_Process: Message verification failed\n");
			return qfalse;
		}

		// Throw away the nonce
		msg->cursize = outlen + hdrLen;
	}
#endif

	// get sequence numbers
	MSG_BeginReadingOOB( msg );
	sequence = MSG_ReadLong( msg );

	// check for fragment information
	if ( sequence & FRAGMENT_BIT ) {
		sequence &= ~FRAGMENT_BIT;
		fragmented = qtrue;
	} else {
		fragmented = qfalse;
	}

	// read the qport if we are a server
	if ( chan->sock == NS_SERVER ) {
		MSG_ReadShort( msg );
	}

#ifdef LEGACY_PROTOCOL
	if(!chan->compat)
#endif
	{
		int checksum = MSG_ReadLong(msg);

		// UDP spoofing protection
		if(NETCHAN_GENCHECKSUM(chan->challenge, sequence) != checksum)
			return qfalse;
	}

	// read the fragment information
	if ( fragmented ) {
		fragmentStart = MSG_ReadShort( msg );
		fragmentLength = MSG_ReadShort( msg );
		if (chan->scionext) {
			lastFragment = (fragmentLength & LAST_FRAGMENT_BIT);
			fragmentLength &= ~LAST_FRAGMENT_BIT;
		} else {
			lastFragment = (fragmentLength != FRAGMENT_SIZE);
		}
	} else {
		fragmentStart = 0;		// stop warning message
		fragmentLength = 0;
	}

	if ( showpackets->integer ) {
		if ( fragmented ) {
			Com_Printf( "%s recv %4i : s=%i fragment=%i,%i\n"
				, netsrcString[ chan->sock ]
				, msg->cursize
				, sequence
				, fragmentStart, fragmentLength );
		} else {
			Com_Printf( "%s recv %4i : s=%i\n"
				, netsrcString[ chan->sock ]
				, msg->cursize
				, sequence );
		}
	}

	//
	// discard out of order or duplicated packets
	//
	if ( sequence <= chan->incomingSequence ) {
		if ( showdrop->integer || showpackets->integer ) {
			Com_Printf( "%s:Out of order packet %i at %i\n"
				, NET_AdrToString( &chan->remoteAddress )
				,  sequence
				, chan->incomingSequence );
		}
		return qfalse;
	}

	//
	// dropped packets don't keep the message from being used
	//
	chan->dropped = sequence - (chan->incomingSequence+1);
	if ( chan->dropped > 0 ) {
		if ( showdrop->integer || showpackets->integer ) {
			Com_Printf( "%s:Dropped %i packets at %i\n"
			, NET_AdrToString( &chan->remoteAddress )
			, chan->dropped
			, sequence );
		}
	}


	//
	// if this is the final fragment of a reliable message,
	// bump incoming_reliable_sequence
	//
	if ( fragmented ) {
		// TTimo
		// make sure we add the fragments in correct order
		// either a packet was dropped, or we received this one too soon
		// we don't reconstruct the fragments. we will wait till this fragment gets to us again
		// (NOTE: we could probably try to rebuild by out of order chunks if needed)
		if ( sequence != chan->fragmentSequence ) {
			chan->fragmentSequence = sequence;
			chan->fragmentLength = 0;
		}

		// if we missed a fragment, dump the message
		if ( fragmentStart != chan->fragmentLength ) {
			if ( showdrop->integer || showpackets->integer ) {
				Com_Printf( "%s:Dropped a message fragment\n"
				, NET_AdrToString( &chan->remoteAddress ));
			}
			// we can still keep the part that we have so far,
			// so we don't need to clear chan->fragmentLength
			return qfalse;
		}

		// copy the fragment to the fragment buffer
		if ( fragmentLength < 0 || msg->readcount + fragmentLength > msg->cursize ||
			chan->fragmentLength + fragmentLength > sizeof( chan->fragmentBuffer ) ) {
			if ( showdrop->integer || showpackets->integer ) {
				Com_Printf ("%s:illegal fragment length\n"
				, NET_AdrToString (&chan->remoteAddress ) );
			}
			return qfalse;
		}

		Com_Memcpy( chan->fragmentBuffer + chan->fragmentLength,
			msg->data + msg->readcount, fragmentLength );

		chan->fragmentLength += fragmentLength;

		// if this wasn't the last fragment, don't process anything
		if ( !lastFragment ) {
			return qfalse;
		}

		if ( chan->fragmentLength > msg->maxsize ) {
			Com_Printf( "%s:fragmentLength %i > msg->maxsize\n"
				, NET_AdrToString (&chan->remoteAddress ),
				chan->fragmentLength );
			return qfalse;
		}

		// copy the full message over the partial fragment

		// make sure the sequence number is still there
		*(int *)msg->data = LittleLong( sequence );

		Com_Memcpy( msg->data + 4, chan->fragmentBuffer, chan->fragmentLength );
		msg->cursize = chan->fragmentLength + 4;
		chan->fragmentLength = 0;
		msg->readcount = 4;	// past the sequence number
		msg->bit = 32;	// past the sequence number

		// TTimo
		// clients were not acking fragmented messages
		chan->incomingSequence = sequence;

		return qtrue;
	}

	//
	// the message can now be read from the current message pointer
	//
	chan->incomingSequence = sequence;

	return qtrue;
}


//==============================================================================


/*
=============================================================================

LOOPBACK BUFFERS FOR LOCAL PLAYER

=============================================================================
*/

// there needs to be enough loopback messages to hold a complete
// gamestate of maximum size
#define	MAX_LOOPBACK	16

typedef struct {
	byte	data[MAX_PACKETLEN];
	int		datalen;
} loopmsg_t;

typedef struct {
	loopmsg_t	msgs[MAX_LOOPBACK];
	int			get, send;
} loopback_t;

loopback_t	loopbacks[2];


qboolean	NET_GetLoopPacket (netsrc_t sock, netadr_t *net_from, msg_t *net_message)
{
	int		i;
	loopback_t	*loop;

	loop = &loopbacks[sock];

	if (loop->send - loop->get > MAX_LOOPBACK)
		loop->get = loop->send - MAX_LOOPBACK;

	if (loop->get >= loop->send)
		return qfalse;

	i = loop->get & (MAX_LOOPBACK-1);
	loop->get++;

	Com_Memcpy (net_message->data, loop->msgs[i].data, loop->msgs[i].datalen);
	net_message->cursize = loop->msgs[i].datalen;
	Com_Memset (net_from, 0, sizeof(*net_from));
	net_from->type = NA_LOOPBACK;
	return qtrue;

}


void NET_SendLoopPacket (netsrc_t sock, int length, const void *data, const netadr_t *to)
{
	int		i;
	loopback_t	*loop;

	loop = &loopbacks[sock^1];

	i = loop->send & (MAX_LOOPBACK-1);
	loop->send++;

	Com_Memcpy (loop->msgs[i].data, data, length);
	loop->msgs[i].datalen = length;
}

//=============================================================================

typedef struct packetQueue_s {
        struct packetQueue_s *next;
        int length;
        byte *data;
        netadr_t to;
		path_context_t pctx;
        int release;
} packetQueue_t;

packetQueue_t *packetQueue = NULL;

static void NET_QueuePacket(int length, const void *data, const netadr_t *to,
	path_context_t *pctx, int offset)
{
	packetQueue_t *new, *next = packetQueue;

	if(offset > 999)
		offset = 999;

	new = S_Malloc(sizeof(packetQueue_t));
	new->data = S_Malloc(length);
	Com_Memcpy(new->data, data, length);
	new->length = length;
	new->to = *to;
	new->pctx = *pctx;
	new->release = Sys_Milliseconds() + (int)((float)offset / com_timescale->value);
	new->next = NULL;

	if(!packetQueue) {
		packetQueue = new;
		return;
	}
	while(next) {
		if(!next->next) {
			next->next = new;
			return;
		}
		next = next->next;
	}
}

void NET_FlushPacketQueue(void)
{
	packetQueue_t *last;
	int now;

	while(packetQueue) {
		now = Sys_Milliseconds();
		if(packetQueue->release >= now)
			break;
		Sys_SendPacket(packetQueue->length, packetQueue->data, &packetQueue->to, &packetQueue->pctx);
		last = packetQueue;
		packetQueue = packetQueue->next;
		Z_Free(last->data);
		Z_Free(last);
	}
}

void NET_SendPacket(netsrc_t sock, int length, const void *data, const netadr_t *to, path_context_t *pctx) {

	// sequenced packets are shown in netchan, so just show oob
	if ( showpackets->integer && *(int *)data == -1 )	{
		Com_Printf ("send packet %4i\n", length);
	}

	if ( to->type == NA_LOOPBACK ) {
		NET_SendLoopPacket (sock, length, data, to);
		return;
	}
	if ( to->type == NA_BOT ) {
		return;
	}
	if ( to->type == NA_BAD ) {
		return;
	}

	if ( sock == NS_CLIENT && cl_packetdelay->integer > 0 ) {
		NET_QueuePacket(length, data, to, pctx, cl_packetdelay->integer);
	}
	else if ( sock == NS_SERVER && sv_packetdelay->integer > 0 ) {
		NET_QueuePacket(length, data, to, pctx, sv_packetdelay->integer);
	}
	else {
		Sys_SendPacket(length, data, to, pctx);
	}
}

/*
===============
NET_OutOfBandPrint

Sends a text message in an out-of-band datagram
================
*/
void QDECL NET_OutOfBandPrint( netsrc_t sock, const netadr_t *adr, const char *format, ... ) {
	va_list		argptr;
	char		string[MAX_MSGLEN];


	// set the header
	string[0] = -1;
	string[1] = -1;
	string[2] = -1;
	string[3] = -1;

	va_start( argptr, format );
	Q_vsnprintf( string+4, sizeof(string)-4, format, argptr );
	va_end( argptr );

	// send the datagram
	NET_SendPacket( sock, strlen( string ), string, adr, NULL );
}

/*
===============
NET_OutOfBandPrint

Sends a data message in an out-of-band datagram (only used for "connect")
================
*/
void QDECL NET_OutOfBandData( netsrc_t sock, const netadr_t *adr, byte *format, int len ) {
	byte		string[MAX_MSGLEN*2];
	int			i;
	msg_t		mbuf;

	// set the header
	string[0] = 0xff;
	string[1] = 0xff;
	string[2] = 0xff;
	string[3] = 0xff;

	for(i=0;i<len;i++) {
		string[i+4] = format[i];
	}

	mbuf.data = string;
	mbuf.cursize = len+4;
	Huff_Compress( &mbuf, 12);
	// send the datagram
	NET_SendPacket( sock, mbuf.cursize, mbuf.data, adr, NULL );
}

/*
=============
NET_PanToAdr

Initializes a netadr_t from a PAN UDP address. All unused fields are zeroed.
=============
*/
void NET_PanToAdr(PanUDPAddr pan, netadr_t *a)
{
	Com_Memset(a, 0, sizeof(netadr_t));

	uint64_t ia;
	PanUDPAddrGetIA(pan, &ia);
	memcpy(a->isd, &ia, 2);
	memcpy(a->asn, ((byte*)&ia + 2), 6);

	if (!PanUDPAddrIsIPv6(pan)) {
		a->type = NA_SCION_IP;
		PanUDPAddrGetIPv4(pan, a->ip);
		memset(a->ip6, 0, 16);
	} else {
		a->type = NA_SCION_IP6;
		PanUDPAddrGetIPv6(pan, a->ip6);
		memset(a->ip, 0, 4);
	}

	a->port = BigShort(PanUDPAddrGetPort(pan));
}

/*
=============
NET_StringToAdr

Traps "localhost" for loopback, passes everything else to system
return 0 on address not found, 1 on address found with port, 2 on address found without port.

Address family NA_SCION_IP and NA_SCION_IP6 can both resolve to either IPv4 or IPv6 addresses
over SCION.
=============
*/
int NET_StringToAdr( const char *s, netadr_t *a, netadrtype_t family )
{
	char	base[MAX_STRING_CHARS], *search;
	char	*port = NULL;

	if (!strcmp (s, "localhost")) {
		Com_Memset (a, 0, sizeof(*a));
		a->type = NA_LOOPBACK;
// as NA_LOOPBACK doesn't require ports report port was given.
		return 1;
	}

	if (family == NA_SCION_IP || family == NA_SCION_IP6 || family == NA_UNSPEC)
	{
		PanUDPAddr resolved = PAN_INVALID_HANDLE;
		if (PanResolveUDPAddr(s, &resolved) == PAN_ERR_OK)
		{
			NET_PanToAdr(resolved, a);
			PanDeleteHandle(resolved);
			return a->port != 0 ? 1 : 2;
		}
		else if (family != NA_UNSPEC)
		{
			a->type = NA_BAD;
			return 0;
		}
		// try again as direct IP if address family was UNSPEC
	}

	Q_strncpyz( base, s, sizeof( base ) );

	if(*base == '[' || Q_CountChar(base, ':') > 1)
	{
		// This is an ipv6 address, handle it specially.
		search = strchr(base, ']');
		if(search)
		{
			*search = '\0';
			search++;

			if(*search == ':')
				port = search + 1;
		}

		if(*base == '[')
			search = base + 1;
		else
			search = base;
	}
	else
	{
		// look for a port number
		port = strchr( base, ':' );

		if ( port ) {
			*port = '\0';
			port++;
		}

		search = base;
	}

	if(!Sys_StringToAdr(search, a, family))
	{
		a->type = NA_BAD;
		return 0;
	}

	if(port)
	{
		a->port = BigShort((short) atoi(port));
		return 1;
	}
	else
	{
		a->port = BigShort(PORT_SERVER);
		return 2;
	}
}
