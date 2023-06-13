/*
===========================================================================
Copyright (C) 2023 Lars-Christian Schulz

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
#include "../uthash/uthash.h"

#define CL_KNOWN_SERVERS_FILE "known_servers"

typedef struct {
	char adr[NET_ADDRSTRMAXLEN];
	char key[sodium_base64_ENCODED_LEN(crypto_kx_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL)];
	UT_hash_handle hh;
} known_server_t;

static known_server_t *knownServers;

/*
==================
CL_InitKnownServers

Load known servers from file system.
==================
*/
void CL_InitKnownServers(void)
{
	int len = 0;
	char buf[4096];
	char fmt[32];
	char adr[NET_ADDRSTRMAXLEN];
	char key[sodium_base64_ENCODED_LEN(crypto_kx_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL)];
	fileHandle_t f;
	known_server_t *srv;

	len = FS_SV_FOpenFileRead(CL_KNOWN_SERVERS_FILE, &f);
	if (len < 0) return;

	// Prepare format string
	Com_sprintf(fmt, sizeof(fmt), "%%%zus %%%zus", sizeof(adr), sizeof(key));

	while (1)
	{
		// Read a chunk
		len = FS_Read(buf, sizeof(buf) - 1, f);
		if (len < 1) break;
		buf[len] = '\0';

		// Scan line by line
		char *line = buf;
		while (line)
		{
			char *end = strchr(line, '\n');
			if (!end) break; // last line of the file must have a newline
			*end = '\0';

			if (sscanf(line, fmt, adr, key) == 2)
			{
				Com_Printf("adr = %s, key = %s\n", adr, key);
				srv = malloc(sizeof(known_server_t));
				if (!srv) Com_Error(ERR_FATAL, "malloc failed");
				strcpy(srv->adr, adr);
				strcpy(srv->key, key);
				known_server_t *replaced = NULL;
				HASH_REPLACE_STR(knownServers, adr, srv, replaced);
				free(replaced);
			}
			line = end + 1;
		}

		// Read partially read line again
		ptrdiff_t parsed = line - buf;
		if (parsed == 0) break;
		if (FS_Seek(f, -(len - parsed), FS_SEEK_CUR) < 0) break;
	}

	FS_FCloseFile(f);
}

/*
==================
CL_InitKnownServers

Write known servers back to file and release memory.
==================
*/
void CL_FreeKnownServers(void)
{
	fileHandle_t f;

	f = FS_SV_FOpenFileWrite(CL_KNOWN_SERVERS_FILE);

	known_server_t *srv, *tmp;
	HASH_ITER(hh, knownServers, srv, tmp)
	{
		if (f) FS_Printf(f, "%s %s\n", srv->adr, srv->key);
		HASH_DEL(knownServers, srv);
		free(srv);
	}

	if (f) FS_FCloseFile(f);
}

/*
==================
CL_VerifyServerKey

Check whether the server is known and its public key is unchanged.
New servers are added to the list automatically.
==================
*/
qboolean CL_VerifyServerKey(const netadr_t *server, const char *publicKey)
{
	known_server_t *srv;
	const char *adr = NET_AdrToStringwPort(server);

	HASH_FIND_STR(knownServers, adr, srv);
	if (srv)
		return strcmp(srv->key, publicKey) == 0;
	else
	{
		Com_Printf(S_COLOR_YELLOW
			"WARNING: Adding server %s with key %s to list of known servers.\n",
			adr, publicKey);
		srv = malloc(sizeof(known_server_t));
		if (!srv) Com_Error(ERR_FATAL, "malloc failed");
		Q_strncpyz(srv->adr, adr, sizeof(srv->adr));
		Q_strncpyz(srv->key, publicKey, sizeof(srv->key));
		HASH_ADD_STR(knownServers, adr, srv);
		return qtrue;
	}
}
