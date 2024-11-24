/*
===========================================================================
Copyright (C) 2023 Lars-Christian Schulz

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
St, Fifth Floor, Boston, MA  02110-1301  USA
===========================================================================
*/

#include "../qcommon/q_shared.h"
#include "../qcommon/qcommon.h"

static cvar_t *net_safeMSS;

/*
==================
NET_HashPath
==================
*/
uint32_t NET_HashPath(PanPath path)
{
    char *str = PanPathToString(path);
	uint32_t h = 5381;
	for (unsigned int i = 0; str[i]; ++i)
		h = ((h << 5) + h) + (uint32_t)str[i];
    free(str);
    return h;
}

/*
==================
NET_GetSafeMSS
==================
*/
int NET_GetSafeMSS(void)
{
    if (!net_safeMSS)
        net_safeMSS = Cvar_Get("net_safeMSS", "1000", CVAR_ARCHIVE);
    if (net_safeMSS->integer < 200)
    {
        Cvar_Set("net_safeMSS", "200");
        return 200;
    }
    else if (net_safeMSS->integer > 65535)
    {
        Cvar_Set("net_safeMSS", "65535");
        return 65535;
    }
    else
        return net_safeMSS->integer;
}

/*
==================
NET_GetPathMSS
==================
*/
int NET_GetPathMSS(PanPath path, const netadr_t *src, const netadr_t *dst)
{
    const int MIN_HEADER_SIZE =
        + 40    // IPv6 underlay
        + 2 * 8 // 2 UDP headers
        + 12    // SCION common header
        + 16;   // SCION AS addresses

    int mtu = PanPathGetMTU(path);

    int pathSize = PanPathDpLength(path);

    if (mtu == 0 || pathSize < 0)
        return NET_GetSafeMSS();

    int headers = MIN_HEADER_SIZE + pathSize;
    if (src->type == NA_SCION_IP) // src host address
        headers += 4;
    else
        headers += 16;
    if (dst->type == NA_SCION_IP) // dst host address
        headers += 4;
    else
        headers += 16;

    if (headers >= mtu)
        return 0;
    return mtu - headers;
}
