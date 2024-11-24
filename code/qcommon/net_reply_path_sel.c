/*
===========================================================================
Copyright (C) 2024 Lars-Christian Schulz

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
#include "../uthash/uthash.h"
#include <pthread.h>

uint32_t NET_HashPath(PanPath path);
int NET_GetSafeMSS(void);
int NET_GetPathMSS(PanPath path, const netadr_t *src, const netadr_t *dst);

#define MAX_REMOTES 1024
#define CLEAR_INTERVAL (120 * 1000)

typedef struct
{
    netadr_t adr; // key (make sure unused fields are zeroed)
    int      lastUsed;
    PanPath  path;
    uint32_t hash;
    int      mss;
    UT_hash_handle hh;
} remote_host_t;

typedef struct
{
    netadr_t      local;
    int           lastClear;
    remote_host_t *remotes;
} reply_selector_t;

static reply_selector_t selector;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static PanReplySelector replySelHandle = PAN_INVALID_HANDLE;

//=============================================================================
// Private functions
//=============================================================================

// Looks up paths to remote, selects one, and stores it in the cache.
// Remote must not be in the cache yet and mutex must be held.
remote_host_t *registerNewPathTo(const netadr_t *remote)
{
    PanPath path = PAN_INVALID_HANDLE;
	PanIA dstIA = 0;
	dstIA |= (PanIA)remote->isd[0] << 56;
	dstIA |= (PanIA)remote->isd[1] << 48;
	dstIA |= (PanIA)remote->asn[0] << 40;
	dstIA |= (PanIA)remote->asn[1] << 32;
	dstIA |= (PanIA)remote->asn[2] << 24;
	dstIA |= (PanIA)remote->asn[3] << 16;
	dstIA |= (PanIA)remote->asn[4] << 8;
	dstIA |= (PanIA)remote->asn[5];

	PanPath *paths = NULL;
	int n = 0;
    PanError err = PanQueryPaths(dstIA, &paths, &n);
    if (err || n == 0)
        return NULL; // no paths available

    // select the first path with a sufficiently high MTU
    int minMSS = NET_GetSafeMSS();
    for (int i = 0; i < n; ++i)
    {
        if (!path && NET_GetPathMSS(paths[i], &selector.local, remote) >= minMSS)
            path = paths[i];
        else
            PanDeleteHandle(paths[i]);
    }
    free(paths);

    remote_host_t *entry = malloc(sizeof(remote_host_t));
    if (!entry) Com_Error(ERR_FATAL, "malloc failed");
    Com_Memset(entry, 0, sizeof(remote_host_t));

    // Copy address manually to ensure unused fields are zero
    entry->adr.type = remote->type;
    Com_Memcpy(entry->adr.isd, remote->isd, sizeof(remote->isd));
    Com_Memcpy(entry->adr.asn, remote->asn, sizeof(remote->asn));
    if (remote->type == NA_SCION_IP)
        Com_Memcpy(entry->adr.ip, remote->ip, sizeof(remote->ip));
    else
    {
        Com_Memcpy(entry->adr.ip6, remote->ip6, sizeof(remote->ip6));
        entry->adr.scope_id = remote->scope_id;
    }
    entry->adr.port = remote->port;

    entry->lastUsed = Sys_Milliseconds();
    entry->path = path;
    entry->hash = NET_HashPath(path);
    entry->mss = NET_GetPathMSS(path, &selector.local, remote);
    HASH_ADD(hh, selector.remotes, adr, sizeof(netadr_t), entry);
    return entry;
}

// Deletes all remotes. Mutex must be held.
static void clearAllRemotes(void)
{
    remote_host_t *remote, *tmp;
    HASH_ITER(hh, selector.remotes, remote, tmp)
    {
        HASH_DEL(selector.remotes, remote);
        PanDeleteHandle(remote->path);
        free(remote);
    }
}

// Deletes remotes not used since the given time. Mutex must be held.
static void clearUnusedRemotes(int since)
{
    remote_host_t *remote, *tmp;
    HASH_ITER(hh, selector.remotes, remote, tmp)
    {
        if (remote->lastUsed <= since)
        {
            HASH_DEL(selector.remotes, remote);
            PanDeleteHandle(remote->path);
            free(remote);
        }
    }
}

//=============================================================================
// Callbacks
//=============================================================================

static PanPath PathCallback(PanContext ctx, PanUDPAddr remote, uintptr_t)
{
    path_context_t *pctx = (path_context_t*)ctx;
    netadr_t adr;
    PanPath path = PAN_INVALID_HANDLE;
    remote_host_t *entry = NULL;

    pthread_mutex_lock(&mutex);
    NET_PanToAdr(remote, &adr);
    HASH_FIND(hh, selector.remotes, &adr, sizeof(netadr_t), entry);
    if (entry)
    {
        entry->lastUsed = Sys_Milliseconds();
        path = PanDuplicateHandle(entry->path);
        if (pctx && entry->hash != pctx->hash) {
            Com_DPrintf("ReplyPathSelector: Path changed since pre-selection\n");
            if (entry->mss != pctx->mss)
                Com_DPrintf(
                    "ReplyPathSelector: MSS changed since pre-selection, (%hu->%hu)\n",
                    entry->mss, pctx->mss);
        }
    }
    pthread_mutex_unlock(&mutex);
    PanDeleteHandle(remote);

    return path;
}

static void InitializeCallback(PanUDPAddr local, uintptr_t)
{
    pthread_mutex_lock(&mutex);
    NET_PanToAdr(local, &selector.local);
    pthread_mutex_unlock(&mutex);
    PanDeleteHandle(local);
}

static void RecordCallback(PanUDPAddr remote, PanPath path, uintptr_t)
{
    netadr_t adr;
    remote_host_t *entry = NULL;

    if (path == PAN_INVALID_HANDLE)
        return; // empty path

    NET_PanToAdr(remote, &adr);
	pthread_mutex_lock(&mutex);

    int now = Sys_Milliseconds();
    if (selector.lastClear + CLEAR_INTERVAL <= now)
    {
        clearUnusedRemotes(selector.lastClear);
        selector.lastClear = now;
    }

    HASH_FIND(hh, selector.remotes, &adr, sizeof(netadr_t), entry);
    if (entry)
    {
        PanDeleteHandle(entry->path);
        entry->path = path;
    }
    else
    {
        if ((HASH_COUNT(selector.remotes) >= MAX_REMOTES))
        {
            clearAllRemotes();
            selector.lastClear = now;
        }
        entry = malloc(sizeof(remote_host_t));
        if (!entry) Com_Error(ERR_FATAL, "malloc failed");
        Com_Memset(entry, 0, sizeof(remote_host_t));
        entry->adr = adr;
        entry->lastUsed = now;
        entry->path = path;
        entry->hash = NET_HashPath(path);
        entry->mss = NET_GetPathMSS(path, &selector.local, &adr);
        HASH_ADD(hh, selector.remotes, adr, sizeof(netadr_t), entry);
    }

	pthread_mutex_unlock(&mutex);
    PanDeleteHandle(remote);
}

static void PathDownCallback(PanPathFingerprint pf, PanPathInterface pi, uintptr_t)
{
    PanDeleteHandle(pf);
    PanDeleteHandle(pi);
}

static void CloseCallback(uintptr_t)
{
    clearAllRemotes();
    Com_Memset(&selector, 0, sizeof(reply_selector_t));
}

//=============================================================================
// Commands
//=============================================================================

/*
==================
NET_ShowClientPaths_f

Print last path to connected SCION clients.
==================
*/
void NET_ShowClientPaths_f(void)
{
    const char spaces[] = "                                       ";
    const int width = sizeof(spaces) - 1;
    char fstr[8] = "";

    pthread_mutex_lock(&mutex);
    remote_host_t *client, *tmp;
    Com_Printf("address                                 mss  path\n");
    Com_Printf("--------------------------------------- ---- --------------------------------\n");
    HASH_ITER(hh, selector.remotes, client, tmp)
    {
        const char *addrStr = NET_AdrToStringwPort(&client->adr);

        Com_Printf("%s", addrStr);
        int n = width - (int)strlen(addrStr);
        if (n > 0)
        {
            Com_sprintf(fstr, sizeof(fstr), "%%.%ds", n);
            Com_Printf(fstr, spaces);
        }

        Com_Printf(" %4d", client->mss);

        char *pathStr = PanPathToString(client->path);
        Com_Printf(" %s\n", pathStr);
        free(pathStr);
    }
    pthread_mutex_unlock(&mutex);
}

//=============================================================================
// Public functions
//=============================================================================

/*
===================
NET_ReplyPathSelInit

Initialize the reply path selector.
===================
*/
PanReplySelector NET_ReplyPathSelInit(void)
{
	if (replySelHandle != PAN_INVALID_HANDLE)
		return replySelHandle;

    struct PanReplySelCallbacks callbacks = {
        &PathCallback,
        &InitializeCallback,
        &RecordCallback,
        &PathDownCallback,
        &CloseCallback,
    };
    replySelHandle = PanNewCReplySelector(&callbacks, 0);
    if (replySelHandle == PAN_INVALID_HANDLE)
        return replySelHandle;

    Com_Memset(&selector, 0, sizeof(reply_selector_t));
    selector.lastClear = Sys_Milliseconds();

    Cmd_AddCommand("showclientpaths", NET_ShowClientPaths_f);
    Cmd_AddCommand("clearclientpaths", clearAllRemotes);

    return replySelHandle;
}

/*
===================
NET_ReplyPathSelDestroy
===================
*/
void NET_ReplyPathSelDestroy(void)
{
	if (replySelHandle == PAN_INVALID_HANDLE)
		return;

    PanDeleteHandle(replySelHandle);
    replySelHandle = PAN_INVALID_HANDLE;

    Cmd_RemoveCommand("showclientpaths");
    Cmd_RemoveCommand("clearclientpaths");
}

/*
===================
NET_ServerSelectPath

Select a path to a remote SCION host taking context into account.
Returns false if there is no known path to the remote.
===================
*/
qboolean NET_ServerSelectPath(const netadr_t *remote, path_context_t *pctx)
{
    qboolean ret = qfalse;
    remote_host_t *entry = NULL;

	if (replySelHandle == PAN_INVALID_HANDLE)
        return ret;

    pthread_mutex_lock(&mutex);
    HASH_FIND(hh, selector.remotes, remote, sizeof(netadr_t), entry);
    if (!entry) entry = registerNewPathTo(remote);
    if (entry)
    {
        pctx->hash = entry->hash;
        pctx->mss = entry->mss;
        ret = qtrue;
    }
    pthread_mutex_unlock(&mutex);

    return ret;
}
