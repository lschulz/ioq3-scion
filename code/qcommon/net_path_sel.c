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
#include <pthread.h>

uint32_t NET_HashPath(PanPath path);
int NET_GetSafeMSS(void);
int NET_GetPathMSS(PanPath path, const netadr_t *src, const netadr_t *dst);

#define MAX_PATH_COUNT 128

typedef struct
{
	PanPath  path;
	uint32_t hash;
	int      mss;
} scion_path_t;

typedef struct
{
	qboolean initialized;   // selector is never initialized by PAN for AS-internal communication
	netadr_t local, remote; // connection endpoints
	unsigned int currPath;  // index of currently selected path
	unsigned int pathCount; // number of paths in paths
	scion_path_t paths[MAX_PATH_COUNT];
} path_selector_t;

static path_selector_t selector;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static PanSelector pathSelHandle = PAN_INVALID_HANDLE;

//=============================================================================
// Private functions
//=============================================================================

static void copyPaths(PanPath *paths, size_t count)
{
	size_t j = 0;
	int minMSS = NET_GetSafeMSS();
	for (size_t i = 0; i < count && i < MAX_PATH_COUNT; ++i)
	{
		int mss = NET_GetPathMSS(paths[i], &selector.local, &selector.remote);
		if (mss >= minMSS)
		{
			if (selector.paths[j].path)
				PanDeleteHandle(selector.paths[j].path);
			selector.paths[j].path = paths[i];
			selector.paths[j].hash = NET_HashPath(paths[i]);
			selector.paths[j].mss = mss;
			++j;
		}
	}
	selector.pathCount = j;
}

static void printPath(const scion_path_t *path)
{
	char str[1024];
	char *pathStr = PanPathToString(path->path);
	if (pathStr)
	{
		Com_sprintf(str, sizeof(str), "Path: [^2%08x] ^7%s\n", path->hash, pathStr);
		CL_ConsolePrint(str);
		free(pathStr);
	}
}

static scion_path_t *selectPathFromCtx(path_context_t *pctx)
{
	scion_path_t *path = NULL;
	// try to find a matching hash
	for (unsigned int i = 0; i < selector.pathCount; ++i)
	{
		if (selector.paths[i].hash == pctx->hash)
			path = &selector.paths[i];
	}
	if (!path || path->mss < pctx->mss)
	{
		// try to find a large enough MSS
		for (unsigned int i = 0; i < selector.pathCount; ++i)
		{
			if (selector.paths[i].mss >= pctx->mss)
			{
				path = &selector.paths[i];
				break;
			}
		}
	}
	return path;
}

//=============================================================================
// Callbacks
//=============================================================================

static PanPath PathSelectCallback(uint64_t ctx, uintptr_t)
{
	path_context_t *pctx = (path_context_t*)ctx;
	PanPath path = PAN_INVALID_HANDLE;

	pthread_mutex_lock(&mutex);
	unsigned int curr = selector.currPath;
	if (curr < selector.pathCount)
	{
		path = selector.paths[curr].path;
		if (pctx && selector.paths[curr].mss < pctx->mss)
		{
			scion_path_t *sel = selectPathFromCtx(pctx);
			if (sel) path = sel->path;
		}
	}

	pthread_mutex_unlock(&mutex);
	return path;
}

static void InitializeCallback(
	PanUDPAddr local, PanUDPAddr remote, PanPath *paths, size_t count, uintptr_t)
{
	pthread_mutex_lock(&mutex);

	NET_PanToAdr(local, &selector.local);
	NET_PanToAdr(remote, &selector.remote);
	selector.initialized = qtrue; // local != remote
	copyPaths(paths, count);

	pthread_mutex_unlock(&mutex);
	PanDeleteHandle(local);
	PanDeleteHandle(remote);
}

static void RefreshCallback(PanPath *paths, size_t count, uintptr_t)
{
	pthread_mutex_lock(&mutex);
	PanPathFingerprint currFp = 0;
	unsigned int curr = selector.currPath;
	if (curr < selector.pathCount)
	{
		if (selector.paths[curr].path)
			currFp = PanPathGetFingerprint(selector.paths[curr].path);
	}
	if (currFp)
	{
		for (size_t i = 0; i < count && i < MAX_PATH_COUNT; ++i)
		{
			PanPathFingerprint pf = PanPathGetFingerprint(paths[i]);
			int equal = PanPathFingerprintAreEqual(pf, currFp);
			PanDeleteHandle(pf);
			if (equal)
			{
				selector.currPath = i;
				break;
			}
		}
		PanDeleteHandle(currFp);
	}

	copyPaths(paths, count);
	pthread_mutex_unlock(&mutex);
}

static void PathDownCallback(PanPathFingerprint pf, PanPathInterface pi, uintptr_t)
{
	pthread_mutex_lock(&mutex);
	unsigned int curr = selector.currPath;
	if (curr < selector.pathCount && selector.paths[curr].path)
	{
		PanPath path = selector.paths[curr].path;
		PanPathFingerprint currFp = PanPathGetFingerprint(path);
		if (PanPathFingerprintAreEqual(pf, currFp) && PanPathContainsInterface(path, pi))
		{
			selector.currPath = (curr + 1) % selector.pathCount;
		}
		PanDeleteHandle(currFp);
	}
	pthread_mutex_unlock(&mutex);
	PanDeleteHandle(pf);
	PanDeleteHandle(pi);
}

static void CloseCallback(uintptr_t)
{
	for (unsigned int i = 0; i < selector.pathCount; ++i)
	{
		if (selector.paths[i].path)
			PanDeleteHandle(selector.paths[i].path);
	}
	Com_Memset(&selector, 0, sizeof(path_selector_t));
}

//=============================================================================
// Commands
//=============================================================================

/*
==================
NET_ShowPaths_f
==================
*/
void NET_ShowPaths_f(void)
{
    pthread_mutex_lock(&mutex);
	if (selector.initialized)
	{
		for (unsigned int i = 0; i < selector.pathCount; ++i)
		{
			char *str = PanPathToString(selector.paths[i].path);
			int mss = NET_GetPathMSS(selector.paths[i].path, &selector.local, &selector.remote);
			if (i == selector.currPath)
				Com_Printf(">^2%08x< ^5Hops^7: [^7%s} ^5MSS^7: %d\n", selector.paths[i].hash, str, mss);
			else
				Com_Printf("[^2%08x] ^5Hops^7: [^7%s} ^5MSS^7: %d\n", selector.paths[i].hash, str, mss);
			free(str);
		}
	}
	else
		CL_ConsolePrint("Empty path, AS-local connection\n");
    pthread_mutex_unlock(&mutex);
}

/*
==================
NET_SelectPath_f
==================
*/
void NET_SelectPath_f(void)
{
	int argc = Cmd_Argc();

	if (argc != 2)
	{
		Com_Printf("usage: selectpath path\n");
		return;
	}

	pthread_mutex_lock(&mutex);

	char *hash = Cmd_Argv(1);
	int hashLen = strlen(hash);
	int longestMatch = 0;
	int matchCount = 0;
	unsigned int match = 0;

	// Search for the longest matching hash prefix
	for (unsigned int i = 0; i < selector.pathCount; ++i)
	{
		int j = 0;
		char h[9] = "";
		Com_sprintf(h, 9, "%08x", selector.paths[i].hash);
		for (; hash[j] && h[j]; ++j)
			if (hash[j] != h[j]) break;

		if (j != hashLen) continue;

		if (j == longestMatch)
		{
			matchCount++;
		}
		else if (j > longestMatch)
		{
			longestMatch = j;
			matchCount = 1;
			match = i;
		}
	}

	// Switch path if match is unique
	if (longestMatch > 0)
	{
		if (matchCount == 1)
		{
			selector.currPath = match;
			printPath(&selector.paths[selector.currPath]);
		}
		else
			Com_Printf("Prefix not unique\n");
	}
	else
		Com_Printf("Not found\n");

	pthread_mutex_unlock(&mutex);
}

/*
==================
NET_NextPath_f
==================
*/
void NET_NextPath_f(void)
{
	pthread_mutex_lock(&mutex);
	if (selector.initialized)
	{
		if (selector.currPath + 1 < selector.pathCount)
			selector.currPath += 1;
		if (selector.currPath < selector.pathCount)
			printPath(&selector.paths[selector.currPath]);
	}
	else
		CL_ConsolePrint("Empty path, AS-local connection\n");
	pthread_mutex_unlock(&mutex);
}

/*
==================
NET_PrevPath_f
==================
*/
void NET_PrevPath_f(void)
{
	pthread_mutex_lock(&mutex);
	if (selector.initialized)
	{
		if (selector.currPath > 0)
			selector.currPath -= 1;
		if (selector.currPath < selector.pathCount)
			printPath(&selector.paths[selector.currPath]);
	}
	else
		CL_ConsolePrint("Empty path, AS-local connection\n");
	pthread_mutex_unlock(&mutex);
}

//=============================================================================
// Public functions
//=============================================================================

/*
===================
NET_PathSelInit

Initialize the path selector.
===================
*/
PanSelector NET_PathSelInit(void)
{
	if (pathSelHandle != PAN_INVALID_HANDLE)
		return pathSelHandle;

	struct PanSelectorCallbacks callbacks = {
		&PathSelectCallback,
		&InitializeCallback,
		&RefreshCallback,
		&PathDownCallback,
		&CloseCallback
	};
	pathSelHandle = PanNewCSelector(&callbacks, 0);
	if (pathSelHandle == PAN_INVALID_HANDLE)
		return pathSelHandle;

	Com_Memset(&selector, 0, sizeof(path_selector_t));

	Cmd_AddCommand("showpaths", NET_ShowPaths_f);
	Cmd_AddCommand("selectpath", NET_SelectPath_f);
	Cmd_AddCommand("nextpath", NET_NextPath_f);
	Cmd_AddCommand("prevpath", NET_PrevPath_f);

	return pathSelHandle;
}

/*
===================
NET_PathSelDestroy
===================
*/
void NET_PathSelDestroy(void)
{
	if (pathSelHandle == PAN_INVALID_HANDLE)
		return;

	PanDeleteHandle(pathSelHandle);
	pathSelHandle = PAN_INVALID_HANDLE;

	Cmd_RemoveCommand("showpaths");
	Cmd_RemoveCommand("selectpath");
	Cmd_RemoveCommand("nextpath");
	Cmd_RemoveCommand("prevpath");
}

/*
===================
NET_ClientSelectPath

Select a path taking context into account.
Returns false if there is no path.
===================
*/
qboolean NET_ClientSelectPath(path_context_t *pctx)
{
	qboolean ret = qfalse;
	pthread_mutex_lock(&mutex);
	if (!selector.initialized)
	{
		// AS-internal communication, return default values
		pctx->hash = 0;
		pctx->mss = 1300;
		ret = qtrue;
	}
	else if (selector.currPath < selector.pathCount)
	{
		PanPath path = selector.paths[selector.currPath].path;
		pctx->hash = NET_HashPath(path);
		pctx->mss = NET_GetPathMSS(path, &selector.local, &selector.remote);
		ret = qtrue;
	}
	pthread_mutex_unlock(&mutex);
	return ret;
}
