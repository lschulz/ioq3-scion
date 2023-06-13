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
#include <pthread.h>

#define MAX_PATH_COUNT 128

typedef struct
{
	char hash[9]; // 8 hex digits plus null terminator
	PanPath path;
} scion_path_t;

typedef struct
{
	unsigned int pathCount;
	unsigned int currPath;
	scion_path_t paths[MAX_PATH_COUNT];
} path_selector_t;

static path_selector_t selector;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static PanSelector pathSelHandle = PAN_INVALID_HANDLE;

//=============================================================================
// Private functions
//=============================================================================

static void hashPath(const char *path, char hash[9])
{
	uint32_t h = 0;
	for (unsigned int i = 0; path[i]; ++i)
		h ^= (uint32_t)path[i] << (8 * (i % 4));
	Com_sprintf(hash, 9, "%08x", h);
}

static void copyPaths(PanPath *paths, size_t count)
{
	for (size_t i = 0; i < count && i < MAX_PATH_COUNT; ++i)
	{
		if (selector.paths[i].path)
			PanDeleteHandle(selector.paths[i].path);
		selector.paths[i].path = paths[i];

		char *str = PanPathToString(paths[i]);
		if (str)
		{
			hashPath(str, selector.paths[i].hash);
			free(str);
		}
	}
	selector.pathCount = MIN(count, MAX_PATH_COUNT);
}

static void printPath(const scion_path_t *path)
{
	char str[128];
	char *pathStr = PanPathToString(path->path);
	if (pathStr)
	{
		Com_sprintf(str, sizeof(str), "Path: [%s] %s\n", path->hash, pathStr);
		CL_ConsolePrint(str);
		free(pathStr);
	}
}

//=============================================================================
// Callbacks
//=============================================================================

static PanPath PathSelectCallback(uintptr_t)
{
	PanPath path;
	pthread_mutex_lock(&mutex);

	unsigned int curr = selector.currPath;
	if (curr < selector.pathCount)
		path = selector.paths[curr].path;
	else
		path = PAN_INVALID_HANDLE;

	pthread_mutex_unlock(&mutex);
	return path;
}

static void InitializeCallback(
	PanUDPAddr local, PanUDPAddr remote,
	PanPath *paths, size_t count, uintptr_t)
{
	pthread_mutex_lock(&mutex);
	copyPaths(paths, count);
	pthread_mutex_unlock(&mutex);
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
    for (unsigned int i = 0; i < selector.pathCount; ++i)
    {
        char *str = PanPathToString(selector.paths[i].path);
		if (i == selector.currPath)
			Com_Printf(">%s< %s\n", selector.paths[i].hash, str);
		else
        	Com_Printf("[%s] %s\n", selector.paths[i].hash, str);
        free(str);
    }
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
		for (; hash[j] && selector.paths[i].hash[j]; ++j)
			if (hash[j] != selector.paths[i].hash[j]) break;

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
	if (selector.currPath + 1 < selector.pathCount)
		selector.currPath += 1;
	printPath(&selector.paths[selector.currPath]);
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
	if (selector.currPath > 0)
		selector.currPath -= 1;
	printPath(&selector.paths[selector.currPath]);
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
