#include "stdafx.h"
#include "dota2interface.h"

EGCResults MySendMessage(DWORD64 dwThis, DWORD punMsgType, DWORD64 *pubDest, int pcubMsgSize);

static CDota2Tool g_dota2tool;

CDota2Tool *::dota2interface()
{
	return &g_dota2tool;
}

bool CDota2Tool::GetRoomId(char*strRoomid)
{
	if (!mRoomid.length())return false;
	strcpy(strRoomid, mRoomid.c_str());
	return true;
}

bool CDota2Tool::CreateRoom(const char*strPassword)
{
	if (strlen(strPassword) != 10)return false;
	
	
}

