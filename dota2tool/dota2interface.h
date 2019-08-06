#pragma once

#include "string"
using namespace std;
struct GClient
{
	DWORD64 a1;
	DWORD64 a2;
};

enum EGCResults
{
	k_EGCResultOK = 0,
	k_EGCResultNoMessage = 1,			// There is no message in the queue
	k_EGCResultBufferTooSmall = 2,		// The buffer is too small for the requested message
	k_EGCResultNotLoggedOn = 3,			// The client is not logged onto Steam
	k_EGCResultInvalidMessage = 4,		// Something was wrong with the message being sent with SendMessage
};
class CDota2Tool
{
public:
	
	bool CreateRoom(const char*strPassword);
	bool GetRoomId( char*strRoomid);
public:
	string mRoomid;
};
CDota2Tool *dota2interface();
extern GClient g_ecx;
