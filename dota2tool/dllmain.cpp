// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include "dota2interface.h"
#include "dota_gcmessages.pb.h"
#include "time.h"
// #define SENDOFFSETFUN 0x159c900
// #define ECXOFFSET 0x26d6208
// #define PACKETCOUNT 0x2657920;

DWORD64 GCClientSendAdd1;
DWORD64 GCClientSendAdd2;
DWORD64 GCClientTicket;
DWORD64 GPlayerIDAdrr;
DWORD64 GGetPlayTeamEcx;
DWORD64 GGetPlayerTeamCall;
DWORD64 GGetGameWinnerCall;
HMODULE hClient = 0;
//用于构造ecx

GClient g_ecx;

struct GCMsgHeaderPB_t
{
	DWORD msg;
	DWORD headerLength;
};
struct CMsgGCBase
{

	GCMsgHeaderPB_t header;
	
	BYTE proto[4096];
};
struct CMsgGCBaseEx
{
	GCMsgHeaderPB_t header;
	char a1[9];
	BYTE proto[4096];
};

typedef EGCResults (__fastcall* SendMessageFn)(DWORD64,DWORD punMsgType, DWORD64 *pubDest, int pcubMsgSize);
typedef int(__fastcall* GetPlayerTeamFn)(DWORD64, int nid);
typedef int(__stdcall* GetGmaeWinnerFn)();
GetPlayerTeamFn pfnGetPlayerTeam = NULL;
SendMessageFn pfnSendMessage = NULL;
GetGmaeWinnerFn pfnGetGameWinner = NULL;
DWORD GetPacketCount()
{
	HMODULE hClient = GetModuleHandleA("client.dll");
	DWORD64 dwPacketCount = (DWORD64)hClient + GCClientTicket;
	return *(DWORD*)(dwPacketCount + 0x198);
}

EGCResults MySendMessage(DWORD64 dwThis, DWORD punMsgType, DWORD64 *pubDest, int pcubMsgSize)
{
	
	printf("%I64X punMsgType %d\n", dwThis,punMsgType);
	if (punMsgType == k_EMsgGCJoinChatChannel)
	{
		CMsgGCBase *pMsgBase = (CMsgGCBase*)pubDest;
		CMsgDOTAJoinChatChannelResponse msg;
		msg.ParseFromArray(pMsgBase->proto, pcubMsgSize);
		//msg.PrintDebugString();
		///Lobby_26128281349804472
		string strChannelName = msg.channel_name();
		if (strChannelName.find("Lobby") != string::npos)
		{
			size_t n = strChannelName.find("Lobby");
			string str(strChannelName.substr(6, strChannelName.length() - 6));
			dota2interface()->mRoomid = str;
			printf("roomid %s\n", dota2interface()->mRoomid.c_str());
		}
	}
	if (punMsgType == k_EMsgGCPracticeLobbyCreate)
	{
		//CMsgGCBase *pMsgBase = (CMsgGCBase*)pubDest;
		//CMsgPracticeLobbyCreate *msg = new CMsgPracticeLobbyCreate;
		CMsgGCBase *pMsgBase = (CMsgGCBase*)pubDest;
		CMsgPracticeLobbyCreate msg;
		msg.ParseFromArray(pMsgBase->proto, pcubMsgSize);
		msg.PrintDebugString();
	}
	if (punMsgType == k_EMsgGCPracticeLobbyJoin)
	{
		CMsgGCBase *pMsgBase = (CMsgGCBase*)(pubDest);
		CMsgPracticeLobbyJoin msg;
		msg.ParseFromArray(pMsgBase->proto+9, pcubMsgSize-9);
		msg.PrintDebugString();
	}
	if (punMsgType == k_EMsgGCChatMessage)
	{
// 		CMsgGCBase *pMsgBase = (CMsgGCBase*)(pubDest);
// 		CMsgDOTAChatMessage msg;
// 		msg.ParseFromArray(pMsgBase->proto, pcubMsgSize);
// 		msg.PrintDebugString();
	}
	//EGCResults result = pfnSendMessage(dwThis, 7038, (DWORD64*)cmd, 0x119);
	EGCResults result = pfnSendMessage(dwThis, punMsgType, pubDest, pcubMsgSize);
	return result;

}


BOOL FindSectionByName(HMODULE hModule, const char*SecName, PVOID &SectionBase, ULONG &SectionSize)
{
	const auto dosHeader = (PIMAGE_DOS_HEADER)hModule;
	const auto ntHeader = (PIMAGE_NT_HEADERS32)((PUCHAR)hModule + dosHeader->e_lfanew);
	const auto SectionHeaders = (PIMAGE_SECTION_HEADER)((PUCHAR)hModule + dosHeader->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + ntHeader->FileHeader.SizeOfOptionalHeader);
	for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		printf("%s\n", SectionHeaders[i].Name);
		if (!strcmp(SecName, (char*)SectionHeaders[i].Name))
		{
			SectionBase = (PUCHAR)hModule + SectionHeaders[i].VirtualAddress;
			SectionSize = SectionHeaders[i].SizeOfRawData;
			return TRUE;
		}

	}
	return FALSE;
}


LPVOID SearchPattern(LPVOID pStartSearch, DWORD dwSearchLen, char *pPattern, DWORD dwPatternLen)
{
	PUCHAR dwStartAddr = (PUCHAR)pStartSearch;
	PUCHAR dwEndAddr = dwStartAddr + dwSearchLen - dwPatternLen;

	while (dwStartAddr < dwEndAddr)
	{
		bool found = true;

		for (DWORD i = 0; i < dwPatternLen; i++)
		{
			char code = *(char *)(dwStartAddr + i);

			if (pPattern[i] != 0x2A && pPattern[i] != code)
			{
				found = false;
				break;
			}
		}

		if (found)
			return (LPVOID)dwStartAddr;

		dwStartAddr++;
	}

	return 0;
}


bool InitDotaTool(HMODULE hClient)
{
	PVOID textBase = 0;
	ULONG textSize = 0;
	if (FindSectionByName(hClient, ".text", textBase, textSize))
	{
		char GCClientSendAdd1_pattern[] = "\x48\x8B\x42\x08\x44\x8B\x4A\x18\x41\x83\xC1\xF0";
		GCClientSendAdd1 = (DWORD64)SearchPattern((PUCHAR)textBase, textSize, GCClientSendAdd1_pattern, sizeof(GCClientSendAdd1_pattern) - 1);
		if (GCClientSendAdd1)
		{
			GCClientSendAdd1 += 0x2f;
			DWORD dwOffset = *(DWORD*)GCClientSendAdd1;
			GCClientSendAdd1 = GCClientSendAdd1 + dwOffset + 4 - (DWORD64)hClient;
			printf("GCClientSendAdd1:%I64x\n", GCClientSendAdd1);
		}
		char GCClientSendAdd2_pattern[] = "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x99\x60\x01\x00\x00\x48\x8B\xF9\x83\x4B\x10\x04\x48\x83\x7B\x28\x00";
		GCClientSendAdd2 = (DWORD64)SearchPattern((PUCHAR)textBase, textSize, GCClientSendAdd2_pattern, sizeof(GCClientSendAdd2_pattern) - 1);
		if (GCClientSendAdd2)
		{
			GCClientSendAdd2 += 0x55;
			DWORD dwOffset = *(DWORD*)GCClientSendAdd2;
			GCClientSendAdd2 = GCClientSendAdd2 + dwOffset + 4;
			GCClientSendAdd2 = *(DWORD64*)GCClientSendAdd2;
			GCClientSendAdd2 += 0x18;
			GCClientSendAdd2 -= (DWORD64)hClient;
			printf("GCClientSendAdd2:%I64x\n", GCClientSendAdd2);
		}
		char GCClientTicket_pattern[] = "\x48\x89\x5C\x24\x18\x48\x89\x6C\x24\x20\x41\x56\x48\x83\xEC\x20\x8B\x41\x48\x33\xDB\x44\x8B\xF2\x48\x8B\xE9\x85\xC0\x7E\x5E\x48\x89\x74\x24\x30\x8B\xF3\x48\x89\x7C\x24\x38\x8B\xFB\x0F\x1F\x00\x48\x85\xF6\x78\x2E";
		GCClientTicket = (DWORD64)SearchPattern((PUCHAR)textBase, textSize, GCClientTicket_pattern, sizeof(GCClientTicket_pattern) - 1);
		if (GCClientSendAdd2)
		{
			GCClientTicket -= 0x10;
			DWORD dwOffset = *(DWORD*)GCClientTicket;
			GCClientTicket = GCClientTicket + dwOffset + 4 - (DWORD64)hClient;
			printf("GCClientTicket:%I64x\n", GCClientTicket);
		}
		char GPlayerIDAdrr_pattern[] = "\x74\x0B\x41\x39\x4F\x10\x75\x05\x4D\x8B\x3F\xEB\x03";
		GPlayerIDAdrr = (DWORD64)SearchPattern((PUCHAR)textBase, textSize, GPlayerIDAdrr_pattern, sizeof(GPlayerIDAdrr_pattern) - 1);
		if (GPlayerIDAdrr)
		{
			GPlayerIDAdrr += 0x13;
			DWORD dwOffset = *(DWORD*)GPlayerIDAdrr;
			GPlayerIDAdrr = GPlayerIDAdrr + dwOffset + 4 - (DWORD64)hClient;
			printf("GPlayerIDAdrr:%I64x\n", GPlayerIDAdrr);
		}
		char GGetPlayerTeamCall_pattern[] = "\x7D\xF1\x48\x63\xC2\x48\x8D\x0C\x80\x49\x8B\x81\x38\x04\x00\x00\x48\x03\xC9\x8B\x44\xC8\x20";
		GGetPlayerTeamCall = (DWORD64)SearchPattern((PUCHAR)textBase, textSize, GGetPlayerTeamCall_pattern, sizeof(GGetPlayerTeamCall_pattern) - 1);
		if (GGetPlayerTeamCall)
		{
			GGetPlayerTeamCall -= 0x2e;
			pfnGetPlayerTeam = (GetPlayerTeamFn)GGetPlayerTeamCall;
			printf("GGetPlayerTeamCall:%I64x\n", GGetPlayerTeamCall);
		}
		char GGetPlayTeamEcx_pattern[] = "\x45\x33\xC0\x49\x8B\xCE\xFF\x50\x38\x44\x8B\xF8\x3D\xFF\x00\x00\x00";
		GGetPlayTeamEcx = (DWORD64)SearchPattern((PUCHAR)textBase, textSize, GGetPlayTeamEcx_pattern, sizeof(GGetPlayTeamEcx_pattern) - 1);
		if (GGetPlayTeamEcx)
		{
			GGetPlayTeamEcx += 0x22;
			DWORD dwOffset = *(DWORD*)GGetPlayTeamEcx;
			GGetPlayTeamEcx = GGetPlayTeamEcx + dwOffset + 4 - (DWORD64)hClient;
			printf("GGetPlayTeamEcx:%I64x\n", GGetPlayTeamEcx);
		}
		char GGetGameWinnerCall_pattern[] = "\x48\x85\xC0\x75\x06\xB8\x05\x00\x00\x00\xC3";
		GGetGameWinnerCall = (DWORD64)SearchPattern((PUCHAR)textBase, textSize, GGetGameWinnerCall_pattern, sizeof(GGetGameWinnerCall_pattern) - 1);
		if (GGetGameWinnerCall)
		{
			GGetGameWinnerCall -= 0x7;
			pfnGetGameWinner = (GetGmaeWinnerFn)GGetGameWinnerCall;
			printf("GGetGameWinnerCall:%I64x\n", GGetGameWinnerCall);
		}
	}
	return true;
}
int GetGameWinner()
{
	return pfnGetGameWinner();
}
int GetPlayerId(HMODULE hClient)
{
	__try
	{
		return *(DWORD*)(*(DWORD64*)(GPlayerIDAdrr + (DWORD64)hClient)+0x1458);
	}
	__except (1)
	{
		return 0;
	}
}
int GetPlayerTeam(int nid)
{
	DWORD64 dwEcx = *(DWORD64*)(GGetPlayTeamEcx + (DWORD64)hClient);
	if (!dwEcx)return 0;
	return pfnGetPlayerTeam(dwEcx, nid);
}
void InitEcx(HMODULE hClient)
{
	
	g_ecx.a1 = (DWORD64)hClient + GCClientSendAdd1;
	g_ecx.a2 = (DWORD64)hClient + GCClientSendAdd2;
}


#define LONGFIX 2147483648
DWORD WINAPI dwMainThread(LPVOID lpArguments)
{

	while (!hClient)
	{
		Sleep(100);
		hClient = GetModuleHandleA("client.dll");
	}
	if (!InitDotaTool(hClient))
	{
		printf("init error\n");
		return 0;
	}

	DWORD64 dwSend = (DWORD64)hClient + GCClientSendAdd1;
	pfnSendMessage = (SendMessageFn)(*(DWORD64*)dwSend);
	DWORD oldflag;
	if(VirtualProtect((PVOID)dwSend, 8, PAGE_READWRITE, &oldflag))
	*(DWORD64*)dwSend = (DWORD64)MySendMessage;
	InitEcx(hClient);
	
	while (1)
	{
		if ((GetAsyncKeyState(VK_F1) & 0x8000))
		{
			//MySendMessage((DWORD64)&g_ecx, 7038, (DWORD64*)cmd, 0x130);
			CMsgGCBase pMsgBaseSend;
			CMsgPracticeLobbyCreate *msgSend = new CMsgPracticeLobbyCreate();
			msgSend->set_pass_key("111111111");
			msgSend->set_client_version(3463);
			CMsgPracticeLobbySetDetails *lobby_details = new CMsgPracticeLobbySetDetails();
			lobby_details->set_game_name("22222");
			CLobbyTeamDetails *team_details1 = lobby_details->add_team_details();
			CLobbyTeamDetails *team_details2 = lobby_details->add_team_details();
			lobby_details->set_server_region(20);
			lobby_details->set_game_mode(15);
			lobby_details->set_cm_pick(DOTA_CM_RANDOM);
			lobby_details->set_bot_difficulty_radiant(BOT_DIFFICULTY_HARD);
			lobby_details->set_allow_cheats(false);
			lobby_details->set_fill_with_bots(false);
			lobby_details->set_intro_mode(false);
			lobby_details->set_allow_spectating(true);
			lobby_details->set_game_version(GAME_VERSION_STABLE);
			lobby_details->set_pass_key("111111111");
			lobby_details->set_leagueid(0);
			lobby_details->set_penalty_level_radiant(0);
			lobby_details->set_penalty_level_dire(0);
			lobby_details->set_load_game_id(0);
			lobby_details->set_series_type(0);
			lobby_details->set_radiant_series_wins(0);
			lobby_details->set_dire_series_wins(0);
			lobby_details->set_allchat(false);
			lobby_details->set_dota_tv_delay(LobbyDotaTV_120);
			lobby_details->set_lan(true);
			lobby_details->set_custom_game_mode("1613886175");
			lobby_details->set_custom_map_name("normal");
			lobby_details->set_custom_difficulty(0);
			lobby_details->set_custom_game_id(1613886175);
			lobby_details->set_custom_min_players(1);
			lobby_details->set_custom_max_players(8);
			lobby_details->set_custom_game_crc(16163587597813023983);
			lobby_details->set_custom_game_timestamp(time(0));
			lobby_details->set_pause_setting(LobbyDotaPauseSetting_Limited);
			lobby_details->set_bot_difficulty_dire(BOT_DIFFICULTY_HARD);
			lobby_details->set_custom_game_penalties(false);
			lobby_details->set_lan_host_ping_location("pww=16+1,shb=17+1,pwg=23+2,cant=23+2,canm=54+5/23+2,canu=60+6/23+2,shat=24+2,sham=26+2/24+2,shau=39+3/24+2,pwz=27+2,pwu=36+3,sgp=231+23/83+4");
			msgSend->set_allocated_lobby_details(lobby_details);
			CMsgPracticeLobbyCreate::SaveGame *savegame = new CMsgPracticeLobbyCreate::SaveGame();
			msgSend->set_allocated_save_game(savegame);
			msgSend->SerializeToArray(pMsgBaseSend.proto, msgSend->ByteSize());
			pMsgBaseSend.header.headerLength = 0;
			pMsgBaseSend.header.msg = k_EMsgGCPracticeLobbyCreate + LONGFIX;
			MySendMessage((DWORD64)&g_ecx, k_EMsgGCPracticeLobbyCreate, (DWORD64*)&pMsgBaseSend, sizeof(pMsgBaseSend.header) + msgSend->ByteSize());
		}
		if ((GetAsyncKeyState(VK_F2) & 0x8000))
		{
			
			CMsgGCBaseEx pMsgBaseSend;
			CMsgPracticeLobbyJoin *msgSend = new CMsgPracticeLobbyJoin();
			
			msgSend->set_lobby_id(26129572850214107);
			msgSend->set_client_version(3461);
			msgSend->set_pass_key("111111111");
			msgSend->set_custom_game_crc(16163587597813023983);
			msgSend->set_custom_game_timestamp(1557419816);
			printf("%d\n", msgSend->ByteSize());
			msgSend->SerializeToArray(pMsgBaseSend.proto, msgSend->ByteSize());
			pMsgBaseSend.header.headerLength = 9;
		

			int dwCount = GetPacketCount();

			if (!dwCount)
			{
				printf("dwcount error\n");
				return 0;
			}
			memset((char*)&pMsgBaseSend.a1[0], 0, 9);
			pMsgBaseSend.a1[0] = 0x51;
			*(DWORD*)((char*)&pMsgBaseSend.a1[1]) = dwCount+1;
			pMsgBaseSend.header.msg = k_EMsgGCPracticeLobbyJoin + LONGFIX;
			MySendMessage((DWORD64)&g_ecx, k_EMsgGCPracticeLobbyJoin, (DWORD64*)&pMsgBaseSend, sizeof(pMsgBaseSend.header)+9+msgSend->ByteSize());
		}
		if ((GetAsyncKeyState(VK_F3) & 0x8000))
		{
			printf("playerid %d\n", GetPlayerId(hClient));
		}
		if ((GetAsyncKeyState(VK_F4) & 0x8000))
		{
			int nid = GetPlayerId(hClient);
			int nTeamid = GetPlayerTeam(nid);
			printf("teamid %d\n", nTeamid);
		}
		if ((GetAsyncKeyState(VK_F5) & 0x8000))
		{
			printf("winner %d\n", GetGameWinner());
		}
		Sleep(100);
	}
	return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		  	if (AllocConsole())
  			{
  				freopen("CONOUT$", "w", stdout);
  				printf("Im In!\n");
  			}
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dwMainThread, NULL, 0, NULL);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

