/*
	2022 Copyright. Eduardo Marques Braga de Faria
	www.eduardoprogramador.com
	consultoria@eduardoprogramador.com

	Todos os direitos reservados
*/

//Next Step: Test Individual Modules and make improvements...

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <WinDNS.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <string.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <VersionHelpers.h>
#include <stdbool.h>
#include <process.h>
#include <TlHelp32.h>
#include <winsock.h>
#include <mysql.h>
#include <WinInet.h>
#include "resource.h"

#define SECURITY_PORT_SCAN_BUTTON_SCAN 1
#define SECURITY_PORT_SCAN_RB_SINGLE 2
#define SECURITY_PORT_SCAN_RB_RANGE 3
#define SECURITY_DNS_CONSULT_BUTTON 4
#define INFO_SYSTEM_CONSULT_BUTTON 5
#define INFO_SYSTEM_CONSULT_BUTTON_SAVE 6
#define FILE_EDITOR_BUTTON_SAVE 7
#define FILE_EDITOR_BUTTON_OPEN 8
#define ADAPTER_BUTTON 13
#define FILE_INFO_BUTTON_CONSULT 14
#define FILE_INFO_BUTTON_OPEN 15
#define FILE_VIEW_BINARY_BUTTON_CONSULT 16
#define FILE_VIEW_BINARY_BUTTON_OPEN 17
#define TRANSFER_FILE_BUTTON_OPEN 18
#define TRANSFER_FILE_BUTTON_START 19
#define TRANSFER_FILE_RB_TRANSFER 20
#define TRANSFER_FILE_RB_RECEIVE 21
#define FILE_LIST_BUTTON_SEARCH 22
#define FILE_LIST_BUTTON_START 23
#define WHOIS_BUTTON 24
#define SMB_RB_UPLOAD 26
#define SMB_RB_DOWNLOAD 27
#define SMB_BUTTON_TRANSFER 28
#define SMB_BUTTON_SERVER 30
#define SMB_BUTTON_PATH 31
#define FILE_TRANSFER_UDP_BT_OPEN 32
#define FILE_TRANSFER_UDP_BT_START 33
#define FILE_TRANSFER_UDP_RB_RV 35
#define FILE_TRANSFER_UDP_RB_UP 34
#define OPEN_CMD_BUTTON 36
#define CONTROLLED_ACTIVE_BUTTON_CONNECT 37
#define CONTROLLER_ACTIVE_BUTTON_CONNECT 38
#define CONTROLLER_ACTIVE_BUTTON_CMD 39
#define CONTROLLED_PASSIVE_BUTTON_CONNECT 40
#define CONTROLLER_PASSIVE_BUTTON_CONNECT 41
#define CONTROLLER_PASSIVE_BUTTON_CMD 42
#define END_PROCESS_BUTTON 43
#define LIST_PROCESS_BUTTON 44
#define BUTTON_MYSQL_CONNECT 45
#define BUTTON_MYSQL_CMD 46
#define BUTTON_MYSQL_CONSULT 47
#define BUTTON_CREDENTIALS 48
#define BUTTON_CHAT_CONNECT 49
#define BUTTON_CHAT_MESSAGE 50
#define RB_CHAT_SERVER 51
#define RB_CHAT_CLIENT 52
#define BUTTON_HASH_BROWSE 53
#define BUTTON_HASH_CALCULATE 54
#define BUTTON_HASH_SEE 55
#define BUTTON_FTP_CONNECT 56
#define BUTTON_FTP_DIRECTORY 57
#define BUTTON_FTP_OK 58
#define RB_FTP_CREDENTIALS 59
#define RB_FTP_ANONYMOUS 60
#define RB_FILE_PUT 61
#define RB_FILE_GET 62
#define BUTTON_FTP_FREE 63

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "libmysql.lib")
#pragma comment(lib, "mysqlclient.lib")
#pragma warning(disable: 4996)

//credentials widgets
HWND passTitle;
HWND passEdit;
HWND passButton;
int broke = 0;
char* secret;
char* alert;
FILE* file_in, * file_out;
char* buf;
char* file_key;
char* min_buf;

//global variables - MAIN
HWND mainWindow;
HWND mainTitle;
HWND mainFoot;
HWND mainOption;
HMENU hMenu;

//variables - Port Scan
HWND titleScan;
HWND rbSingleScan;
HWND rbRangeScan;
HWND editIP;
HWND editPort;
HWND buttonScan;
HWND listScan;
HWND labelIP;
HWND labelPort;
char* c_ip;
char* c_pt;
char* scan_msg;

//variables - Dns Consult
HWND dnsTitle;
HWND dnsCb;
HWND dnsLabelInput;
HWND dnsEditInput;
HWND dnsButtonStart;
HWND dnsTextData;
char* dns_c_ip;

//variables - System Info
HWND sysConsultTitle;
HWND sysConsultTextData;
HWND sysConsultButton;
HWND sysConsultButtonSave;
char* sysConsult_c_result[10 * 1024];
OPENFILENAME ofn, * p_ofn;
char* szFile[252];

//variables - text editor
HWND editorTitle;
HWND editorTextData;
HWND editorButtonSave;
HWND editorButtonOpen;
char* editInput[100 * 1024];

//variables - Network adapters
HWND adapterTitle;
HWND adapterTextData;
HWND adapterButton;

//variables - file archive info
HWND fileInfoTitle;
HWND fileInfoTextData;
HWND fileInfoButtonConsult;
HWND fileInfoButtonOpen;
char* paths[252] = { 0 };

//variables - read binary
HWND readBinaryTitle;
HWND readBinaryTextData;
HWND readBinaryButtonConsult;
HWND readBinaryButtonOpen;
char* path_binary[252] = { 0 };

//variables - file transfer
HWND fileTransferTitle;
HWND fileTransferRbTransfer;
HWND fileTransferRbReceive;
HWND fileTransferButtonOpen;
HWND fileTransferButtonStart;
HWND fileTransferTextData;
HWND fileTransferLabelIP;
HWND fileTransferLabelPort;
HWND fileTransferEditIP;
HWND fileTransferEditPort;
char* c_filetransfer[252] = { 0 };

//variables - list files
HWND listFileTitle;
HWND listFileLabelPath;
HWND listFileEditPath;
HWND listFileButtonSearch;
HWND listFileButtonStart;
HWND listFileTextData;

//variables - whois
HWND whoisTitle;
HWND whoisLabel;
HWND whoisEdit;
HWND whoisButton;
HWND whoisTextData;

//variables - SMB Client
HWND smbTitle;
HWND smbLabelHost;
HWND smbEditHost;
HWND smbButtonHost;
HWND smbRbUpload;
HWND smbRbDownload;
HWND smbButtonUpload;
HWND smbLabelPath;
HWND smbEditPath;
HWND smbButtonPath;
HWND smbTextData;

//variables - file transfer UDP
HWND fileTransferTitleUdp;
HWND fileTransferRbTransferUdp;
HWND fileTransferRbReceiveUdp;
HWND fileTransferButtonOpenUdp;
HWND fileTransferButtonStartUdp;
HWND fileTransferTextDataUdp;
HWND fileTransferLabelIPUdp;
HWND fileTransferLabelPortUdp;
HWND fileTransferEditIPUdp;
HWND fileTransferEditPortUdp;
char* c_filetransferUdp[252] = { 0 };

//variables - open cmd
HWND openCmdTitle;
HWND openCmdLabel;
HWND openCmdEdit;
HWND openCmdButton;
HWND openCmdTextData;

//variables - controlled active 
HWND controlledActiveTitle;
HWND controlledActiveTextData;
HWND controlledActiveLabelPort;
HWND controlledActiveEditPort;
HWND controlledActiveButtonServer;

//variables - controller active 
HWND controllerActiveTitle;
HWND controllerActiveTextData;
HWND controllerActiveLabelIP;
HWND controllerActiveEditIP;
HWND controllerActiveButtonConnect;
HWND controllerActiveLabelPort;
HWND controllerActiveEditPort;
HWND controllerActiveLabelCmd;
HWND controllerActiveEditCmd;
HWND controllerActiveButtonCmd;
SOCKET con_actv;
SOCKADDR_IN serv_actv;
BOOL IS_CONNECTED;
int s_len_actv;
char* result_actv;

//variables - controlled passiv
HWND controlledPassiveTitle;
HWND controlledPassiveTextData;
HWND controlledPassiveLabelIP;
HWND controlledPassiveEditIP;
HWND controlledPassiveButtonConnect;
HWND controlledPassiveLabelPort;
HWND controlledPassiveEditPort;
SOCKET ns, ls;
SOCKADDR_IN serv;
BOOL IS_CONNECTED;
int s_len, c_len, res;
char* result;
char temp[20] = { 0 };

//variables - controller passive
HWND controllerPassiveTitle;
HWND controllerPassiveTextData;
HWND controllerPassiveLabelPort;
HWND controllerPassiveEditPort;
HWND controllerPassiveButtonServer;
HWND controllerPassiveLabelCmd;
HWND controllerPassiveEditCmd;
HWND controllerPassiveButtonCmd;

//variables - finish process
HWND endProcessTitle;
HWND endProcessLabel;
HWND endProcessEdit;
HWND endProcessButton;
HWND endProcessTextData;

//variables - process lists
HWND listProcessTitle;
HWND listProcessTextData;
HWND listProcessButton;

//variables - mysql
HWND mysqlTitle;
HWND mysqlLabelHost;
HWND mysqlEditHost;
HWND mysqlLabelPort;
HWND mysqlEditPort;
HWND mysqlButtonConnect;
HWND mysqlLabelCmd;
HWND mysqlEditCmd;
HWND mysqlButtonCmd;
HWND mysqlTextData;
HWND mysqlLabelUser;
HWND mysqlEditUser;
HWND mysqlLabelDb;
HWND mysqlEditDb;
HWND mysqlLabelPass;
HWND mysqlEditPass;
HWND mysqlButtonConsult;
MYSQL* con;
MYSQL_RES* result_set;
MYSQL_ROW row;
MYSQL_FIELD* field;
char* result_mysql;

//variables - chat
HWND chatTitle;
HWND chatLbRbMode;
HWND chatRbServer;
HWND chatRbClient;
HWND chatLbIp;
HWND chatEditIp;
HWND chatLbPort;
HWND chatEditPort;
HWND chatButtonConnect;
HWND chatTextData;
HWND chatLbMessage;
HWND chatEditMessage;
HWND chatButtonMessage;
WSADATA wsadata;
SOCKET lsChat, nsChat;
SOCKADDR_IN servChat, cliChat;
int resChat, sLenChat, cLenChat;
char* result_chat, * ip_chat, * port_chat;
IN_ADDR ip_chat_addr;
BOOL IS_CHAT_CONNECTED = FALSE;

//variables - hash
HWND hashTitle;
HWND hashLbFile;
HWND hashEditFile;
HWND hashButtonBrowse;
HWND hashTextData;
HWND hashButtonCalculate;
HWND hashButtonSee;
char hash_file[255];
char* result_hash;

//variables - ftp
HWND ftpTitle;
HWND ftpLbIp;
HWND ftpEditIp;
HWND ftpLbPort;
HWND ftpEditPort;
HWND ftpLbUser;
HWND ftpEditUser;
HWND ftpLbPass;
HWND ftpEditPass;
HWND ftpLbModeAccess;
HWND ftpRbCredentials;
HWND ftpRbAnonymous;
HWND ftpButtonConnect;
HWND ftpLbDirectory;
HWND ftpEditDirectory;
HWND ftpButtonDirectory;
HWND ftpButtonFree;
HWND ftpLbModeTransfer;
HWND ftpRbPut;
HWND ftpRbGet;
HWND ftpLbFile;
HWND ftpEditFile;
HWND ftpButtonOk;
HWND ftpTextData;
WIN32_FIND_DATA data_ftp;
char* result_ftp, * ip_ftp, * port_ftp, * user_ftp, * pass_ftp;
char* directory_ftp, * file_ftp;
HINTERNET hInternet, hFtp, hFind;
BOOL IS_FTP_CONNECTED = FALSE;

//bitmaps
HBITMAP hBitmap;
BITMAP bitmap;
HDC hdc, hdcMem, g;
PAINTSTRUCT ps;

//fonts
LOGFONT logfont;
HFONT hFont;

//functions
void scanLayout();
void dnsLayout();
void sysInfoLayout();
void editorLayout();
void adapterLayout();
void fileInfoLayout();
void readBinaryLayout();
void fileTransferLayout();
void fileListLayout();
void whoisLayout();
void smbLayout();
void fileTransferUdpLayout();
void openCmdLayout();
void controlledActiveLayout();
void controllerActiveLayout();
void controlledPassiveLayout();
void controllerPassiveLayout();
void endProcessLayout();
void listProcessLayout();
void mysqlLayout();
void chatLayout();
void hashLayout();
void ftpLayout();

void scanPortsSingle()
{
	WSADATA wsadata;
	SOCKET s;
	SOCKADDR_IN sAddr, * p_addr;
	char* response, * c_ip, * c_port;

	int res_wsadata = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (res_wsadata != 0)
	{
		MessageBox(mainWindow, "Error starting scan module", "Error", MB_ICONERROR);
	}

	c_ip = (char*)malloc(100);
	c_port = (char*)malloc(10);
	response = (char*)malloc(100);

	GetWindowText(editIP, c_ip, 100);
	GetWindowText(editPort, c_port, 10);

	if (c_ip == NULL || c_port == NULL)
	{
		MessageBox(mainWindow, "Please provide a valid IP or port number", "Error", MB_ICONERROR);
	}

	memset(&sAddr, 0, sizeof(SOCKADDR_IN));
	sAddr.sin_family = AF_INET;
	sAddr.sin_port = htons(atoi(c_port));
	sAddr.sin_addr.S_un.S_addr = inet_addr(c_ip);
	p_addr = &sAddr;

	s = socket(p_addr->sin_family, SOCK_STREAM, IPPROTO_TCP);
	if (!s)
	{
		MessageBox(mainWindow, "Error creating socket", "Error", MB_ICONERROR);
	}

	int rc = connect(s, (SOCKADDR*)p_addr, sizeof(*p_addr));

	if (rc != 0)
	{		
		strcpy(response, "The port ");
		strcat(response, c_port);
		strcat(response, " is closed.");
	}
	else
	{
		strcpy(response, "The port ");
		strcat(response, c_port);
		strcat(response, " is open.");
	}

	SendMessage(listScan, LB_ADDSTRING, 0, (LPARAM)response);

}

void scanPortsRange()
{
	WSADATA wsadata;
	SOCKET s;
	SOCKADDR_IN sAddr, * p_addr;
	char* response, * c_ip, * c_port, * p, * c_show_port;
	char* port_arr_str[100][5];
	int port_arr_int[100];
	TIMEVAL timeval;

	int res_wsadata = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (res_wsadata != 0)
	{
		MessageBox(mainWindow, "Error starting scan module", "Error", MB_ICONERROR);
	}

	c_ip = (char*)malloc(100);
	c_port = (char*)malloc(1024);
	response = (char*)malloc(1024);
	c_show_port = (char*)malloc(10);

	GetWindowText(editIP, c_ip, 100);
	GetWindowText(editPort, c_port, 1024);

	if (c_ip == NULL || c_port == NULL)
	{
		MessageBox(mainWindow, "Please provide a valid IP or port number", "Error", MB_ICONERROR);
	}

	p = strtok(c_port, ",");
	strcpy(port_arr_str[0], p);
	int count = 0;
	while ((p = strtok(NULL, ",")) != NULL)
	{
		count++;
		strcpy(port_arr_str[count], p);
	}

	//convert char array of ports into integer array of ports
	for (int i = 0; i < 100; i++)
	{
		port_arr_int[i] = atoi(port_arr_str[i]);
	}

	//interact with different socket connections (different ports)
	//CONTINUE
	//TRY to set timeout with socket to complete this STEP.
	for (int i = 0; i < 100; i++)
	{
		if (port_arr_int[i] == 0)
			continue;

		memset(&sAddr, 0, sizeof(SOCKADDR_IN));
		sAddr.sin_family = AF_INET;
		sAddr.sin_port = htons(port_arr_int[i]);
		sAddr.sin_addr.S_un.S_addr = inet_addr(c_ip);
		p_addr = &sAddr;

		s = socket(p_addr->sin_family, SOCK_STREAM, IPPROTO_TCP);

		int res_con = connect(s, (SOCKADDR*)p_addr, sizeof(*p_addr));

		if (res_con != 0)
		{
			strcpy(response, "The port ");
			strcat(response, port_arr_str[i]);
			strcat(response, " is closed.");
		}
		else
		{
			strcpy(response, "The port ");
			strcat(response, port_arr_str[i]);
			strcat(response, " is open.");
		}

		SendMessage(listScan, LB_ADDSTRING, 0, response);

	}
}

void dnsConsultByName()
{
	DNS_RECORD dns_rec, * p_dns;
	PDNS_RECORD dnsr = NULL;
	PIP4_ARRAY s_add_arr;
	IN_ADDR ip_ad;
	DNS_STATUS dns_st;
	char* f_ip;
	char* o_msg[1024];
	DNS_FREE_TYPE free_type;

	s_add_arr = (PIP4_ARRAY)LocalAlloc(LPTR, sizeof(IP4_ARRAY));
	s_add_arr->AddrCount = 1;
	s_add_arr->AddrArray[0] = inet_addr("8.8.8.8");
	f_ip = (char*)malloc(255);

	memset(&dns_rec, 0, sizeof(DNS_RECORD));
	p_dns = &dns_rec;


	if ((dns_st = DnsQuery(dns_c_ip, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, s_add_arr, &p_dns, NULL)) != 0)
	{
		MessageBox(mainWindow, "DNS query error. Check your Internet connection and the host used.", "Error", MB_ICONERROR);
	}

	else if ((dns_st = DnsQuery(dns_c_ip, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, s_add_arr, &p_dns, NULL)) == 0)

	{
		ip_ad.S_un.S_addr = p_dns->Data.A.IpAddress;
		strcpy(f_ip, inet_ntoa(ip_ad));
		strcpy(o_msg, "The host's IP address ");
		strcat(o_msg, dns_c_ip);
		strcat(o_msg, " is ");
		strcat(o_msg, f_ip);

		SetWindowText(dnsTextData, o_msg);
		free_type = DnsFreeRecordListDeep;
		DnsFree(p_dns, free_type);
	}
}

void dnsConsultByIP()
{
	//declare variables
	DNS_RECORD dns_rec, * p_rec;
	DNS_FREE_TYPE free_type;
	PIP4_ARRAY s_addr_arr;
	char* ip_blocks[4][4];
	char* result[1024];

	//initializes variables
	dns_c_ip = (char*)malloc(255);
	ZeroMemory(&dns_rec, sizeof(DNS_RECORD));
	p_rec = &dns_rec;
	free_type = DnsFreeRecordListDeep;
	s_addr_arr = (PIP4_ARRAY)malloc(sizeof(IP4_ARRAY));
	s_addr_arr->AddrCount = 1;
	s_addr_arr->AddrArray[0] = inet_addr("8.8.8.8");

	//reverse ip address and create four blocks of ip;
	GetWindowText(dnsEditInput, dns_c_ip, 255);
	char* p;
	p = strtok(dns_c_ip, ".");
	strcpy(ip_blocks, p);

	int now_or = 1;
	while ((p = strtok(NULL, ".")) != NULL)
	{
		strcpy(ip_blocks[now_or], p);
		now_or++;
	}

	char* reversedIP[255];
	strcpy(reversedIP, ip_blocks[3]);
	strcat(reversedIP, ".");
	strcat(reversedIP, ip_blocks[2]);
	strcat(reversedIP, ".");
	strcat(reversedIP, ip_blocks[1]);
	strcat(reversedIP, ".");
	strcat(reversedIP, ip_blocks[0]);
	strcat(reversedIP, ".");
	strcat(reversedIP, "IN-ADDR.ARPA");

	//call functions
	int r_code;
	if ((r_code = DnsQuery(reversedIP, DNS_TYPE_PTR, DNS_QUERY_BYPASS_CACHE, s_addr_arr, &p_rec, NULL)) != 0)
	{
		MessageBox(mainWindow, "DNS query error. Check your Internet connection and the host used.", "Error", MB_ICONERROR);
	}
	else
	{
		strcpy(result, "The IP ");
		strcat(result, ip_blocks[0]);
		strcat(result, ".");
		strcat(result, ip_blocks[1]);
		strcat(result, ".");
		strcat(result, ip_blocks[2]);
		strcat(result, ".");
		strcat(result, ip_blocks[3]);
		strcat(result, " belongs to ");
		strcat(result, p_rec->Data.CNAME.pNameHost);
		SetWindowText(dnsTextData, result);
		DnsFree(p_rec, free_type);

	}

}

void retrieveSysInfo()
{
	//computer name
	char* temp[100];
	DWORD cLen = sizeof(temp);
	GetComputerName(temp, &cLen);
	strcpy(sysConsult_c_result, "Computer name: ");
	strcat(sysConsult_c_result, temp);


	//username
	char* user[100];
	DWORD ulen = 100;
	GetUserNameA(user, &ulen);
	strcat(sysConsult_c_result, "\r\nUser name: ");
	strcat(sysConsult_c_result, user);

	//windows version
	if (IsWindows10OrGreater)
	{
		strcat(sysConsult_c_result, "\r\nWindows Version: Windows 10");
	}
	else if (IsWindows8Point1OrGreater && !IsWindows10OrGreater)
	{
		strcat(sysConsult_c_result, "\r\nWindows Version: Windows 8.1");
	}
	else if (IsWindows8OrGreater && !IsWindows8Point1OrGreater && !IsWindows10OrGreater)
	{
		strcat(sysConsult_c_result, "\r\nWindows Version: Windows 8");
	}
	else if (IsWindows7OrGreater && !IsWindows8OrGreater && !IsWindows8Point1OrGreater && !IsWindows10OrGreater)
	{
		strcat(sysConsult_c_result, "\r\nWindows Version: Windows 7");
	}
	else if (IsWindowsServer)
	{
		strcat(sysConsult_c_result, "\r\nWindows Version: Windows Server");
	}
	else if (IsWindowsVistaOrGreater && !IsWindows7OrGreater && !IsWindows7SP1OrGreater && !IsWindows8OrGreater && !IsWindows8Point1OrGreater && !IsWindows10OrGreater)
	{
		strcat(sysConsult_c_result, "\r\nWindows Version: Windows Vista");
	}
	else if (IsWindowsXPOrGreater && !IsWindowsVistaOrGreater && !IsWindows7OrGreater && !IsWindows8OrGreater && !IsWindows8Point1OrGreater && !IsWindows10OrGreater)
	{
		strcat(sysConsult_c_result, "\r\nWindows Version: Windows XP");
	}


	//diskinformation
	DISK_SPACE_INFORMATION dsi, * p_dsi;
	ZeroMemory(&dsi,sizeof(DISK_SPACE_INFORMATION));
	p_dsi = &dsi;
	DWORD sc;
	DWORD bps;
	DWORD fc;
	DWORD tc;
	unsigned long long u1, u2, u3;
	char* c_u1[100], * c_u2[100], * c_u3[100];


	GetDiskFreeSpace("C:", &sc, &bps, &fc, &tc);
	char* a[10], * b[10], * c[10], * d[10];
	strcat(sysConsult_c_result, "\r\nDisk space analysis on drive 'C':");
	sprintf(a, "%ld", sc); //sectorsper clusters
	sprintf(b, "%ld", bps); //bytes per sector
	sprintf(c, "%ld", fc); //free clusters
	sprintf(d, "%ld", tc); //total of clusters
	strcat(sysConsult_c_result, "\r\nSector by cluster:");
	strcat(sysConsult_c_result, a);
	strcat(sysConsult_c_result, "\r\nBytes by sector: ");
	strcat(sysConsult_c_result, b);
	strcat(sysConsult_c_result, "\r\nClusters available: ");
	strcat(sysConsult_c_result, c);
	strcat(sysConsult_c_result, "\r\nTotal of clusters: ");
	strcat(sysConsult_c_result, d);

	SHGetDiskFreeSpace("C:\\", &u1, &u2, &u3);
	sprintf(c_u3, "%lld", u3);

	strcat(sysConsult_c_result, "\r\nFree disk space (bytes):");
	strcat(sysConsult_c_result, c_u3);


	//localtime
	SYSTEMTIME systime;
	memset(&systime, 0, sizeof(SYSTEMTIME));
	GetLocalTime(&systime);
	char* tmp_day[20];
	char* tmp_hour[20];
	char* tmp_minute[20];
	char* tmp_month[20];
	char* tmp_year[20];
	WORD day = systime.wDay;
	WORD hour = systime.wHour;
	WORD minute = systime.wMinute;
	WORD month = systime.wMonth;
	WORD year = systime.wYear;
	strcat(sysConsult_c_result, "\r\nLocal Time: ");
	sprintf(tmp_day, "%d", day);
	sprintf(tmp_hour, "%d", hour);
	sprintf(tmp_minute, "%d", minute);
	sprintf(tmp_month, "%d", month);
	sprintf(tmp_year, "%d", year);
	strcat(sysConsult_c_result, tmp_day);
	strcat(sysConsult_c_result, "/");
	strcat(sysConsult_c_result, tmp_month);
	strcat(sysConsult_c_result, "/");
	strcat(sysConsult_c_result, tmp_year);
	strcat(sysConsult_c_result, " -> ");
	strcat(sysConsult_c_result, tmp_hour);
	strcat(sysConsult_c_result, ":");
	strcat(sysConsult_c_result, tmp_minute);

	//memory ram
	MEMORYSTATUS ram, * p_ram;
	ZeroMemory(&ram,sizeof(MEMORYSTATUS));
	p_ram = &ram;
	GlobalMemoryStatus(p_ram);
	size_t aphy = p_ram->dwAvailPhys;
	size_t avir = p_ram->dwAvailVirtual;
	size_t mload = p_ram->dwMemoryLoad;
	size_t tphy = p_ram->dwTotalPhys;
	size_t tvir = p_ram->dwTotalVirtual;
	char* c_aphy[20];
	char* c_avir[20];
	char* c_mload[20];
	char* c_tphy[20];
	char* c_tvir[20];
	ULONGLONG rammem;
	char* c_rammem[20];
	sprintf(c_aphy, "%ld", aphy);
	sprintf(c_avir, "%ld", avir);
	sprintf(c_mload, "%ld", mload);
	sprintf(c_tphy, "%ld", tphy);
	sprintf(c_tvir, "%ld", tvir);
	strcat(sysConsult_c_result, "\r\nTotal physical memory:");
	strcat(sysConsult_c_result, c_tphy);
	strcat(sysConsult_c_result, "\r\nAvailable physical memory:");
	strcat(sysConsult_c_result, c_aphy);
	strcat(sysConsult_c_result, "\r\nTotal virtual memory:");
	strcat(sysConsult_c_result, c_tvir);
	strcat(sysConsult_c_result, "\r\nAvailable virtual memory:");
	strcat(sysConsult_c_result, c_avir);
	strcat(sysConsult_c_result, "\r\nLoaded memory:");
	strcat(sysConsult_c_result, c_mload);
	GetPhysicallyInstalledSystemMemory(&rammem);
	strcat(sysConsult_c_result, "\r\nInstalled memory in Kilobyte:");
	sprintf(c_rammem, "%lld", rammem);
	strcat(sysConsult_c_result, c_rammem);

	//battery
	SYSTEM_POWER_STATUS ps, * p_ps;
	ZeroMemory(&ps, sizeof(SYSTEM_POWER_STATUS));
	p_ps = &ps;
	GetSystemPowerStatus(p_ps);
	BYTE bltp = p_ps->BatteryLifePercent;


	char* c_bltp[20];

	strcat(sysConsult_c_result, "\r\nBattery percentage:");
	sprintf(c_bltp, "%d", bltp);
	strcat(sysConsult_c_result, c_bltp);


	SYSTEM_INFO si;
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	WORD pa = si.wProcessorArchitecture;
	switch (pa)
	{
	case 0:
		strcat(sysConsult_c_result, "\r\nProcessor architecture: x86");
		break;

	case 5:
		strcat(sysConsult_c_result, "\r\nProcessador architeture: ARM");
		break;

	case 6:
		strcat(sysConsult_c_result, "\r\nProcessador architeture: Intel Itanium-based");
		break;

	case 9:
		strcat(sysConsult_c_result, "\r\nProcessador architeture: x64");
		break;

	case 12:
		strcat(sysConsult_c_result, "\r\nProcessador architeture: ARM64");
		break;

	default:
		strcat(sysConsult_c_result, "\r\nProcessador architeture: Unkown");
		break;
	}

	SYSTEM_LOGICAL_PROCESSOR_INFORMATION pi;
	ZeroMemory(&pi, sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
	char* pn[10];
	sprintf(pn, "%d", si.dwNumberOfProcessors);
	strcat(sysConsult_c_result, "\r\nNumber of processors:");
	strcat(sysConsult_c_result, pn);

	SetWindowText(sysConsultTextData, sysConsult_c_result);

}

void saveTextToFile()
{
	ZeroMemory(&ofn, sizeof(OPENFILENAME));
	p_ofn = &ofn;
	FILE* file;
	GetWindowText(editorTextData, editInput, sizeof(editInput));

	p_ofn->hwndOwner = mainWindow;
	p_ofn->lpstrFile = szFile;
	p_ofn->lpstrFilter = "Text Files (.txt)\0*.txt\0";
	p_ofn->lpstrInitialDir = NULL;
	p_ofn->lStructSize = sizeof(*p_ofn);
	p_ofn->nMaxFile = sizeof(szFile);

	if (GetSaveFileName(p_ofn) == TRUE)
	{
		strcat(szFile, ".txt");
		file = fopen(szFile, "w");
		fwrite(editInput, sizeof(editInput), 1, file);
		fclose(file);
	}
}

void openText()
{
	ZeroMemory(&ofn, sizeof(OPENFILENAME));
	p_ofn = &ofn;
	FILE* file;
	char* szFileData[100 * 1024];

	p_ofn->hwndOwner = mainWindow;
	p_ofn->lpstrFile = szFile;
	p_ofn->lpstrFilter = "Text Files (.txt)\0*.txt\0";
	p_ofn->lpstrInitialDir = NULL;
	p_ofn->lStructSize = sizeof(*p_ofn);
	p_ofn->nMaxFile = sizeof(szFile);

	if (GetOpenFileName(p_ofn) == TRUE)
	{
		file = fopen(szFile, "r");
		fread(szFileData, sizeof(szFileData), 1, file);
		SetWindowText(editorTextData, szFileData);
		fclose(file);
	}
}

const char* getAdaptersOnlyNetParams()
{
	//declare
	FIXED_INFO* p_fi;
	DWORD fi_res, fi_len;
	char* result_params;

	//initializes
	p_fi = (FIXED_INFO*)malloc(sizeof(FIXED_INFO));
	fi_len = sizeof(FIXED_INFO);
	result_params = (char*)malloc(10 * 1024);

	//functions
	if ((fi_res = GetNetworkParams(p_fi, &fi_len)) == ERROR_BUFFER_OVERFLOW)
	{
		free(p_fi);
		p_fi = (FIXED_INFO*)malloc(fi_len);
		if (!p_fi)
			MessageBox(mainWindow, "Error allocating memory for calling some functions", "Error", MB_ICONERROR);
	}

	if ((fi_res = GetNetworkParams(p_fi, &fi_len)) == NO_ERROR)
	{
		strcpy(result_params, "DNS Setting:\r\n\r\n");

		strcat(result_params, "Domain name: ");
		strcat(result_params, p_fi->DomainName);
		strcat(result_params, "\r\nHost name: ");
		strcat(result_params, p_fi->HostName);

		switch (p_fi->NodeType)
		{
		case BROADCAST_NODETYPE:
			strcat(result_params, "\r\nType: Broadcast");
			break;

		case HYBRID_NODETYPE:
			strcat(result_params, "\r\nType: Hibrid");
			break;

		case MIXED_NODETYPE:
			strcat(result_params, "\r\nType: Mixed");
			break;

		case PEER_TO_PEER_NODETYPE:
			strcat(result_params, "\r\nType: Peer to peer");
			break;

		default:
			strcat(result_params, "\r\nType: Not identified");
			break;
		}

		strcat(result_params, "\r\n\r\nDNS Server 1: \r\n");
		strcat(result_params, "\r\nIP: ");
		strcat(result_params, p_fi->DnsServerList.IpAddress.String);
		strcat(result_params, "\r\nNetmask: ");
		strcat(result_params, p_fi->DnsServerList.IpMask.String);

		strcat(result_params, "\r\n\r\nDNS Server 2:\r\n");
		strcat(result_params, "\r\nIP: ");
		strcat(result_params, p_fi->DnsServerList.Next->IpAddress.String);
		strcat(result_params, "\r\nNetmask: ");
		strcat(result_params, p_fi->DnsServerList.Next->IpMask.String);

		return result_params;
		free(p_fi);

	}
	else
	{
		return NULL;
	}
}

void getAdapters()
{
	//declare
	IP_ADAPTER_INFO* p_ai;
	DWORD ai_res, ai_len;
	char* result;
	int count = 0;

	//initializes
	p_ai = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	ai_len = sizeof(IP_ADAPTER_INFO);
	result = (char*)malloc(20 * 1024);

	//fuctions
	if ((ai_res = GetAdaptersInfo(p_ai, &ai_len)) == ERROR_BUFFER_OVERFLOW)
	{
		free(p_ai);
		p_ai = (IP_ADAPTER_INFO*)malloc(ai_len);
		if (!p_ai)
			MessageBox(mainWindow, "Error allocating memory for tracing network adapters", "Error", MB_ICONERROR);
	}

	if ((ai_res = GetAdaptersInfo(p_ai, &ai_len)) == NO_ERROR)
	{
		strcpy(result, "Net Adapters:\r\n\r\n");


		while (p_ai)
		{
			count++;

			strcat(result, "[*] Adapter number ");
			char cc[20];
			sprintf(cc, "%d", count);
			strcat(result, cc);
			strcat(result, "\r\nAdapter Name: ");
			strcat(result, p_ai->AdapterName);
			char* address[200];
			sprintf(address, "%ld", p_ai->Address);
			strcat(result, "\r\nAdapter Address: ");
			strcat(result, address);
			char* index[10];
			sprintf(index, "%d", p_ai->ComboIndex);
			strcat(result, "\r\nIndex: ");
			strcat(result, index);
			strcat(result, "\r\nDescription: ");
			strcat(result, p_ai->Description);
			strcat(result, "\r\nIP: ");
			strcat(result, p_ai->IpAddressList.IpAddress.String);
			strcat(result, "\r\nNetmask: ");
			strcat(result, p_ai->IpAddressList.IpMask.String);
			if (p_ai->DhcpEnabled == 0)
			{
				strcat(result, "\r\nDHCP enabled: No");
			}
			else
			{
				strcat(result, "\r\nDHCP enabled: Yes");
				strcat(result, "\r\nDHCP Server IP: ");
				strcat(result, p_ai->DhcpServer.IpAddress.String);
				strcat(result, "\r\nDHCP Server Netmask: ");
				strcat(result, p_ai->DhcpServer.IpMask.String);

			}

			strcat(result, "\r\nRouter IP: ");
			strcat(result, p_ai->GatewayList.IpAddress.String);
			strcat(result, "\r\nRouter Netmask: ");
			strcat(result, p_ai->GatewayList.IpMask.String);
			switch (p_ai->Type)
			{
			case MIB_IF_TYPE_ETHERNET:
				strcat(result, "\r\nAdapter Type: Ethernet\r\n\r\n");
				break;

			case MIB_IF_TYPE_FDDI:
				strcat(result, "\r\nAdapter Type: FDDI\r\n\r\n");
				break;

			case MIB_IF_TYPE_LOOPBACK:
				strcat(result, "\r\nAdapter Type: Loopback\r\n\r\n");
				break;

			case MIB_IF_TYPE_OTHER:
				strcat(result, "\r\nAdapter Type: Outros\r\n\r\n");
				break;

			case MIB_IF_TYPE_PPP:
				strcat(result, "\r\nAdapter Type: PPP\r\n\r\n");
				break;

			case MIB_IF_TYPE_SLIP:
				strcat(result, "\r\nAdapter Type: Slip\r\n\r\n");
				break;

			case MIB_IF_TYPE_TOKENRING:
				strcat(result, "\r\nAdapter Type: Token Ring\r\n\r\n");
				break;

			default:
				strcat(result, "\r\nAdapter Type: Não identificado\r\n\r\n");
				break;

			}

			p_ai = p_ai->Next;
		}

		char* other_call = getAdaptersOnlyNetParams();
		if (other_call)
			strcat(result, other_call);
		SetWindowText(adapterTextData, result);
		free(p_ai);
		free(result);

	}
	else
	{
		MessageBox(mainWindow, "Error trying to start the network adapter module. Try again!", "Error", MB_ICONERROR);
	}
}

void retrieveFileInformation()
{
	//declare
	SHFILEINFO shfi, * p_shfi;
	DWORD sh_res, sh_size;
	HANDLE hFile = NULL;
	DWORD file_len = 0;
	char* result;
	FILETIME ct, at, wt;
	SYSTEMTIME st;
	HICON hIcon = NULL;
	HDC hdc = NULL;


	//initializes
	hdc = GetDC(mainWindow);
	memset(&st, 0, sizeof(SYSTEMTIME));
	ZeroMemory(&ct, sizeof(FILETIME));
	ZeroMemory(&at, sizeof(FILETIME));
	ZeroMemory(&wt, sizeof(FILETIME));
	ZeroMemory(&shfi, sizeof(SHFILEINFO));
	sh_size = sizeof(SHFILEINFO);
	p_shfi = &shfi;
	result = (char*)malloc(10 * 1024);
	hFile = CreateFile(paths, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
		MessageBox(mainWindow, "Error trying to read selected file. Try again.", "Error", MB_OK);

	//functions
	file_len = GetFileSize(hFile, NULL);
	char* flen[200] = { 0 };
	sprintf(flen, "%ld", file_len);
	strcpy(result, "[*] File analysis: ");
	strcat(result, paths);
	strcat(result, "\r\n\r\nSize: ");
	strcat(result, flen);
	strcat(result, " bytes.");

	if (GetFileTime(hFile, &ct, &at, &wt) == TRUE)
	{
		if (FileTimeToSystemTime(&ct, &st) == TRUE)
		{
			strcat(result, "\r\nCreation Time: ");
			char* day[10] = { 0 };
			char* mon[10] = { 0 };
			char* year[10] = { 0 };
			char* hour[10] = { 0 };
			char* min[10] = { 0 };
			char* sec[10] = { 0 };
			sprintf(day, "%d", st.wDay);
			sprintf(mon, "%d", st.wMonth);
			sprintf(year, "%d", st.wYear);
			sprintf(hour, "%d", st.wHour);
			sprintf(min, "%d", st.wMinute);
			sprintf(sec, "%d", st.wMilliseconds);
			strcat(result, day);
			strcat(result, "/");
			strcat(result, mon);
			strcat(result, "/");
			strcat(result, year);
			strcat(result, " às ");
			strcat(result, hour);
			strcat(result, ":");
			strcat(result, min);
			strcat(result, ":");
			strcat(result, sec);
			ZeroMemory(&st, sizeof(SYSTEMTIME));
		}

		if (FileTimeToSystemTime(&at, &st) == TRUE)
		{
			strcat(result, "\r\nLast modified date:");
			char* day[10] = { 0 };
			char* mon[10] = { 0 };
			char* year[10] = { 0 };
			char* hour[10] = { 0 };
			char* min[10] = { 0 };
			char* sec[10] = { 0 };
			sprintf(day, "%d", st.wDay);
			sprintf(mon, "%d", st.wMonth);
			sprintf(year, "%d", st.wYear);
			sprintf(hour, "%d", st.wHour);
			sprintf(min, "%d", st.wMinute);
			sprintf(sec, "%d", st.wMilliseconds);
			strcat(result, day);
			strcat(result, "/");
			strcat(result, mon);
			strcat(result, "/");
			strcat(result, year);
			strcat(result, " às ");
			strcat(result, hour);
			strcat(result, ":");
			strcat(result, min);
			strcat(result, ":");
			strcat(result, sec);
			ZeroMemory(&st, sizeof(SYSTEMTIME));
		}

		if (FileTimeToSystemTime(&wt, &st) == TRUE)
		{
			strcat(result, "\r\nLast access date:");
			char* day[10] = { 0 };
			char* mon[10] = { 0 };
			char* year[10] = { 0 };
			char* hour[10] = { 0 };
			char* min[10] = { 0 };
			char* sec[10] = { 0 };
			sprintf(day, "%d", st.wDay);
			sprintf(mon, "%d", st.wMonth);
			sprintf(year, "%d", st.wYear);
			sprintf(hour, "%d", st.wHour);
			sprintf(min, "%d", st.wMinute);
			sprintf(sec, "%d", st.wMilliseconds);
			strcat(result, day);
			strcat(result, "/");
			strcat(result, mon);
			strcat(result, "/");
			strcat(result, year);
			strcat(result, " às ");
			strcat(result, hour);
			strcat(result, ":");
			strcat(result, min);
			strcat(result, ":");
			strcat(result, sec);
			ZeroMemory(&st, sizeof(SYSTEMTIME));
		}

	}
	else
	{
		MessageBox(mainWindow, "Error getting access information for specified file", "Error", MB_ICONERROR);
	}

	CloseHandle(hFile);

	if ((sh_res = SHGetFileInfo(paths, 0, p_shfi, sh_size, SHGFI_ATTRIBUTES | SHGFI_DISPLAYNAME | SHGFI_ICON | SHGFI_SMALLICON | SHGFI_TYPENAME)) == 1)
	{
		strcat(result, "\r\nFile type: ");
		strcat(result, p_shfi->szTypeName);
		DWORD d_att = p_shfi->dwAttributes;
		if (d_att != 0)
			strcat(result, "\r\nProperties: ");

		if (d_att & SFGAO_CANCOPY)
			strcat(result, "|Copy|");
		if (d_att & SFGAO_CANDELETE)
			strcat(result, "|Delete|");
		if (d_att & SFGAO_CANMOVE)
			strcat(result, "|Move|");
		if (d_att & SFGAO_CANRENAME)
			strcat(result, "|Rename|");
		if (d_att & SFGAO_ENCRYPTED)
			strcat(result, "|Encrypted|");
		if (d_att & SFGAO_HIDDEN)
			strcat(result, "|Hidden|");
		if (d_att & SFGAO_LINK)
			strcat(result, "|Shortcut|");
		if (d_att & SFGAO_READONLY)
			strcat(result, "|Read only|");

		hIcon = p_shfi->hIcon;
		DrawIcon(hdc, 450, 130, hIcon);
		DeleteDC(hdc);

		ZeroMemory(p_shfi, sizeof(SHFILEINFO));
	}
	else
	{
		MessageBox(mainWindow, "Error starting data collection from specified file.", "Error", MB_ICONERROR);
	}

	SetWindowText(fileInfoTextData, result);
	free(result);

}

void retrieveFilePath()
{
	//declare
	OPENFILENAME* p_op, op;
	char* res[500] = { 0 };

	//initializes
	ZeroMemory(&op, sizeof(OPENFILENAME));
	p_op = &op;
	if (!p_op)
		MessageBox(mainWindow, "Error allocating memory. Try again.", "Error", MB_ICONERROR);

	p_op->hwndOwner = mainWindow;
	p_op->lpstrFile = paths;
	p_op->lpstrFilter = "All files\0*.*\0";
	p_op->lpstrInitialDir = NULL;
	p_op->lStructSize = sizeof(*p_op);
	p_op->nMaxFile = sizeof(paths);

	//functions
	if (GetSaveFileName(p_op) == TRUE)
	{
		strcpy(res, "Selected file: ");
		strcat(res, paths);
		SetWindowText(fileInfoTextData, res);

	}

}

void showPathBinary()
{

	//declare
	char* hex[100 * 1024];
	char* temp[20];
	char* bytes[10 * 1024];
	char* string;
	HANDLE hFile;
	DWORD bRead;


	//initializes
	hFile = CreateFile(path_binary, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
	{
		MessageBox(mainWindow, "Error trying to open file", "Error", MB_ICONERROR);
	}

	//functions
	if (ReadFile(hFile, bytes, 10240, &bRead, NULL) == TRUE)
	{
		strcpy(hex, ">>>>>>>>>> Contents of the file in string <<<<<<<<<<<\r\n\r\n");
		strcat(hex, bytes);
		strcat(hex, "\r\n\r\n>>>>>>>>>> Contents of the file in hexadecimal <<<<<<<<<<<\r\n\r\n");

		for (int i = 0; i < 10240; i++)
		{
			sprintf(temp, "0x%02X ", bytes[i]);
			strcat(hex, " |");
			strcat(hex, temp);
			strcat(hex, "| ");
		}



		SetWindowText(readBinaryTextData, hex);




		CloseHandle(hFile);




	}




}

void getPathBinary()
{
	//declare
	OPENFILENAME op_bin;
	OPENFILENAME* p_bin;

	//initializes
	memset(&op_bin, 0, sizeof(OPENFILENAME));
	p_bin = &op_bin;

	p_bin->hwndOwner = mainWindow;
	p_bin->lpstrFilter = "All files\0*.*\0";
	p_bin->lpstrInitialDir = NULL;
	p_bin->lStructSize = sizeof(OPENFILENAME);
	p_bin->nFilterIndex = 1;
	p_bin->lpstrFile = path_binary;
	p_bin->nMaxFile = sizeof(path_binary);

	//functions
	if (GetOpenFileName(p_bin) == TRUE)
	{
		//empty
	}

}

void uploadThread()
{
	//declare
	FILE* file;
	WSADATA wsadata;
	SOCKET con;
	SOCKADDR_IN serv, cli;
	int s_len, res;
	char* buf;
	char c_ip[200] = { 0 };
	char c_port[20] = { 0 };
	char temp[20] = { 0 };
	IN_ADDR ip;


	//initializes
	buf = (char*)malloc(1024);

	GetWindowText(fileTransferEditIP, c_ip, 200);
	GetWindowText(fileTransferEditPort, c_port, 20);
	if (strcmp("", c_ip) == 0)
	{
		MessageBox(mainWindow, "IP address not informed", "Warning", MB_ICONEXCLAMATION);
	}
	else if (strcmp("", c_port) == 0)
	{
		MessageBox(mainWindow, "Port number not reported", "Warning", MB_ICONEXCLAMATION);
	}

	WSAStartup(MAKEWORD(2, 2), &wsadata);
	con = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&serv, 0, sizeof(SOCKADDR_IN));
	serv.sin_addr.S_un.S_addr = inet_addr(c_ip);
	serv.sin_family = AF_INET;
	serv.sin_port = htons(atoi(c_port));
	s_len = sizeof(SOCKADDR_IN);

	//functions

	if ((res = connect(con, (SOCKADDR*)&serv, s_len)) != 0)
	{
		MessageBox(mainWindow, "Error starting connection to remote device for file upload", "Error", MB_ICONERROR);
	}

	strcpy(buf, "[*] Connected to the remote device:");
	ip.S_un.S_addr = serv.sin_addr.S_un.S_addr;
	strcat(buf, inet_ntoa(ip));
	strcat(buf, ":");
	sprintf(temp, "%d", ntohs(serv.sin_port));
	strcat(buf, temp);
	SetWindowText(fileTransferTextData, buf);
	free(buf);

	buf = (char*)malloc(1);

	file = fopen(c_filetransfer, "rb");
	if (!file)
	{
		MessageBox(mainWindow, "Error opening file", "Error", MB_ICONERROR);
	}


	while (fread(buf, sizeof(char), 1, file) > 0)
	{
		send(con, buf, 1, 0);
	}

	fclose(file);
	SetWindowText(fileTransferTextData, "[*] File uploaded successfully.");

	free(buf);
	closesocket(con);
	WSACleanup();

	MessageBox(mainWindow, "[*] File uploaded successfully", "Upload completed", MB_OK);


}

void transferFile()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)uploadThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Error creating Thread for file upload", "Error", MB_ICONERROR);
	}
}

void serverTransferThread()
{
	//declare
	FILE* file;
	WSADATA wsadata;
	SOCKET ls, ns;
	SOCKADDR_IN serv, cli;
	int s_len, c_len, res;
	char* buf;
	char temp[20] = { 0 };
	IN_ADDR ip;

	//initializes
	buf = (char*)malloc(1024);

	GetWindowText(fileTransferEditPort, temp, 20);
	if (strcmp("", temp) == 0)
	{
		MessageBox(mainWindow, "Before starting the server, enter at least the port number", "Warning", MB_ICONEXCLAMATION);
	}

	WSAStartup(MAKEWORD(2, 2), &wsadata);
	ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&serv, 0, sizeof(SOCKADDR_IN));
	serv.sin_addr.S_un.S_addr = INADDR_ANY;
	serv.sin_family = AF_INET;
	serv.sin_port = htons(atoi(temp));
	s_len = sizeof(SOCKADDR_IN);

	c_len = sizeof(SOCKADDR_IN);

	//functions
	if ((res = bind(ls, (SOCKADDR*)&serv, s_len)) != 0)
	{
		MessageBox(mainWindow, "Error starting server", "Error", MB_ICONERROR);
	}

	if ((res = listen(ls, 1)) != 0)
	{
		MessageBox(mainWindow, "Error starting server to receive file", "Error", MB_ICONERROR);
	}

	strcpy(buf, "[*] Server open at address:");
	ip.S_un.S_addr = serv.sin_addr.S_un.S_addr;
	strcat(buf, inet_ntoa(ip));
	strcat(buf, ":");
	sprintf(temp, "%d", ntohs(serv.sin_port));
	strcat(buf, temp);
	MessageBox(mainWindow, buf, "Waiting for connection", MB_OK);
	free(buf);

	ns = accept(ls, (SOCKADDR*)&cli, &c_len);
	buf = (char*)malloc(1024);
	strcpy(buf, "[*] New device connected:");
	ip.S_un.S_addr = cli.sin_addr.S_un.S_addr;
	strcat(buf, inet_ntoa(ip));
	strcat(buf, ":");
	sprintf(temp, "%d", ntohs(cli.sin_port));
	strcat(buf, temp);
	SetWindowText(fileTransferTextData, buf);
	free(buf);
	buf = (char*)malloc(1);

	file = fopen(c_filetransfer, "wb");
	if (!file)
	{
		MessageBox(mainWindow, "Error opening file", "Error", MB_ICONERROR);
	}


	while (TRUE)
	{
		while (recv(ns, buf, 1, 0) > 0)
		{
			fwrite(buf, sizeof(char), 1, file);
		}

		fclose(file);
		MessageBox(mainWindow, "[*] File received successfully", "Download completed", MB_OK);
		SetWindowText(fileTransferTextData, "[*] File received successfully.");

		free(buf);
		break;
	}

}

void receiveFile()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)serverTransferThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Server Thread Error", "Error", MB_ICONERROR);
	}

}

void retrieveFileToTransfer()
{
	//declare
	OPENFILENAME st_fi, * p_st;
	char* output;

	//initializes
	output = (char*)malloc(500);

	memset(&st_fi, 0, sizeof(OPENFILENAME));
	p_st = &st_fi;
	p_st->hwndOwner = mainWindow;
	p_st->lpstrFile = c_filetransfer;
	p_st->lpstrInitialDir = NULL;
	p_st->lpstrFilter = "All files\0*.*\0";
	p_st->lStructSize = sizeof(OPENFILENAME);
	p_st->nMaxFile = sizeof(c_filetransfer);

	if (SendDlgItemMessage(mainWindow, TRANSFER_FILE_RB_RECEIVE, BM_GETCHECK, 0, 0) != 0)
	{
		if (GetSaveFileName(p_st) == TRUE)
		{
			strcpy(output, "[*] Downloadable file:");
			strcat(output, c_filetransfer);
		}
	}

	else if (SendDlgItemMessage(mainWindow, TRANSFER_FILE_RB_TRANSFER, BM_GETCHECK, 0, 0) != 0)
	{
		if (GetOpenFileName(p_st) == TRUE)
		{
			strcpy(output, "[*] File to upload:");
			strcat(output, c_filetransfer);
		}

	}

	SetWindowText(fileTransferTextData, output);
	free(output);

}

void browseFolder()
{
	//declare
	BROWSEINFO bi;
	char* path_choosen;
	LPITEMIDLIST id_list;


	//initializes
	path_choosen = (char*)malloc(252);

	ZeroMemory(&bi, sizeof(BROWSEINFO));
	bi.hwndOwner = mainWindow;
	bi.ulFlags = BIF_BROWSEINCLUDEFILES;

	//functiions
	id_list = SHBrowseForFolder(&bi);
	if (!id_list)
	{
		MessageBox(mainWindow, "Error querying directory", "Error", MB_ICONERROR);
	}

	SHGetPathFromIDList(id_list, path_choosen);
	SetWindowText(listFileEditPath, path_choosen);

	free(path_choosen);

}

void listFiles()
{
	//declare
	WIN32_FIND_DATA data, * p_data;
	HANDLE hFile;
	char* current_dir, * result;

	//initializes
	current_dir = (char*)malloc(252);
	result = (char*)malloc(10 * 1024);

	memset(&data, 0, sizeof(WIN32_FIND_DATA));
	p_data = &data;

	//functions
	GetWindowText(listFileEditPath, current_dir, 252);
	if (strcmp("", current_dir) == 0)
	{
		MessageBox(mainWindow, "Select a valid directory", "Warning", MB_ICONEXCLAMATION);
	}

	strcat(current_dir, "\\*");

	hFile = FindFirstFile(current_dir, p_data);
	if (!hFile)
	{
		MessageBox(mainWindow, "Failed to query directory", "Warning", MB_ICONERROR);
	}

	strcpy(result, "[*] Directory content\r\n\r\n");

	while (FindNextFile(hFile, p_data) == TRUE)
	{
		if (p_data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			strcat(result, "Folder: ");
			strcat(result, p_data->cFileName);
			strcat(result, "\r\n");
		}
		else
		{
			strcat(result, "File: ");
			strcat(result, p_data->cFileName);
			strcat(result, "\t Size: ");
			char* sz[252];
			sprintf(sz, "%ld", p_data->nFileSizeLow);
			strcat(result, sz);
			strcat(result, "\r\n");
		}
	}

	SetWindowText(listFileTextData, result);
	free(current_dir);
	free(result);



}

void whoisSearch()
{
	//declare
	WSADATA wsadata;
	SOCKET s;
	SOCKADDR_IN server, * p_s;
	int s_len, s_port, res;
	char* host, * result;
	char* search;
	char* res_string;

	//initializes
	search = (char*)malloc(252);
	s_port = 43;
	host = "192.0.47.59";
	result = (char*)malloc(10 * 1024);
	res_string = (char*)malloc(10 * 1024);

	WSAStartup(MAKEWORD(2, 2), &wsadata);
	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&server, 0, sizeof(SOCKADDR_IN));
	p_s = &server;
	p_s->sin_addr.S_un.S_addr = inet_addr(host);
	p_s->sin_family = AF_INET;
	p_s->sin_port = htons(s_port);
	s_len = sizeof(*p_s);

	//functions
	GetWindowText(whoisEdit, search, 252);
	if (strcmp(search, "") == 0)
	{
		MessageBox(mainWindow, "Enter valid search criteria", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		strcat(search, "\r\n");

		if ((res = connect(s, (SOCKADDR*)p_s, s_len)) == 0)
		{
			send(s, search, 252, 0);
			recv(s, result, 10240, 0);

			char* p;
			p = strtok(result, " ");

			int c = 0;
			strcpy(res_string, "[*] Result:\r\n\r\n");
			while ((p = strtok(NULL, " ")) != NULL)
			{
				strcat(res_string, p);
				strcat(res_string, "\r\n\r\n");
			}

			SetWindowText(whoisTextData, res_string);

			free(result);
			free(search);
			free(res_string);
		}
		else
		{
			MessageBox(mainWindow, "Connection error", "Error", MB_ICONERROR);
		}

		closesocket(s);
		WSACleanup();
	}
}

void smbCheckServer()
{

	//declare
	WSADATA wsadata;
	SOCKADDR_IN serv;
	char* host;
	int port, s_len, res;
	SOCKET s;

	//initializes
	WSAStartup(MAKEWORD(2, 2), &wsadata);

	host = (char*)malloc(252);
	GetWindowText(smbEditHost, host, 252);
	port = 139;

	ZeroMemory(&serv, sizeof(SOCKADDR_IN));
	serv.sin_addr.S_un.S_addr = inet_addr(host);
	serv.sin_family = AF_INET;
	serv.sin_port = htons(port);
	s_len = sizeof(serv);

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	//functions
	if ((res = connect(s, (SOCKADDR*)&serv, s_len)) == 0)
	{
		MessageBox(mainWindow, "The server is active. You can list files and directories and transfer them", "Active server", MB_OK);
	}
	else
	{
		MessageBox(mainWindow, "Connection error", "Error", MB_ICONERROR);
	}

	closesocket(s);
	WSACleanup();
	free(host);

}

void smbListFiles()
{
	//declare
	WIN32_FIND_DATA data;
	char* list_result;
	char* cur_path;
	char* server;
	HANDLE hFile;
	char temp[20] = { 0 };

	//initializes
	ZeroMemory(&data, sizeof(WIN32_FIND_DATA));
	list_result = (char*)malloc(10 * 1024);
	cur_path = (char*)malloc(252);
	server = (char*)malloc(252);

	//functions
	GetWindowText(smbEditHost, server, 252);
	GetWindowText(smbEditPath, cur_path, 252);
	if (strcmp("", server) == 0)
	{
		MessageBox(mainWindow, "When clicking list, enter the server's IP address in the Host field.", "Warning", MB_ICONEXCLAMATION);
	}

	hFile = FindFirstFile(cur_path, &data);
	if (!hFile)
	{
		MessageBox(mainWindow, "Error fetching files", "Error", MB_ICONERROR);
	}
	strcpy(list_result, "[*] Result for directory:");
	strcat(list_result, cur_path);
	strcat(list_result, "\r\n\r\n");
	while (FindNextFile(hFile, &data) == TRUE)
	{
		if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			strcat(list_result, "Directory: ");
			strcat(list_result, data.cFileName);
			strcat(list_result, "\r\n");

		}
		else
		{
			strcat(list_result, "File: ");
			strcat(list_result, data.cFileName);
			strcat(list_result, "\tSize: ");
			sprintf(temp, "%ld", data.nFileSizeLow);
			strcat(list_result, temp);
			strcat(list_result, "\r\n");
		}
	}

	SetWindowText(smbTextData, list_result);
	free(server);
	free(cur_path);
	free(list_result);
	//CloseHandle(hFile);


}

void smbDownload()
{
	//declare
	SHFILEOPSTRUCT op, * p_op;
	char* the_file;
	char this_dir[252] = { 0 };
	int res;

	//initializes
	GetCurrentDirectory(252, this_dir);

	the_file = (char*)malloc(252);
	GetWindowText(smbEditPath, the_file, 252);
	if (strcmp("", the_file) == 0)
	{
		MessageBox(mainWindow, "No file selected for download in 'Directory' field - Ex: \\[Server IP]\file.exe", "Warning", MB_ICONEXCLAMATION);
	}

	memset(&op, 0, sizeof(SHFILEOPSTRUCT));
	p_op = &op;
	p_op->fFlags = FOF_RENAMEONCOLLISION;
	p_op->hwnd = mainWindow;
	p_op->lpszProgressTitle = "Fenix Firewall - Copying file";
	p_op->pFrom = the_file;
	p_op->pTo = this_dir;
	p_op->wFunc = FO_COPY;

	//functions
	if ((res = SHFileOperation(p_op)) != 0)
	{
		MessageBox(mainWindow, "Error downloading file", "Error", MB_ICONERROR);
	}

	free(the_file);



}

void smbUpload()
{
	//declare
	OPENFILENAME st_opfile;
	SHFILEOPSTRUCT st_shfile;
	char local_file[252] = { 0 };
	char* dst_dir;
	int res;

	//initializes
	dst_dir = (char*)malloc(252);
	GetWindowText(smbEditPath, dst_dir, 252);

	ZeroMemory(&st_opfile, sizeof(OPENFILENAME));
	st_opfile.hwndOwner = mainWindow;
	st_opfile.lpstrFile = local_file;
	st_opfile.lpstrFilter = "All files\0*.*\0";
	st_opfile.lpstrInitialDir = NULL;
	st_opfile.lpstrTitle = "Fenix Wing";
	st_opfile.lStructSize = sizeof(st_opfile);
	st_opfile.nMaxFile = sizeof(local_file);

	memset(&st_shfile, 0, sizeof(SHFILEOPSTRUCT));
	st_shfile.fFlags = FOF_RENAMEONCOLLISION;
	st_shfile.hwnd = mainWindow;
	st_shfile.lpszProgressTitle = "Fenix Wing";
	st_shfile.pTo = dst_dir;
	st_shfile.pFrom = local_file;
	st_shfile.wFunc = FO_COPY;

	//functions
	if (GetOpenFileName(&st_opfile) == TRUE)
	{
		if ((res = SHFileOperation(&st_shfile)) != 0)
		{
			MessageBox(mainWindow, "Error uploading file", "Error", MB_ICONERROR);
		}
	}

	free(dst_dir);





}

void uploadThreadUdp()
{
	//declare
	FILE* file;
	WSADATA wsadata;
	SOCKET con;
	SOCKADDR_IN serv, cli;
	int s_len, res;
	char* buf;
	char c_ip[200] = { 0 };
	char c_port[20] = { 0 };
	char temp[20] = { 0 };
	IN_ADDR ip;


	//initializes
	buf = (char*)malloc(1);

	GetWindowText(fileTransferEditIPUdp, c_ip, 200);
	GetWindowText(fileTransferEditPortUdp, c_port, 20);
	if (strcmp("", c_ip) == 0)
	{
		MessageBox(mainWindow, "IP address not informed", "Warning", MB_ICONEXCLAMATION);
	}
	else if (strcmp("", c_port) == 0)
	{
		MessageBox(mainWindow, "Port number not reported", "Warning", MB_ICONEXCLAMATION);
	}

	WSAStartup(MAKEWORD(2, 2), &wsadata);
	con = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset(&serv, 0, sizeof(SOCKADDR_IN));
	serv.sin_addr.S_un.S_addr = inet_addr(c_ip);
	serv.sin_family = AF_INET;
	serv.sin_port = htons(atoi(c_port));
	s_len = sizeof(SOCKADDR_IN);

	//functions
	file = fopen(c_filetransferUdp, "rb");
	if (!file)
	{
		MessageBox(mainWindow, "Error opening file", "Error", MB_ICONERROR);
	}

	SetWindowText(fileTransferTextDataUdp, "[*] Trying to send file via UDP\r\n");


	while (fread(buf, sizeof(char), 1, file) > 0)
	{
		sendto(con, buf, 1, 0, (SOCKADDR*)&serv, s_len);
	}

	sendto(con, NULL, 0, 0, (SOCKADDR*)&serv, s_len);
	fclose(file);
	free(buf);
	buf = (char*)malloc(1024);

	if (recvfrom(con, buf, 200, 0, (SOCKADDR*)&serv, &s_len) == 0)
	{
		strcpy(buf, "[*] File successfully uploaded to device:");
		ip.S_un.S_addr = serv.sin_addr.S_un.S_addr;
		strcat(buf, inet_ntoa(ip));
		strcat(buf, ":");
		sprintf(temp, "%d", ntohs(serv.sin_port));
		strcat(buf, temp);

		sendto(con, buf, 0, 0, (SOCKADDR*)&serv, s_len);
		closesocket(con);
		WSACleanup();

		SetWindowText(fileTransferTextDataUdp, buf);

	}

	MessageBox(mainWindow, buf, "Transfer completed", MB_OK);
	closesocket(con);
	WSACleanup();






}

void transferFileUdp()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)uploadThreadUdp, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Error creating Thread for file upload", "Error", MB_ICONERROR);
	}
}

void serverTransferThreadUdp()
{
	//declare
	FILE* file;
	WSADATA wsadata;
	SOCKET ls;
	SOCKADDR_IN serv, cli;
	int s_len, c_len, res;
	char* buf;
	char temp[20] = { 0 };
	IN_ADDR ip;

	//initializes
	buf = (char*)malloc(1024);

	GetWindowText(fileTransferEditPortUdp, temp, 20);
	if (strcmp("", temp) == 0)
	{
		MessageBox(mainWindow, "Before starting the server, enter at least the port number", "Warning", MB_ICONEXCLAMATION);
	}

	WSAStartup(MAKEWORD(2, 2), &wsadata);
	ls = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset(&serv, 0, sizeof(SOCKADDR_IN));
	serv.sin_addr.S_un.S_addr = INADDR_ANY;
	serv.sin_family = AF_INET;
	serv.sin_port = htons(atoi(temp));
	s_len = sizeof(SOCKADDR_IN);

	c_len = sizeof(SOCKADDR_IN);

	//functions
	if ((res = bind(ls, (SOCKADDR*)&serv, s_len)) != 0)
	{
		MessageBox(mainWindow, "Error starting server", "Warning", MB_ICONERROR);
	}

	strcpy(buf, "[*] Server open at address:");
	ip.S_un.S_addr = serv.sin_addr.S_un.S_addr;
	strcat(buf, inet_ntoa(ip));
	strcat(buf, ":");
	sprintf(temp, "%d", ntohs(serv.sin_port));
	strcat(buf, temp);
	MessageBox(mainWindow, buf, "Waiting to receive file via UDP", MB_OK);
	free(buf);

	buf = (char*)malloc(1);

	file = fopen(c_filetransferUdp, "wb");
	if (!file)
	{
		MessageBox(mainWindow, "Error opening file", "Error", MB_ICONERROR);
	}

	while (TRUE)
	{
		while (recvfrom(ls, buf, 1, 0, (SOCKADDR*)&cli, &c_len) > 0)
		{
			fwrite(buf, sizeof(char), 1, file);
		}

		fclose(file);
		sendto(ls, NULL, 0, 0, (SOCKADDR*)&cli, c_len);
		free(buf);
		buf = (char*)malloc(1024);
		strcpy(buf, "[*] File successfully received from device:");
		ip.S_un.S_addr = cli.sin_addr.S_un.S_addr;
		strcat(buf, inet_ntoa(ip));
		strcat(buf, ":");
		sprintf(temp, "%d", ntohs(cli.sin_port));
		strcat(buf, temp);
		SetWindowText(fileTransferTextDataUdp, buf);
		break;


	}

	MessageBox(mainWindow, buf, "Download completed", MB_OK);
	free(buf);


}

void receiveFileUdp()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)serverTransferThreadUdp, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Server Thread Error", "Error", MB_ICONERROR);
	}
}

void retrieveFileToTransferUdp()
{
	//declare
	OPENFILENAME st_fi, * p_st;
	char* output;

	//initializes
	output = (char*)malloc(500);

	memset(&st_fi, 0, sizeof(OPENFILENAME));
	p_st = &st_fi;
	p_st->hwndOwner = mainWindow;
	p_st->lpstrFile = c_filetransferUdp;
	p_st->lpstrInitialDir = NULL;
	p_st->lpstrFilter = "All files\0*.*\0";
	p_st->lStructSize = sizeof(OPENFILENAME);
	p_st->nMaxFile = sizeof(c_filetransferUdp);

	if (SendDlgItemMessage(mainWindow, FILE_TRANSFER_UDP_RB_RV, BM_GETCHECK, 0, 0) != 0)
	{
		if (GetSaveFileName(p_st) == TRUE)
		{
			strcpy(output, "[*] Downloadable file:");
			strcat(output, c_filetransferUdp);
		}
	}

	else if (SendDlgItemMessage(mainWindow, FILE_TRANSFER_UDP_RB_UP, BM_GETCHECK, 0, 0) != 0)
	{
		if (GetOpenFileName(p_st) == TRUE)
		{
			strcpy(output, "[*] File to upload:");
			strcat(output, c_filetransferUdp);
		}

	}

	SetWindowText(fileTransferTextDataUdp, output);
	free(output);
}

void openPrompt()
{
	//declare
	FILE* file;
	char* buf, * name, * cmd, * result;
	char path_pub[252] = { 0 };
	int res;

	//initializes
	result = (char*)malloc(10240);
	buf = (char*)malloc(1024);
	cmd = (char*)malloc(300);
	strcpy(path_pub, "C:\\Users\\Public");
	name = "temp.txt";
	strcat(path_pub, "\\");
	strcat(path_pub, name);

	//functions	

	GetWindowText(openCmdEdit, cmd, 300);
	if (strcmp("", cmd) == 0)
	{
		MessageBox(mainWindow, "You haven't entered any commands yet.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		strcpy(result, "[*] Command result:");
		strcat(result, cmd);
		strcat(result, "\r\n\r\n");

		strcat(cmd, " > ");
		strcat(cmd, path_pub);

		res = system(cmd);
		if (res != 0)
		{
			MessageBox(mainWindow, "Invalid command", "Error", MB_ICONERROR);
			free(result);
			free(cmd);
			free(buf);
		}
		else
		{
			file = fopen(path_pub, "r");
			if (!file)
			{
				MessageBox(mainWindow, "Error creating temporary file for reading command", "Error", MB_ICONERROR);
				free(result);
				free(cmd);
				free(buf);
			}
			else
			{
				while (fgets(buf, 1024, file) > 0)
				{
					strcat(result, buf);
					strcat(result, "\r\n");
				}
				SetWindowText(openCmdTextData, result);
				fclose(file);
				free(buf);
				free(cmd);
				if (!DeleteFile(path_pub))
				{
					MessageBox(mainWindow, "Could not delete temporary file", "Warning", MB_ICONEXCLAMATION);
				}
			}
		}

	}




}

void controlmeActiveThread()
{
	//declare
	WSADATA wsadata;
	SOCKET ls, ns;
	SOCKADDR_IN serv, cli;
	int res, s_len, c_len;
	char* cmd, * buf, * port, * result;
	char temp[200] = { 0 };
	IN_ADDR ip;
	FILE* file;

	//initializes
	port = (char*)malloc(300);
	GetWindowText(controlledActiveEditPort, port, 300);
	if (strcmp("", port) == 0)
	{
		MessageBox(mainWindow, "Specify a port to start server.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		WSAStartup(MAKEWORD(2, 2), &wsadata);
		ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		ZeroMemory(&serv, sizeof(SOCKADDR_IN));
		serv.sin_addr.S_un.S_addr = INADDR_ANY;
		serv.sin_family = AF_INET;
		serv.sin_port = ntohs(atoi(port));
		s_len = sizeof(SOCKADDR_IN);

		c_len = sizeof(SOCKADDR_IN);

		if ((res = bind(ls, (SOCKADDR*)&serv, s_len)) != 0)
		{
			MessageBox(mainWindow, "Error starting server", "Error", MB_ICONERROR);
		}
		else
		{
			if ((res = listen(ls, 1)) != 0)
			{
				MessageBox(mainWindow, "Error waiting for new connection", "Error", MB_ICONERROR);
			}
			else
			{
				result = (char*)malloc(10240);
				strcpy(result, "[*] Waiting for controller to connect to the port:");
				strcat(result, port);
				strcat(result, "\r\n");
				SetWindowText(controlledActiveTextData, result);

				ns = accept(ls, (SOCKADDR*)&cli, &c_len);
				ip.S_un.S_addr = cli.sin_addr.S_un.S_addr;
				strcat(result, "[*] Connection received from controller");
				strcat(result, inet_ntoa(ip));
				strcat(result, ":");
				sprintf(temp, "%d", ntohs(cli.sin_port));
				strcat(result, temp);
				strcat(result, "\r\n");
				SetWindowText(controlledActiveTextData, result);

				int err = 0;
				while (TRUE)
				{
					if (err > 50)
					{
						break;
						exit(0);
					}

					cmd = (char*)malloc(300);
					buf = (char*)malloc(10240);

					recv(ns, cmd, 300, 0);

					if (strcmp("getout", cmd) == 0)
					{
						strcat(result, "[*]Termination order 'getout' received. Server off...\r\n");
						send(ns, "Controlled device terminated successfully.", 300, 0);
						SetWindowText(controlledActiveTextData, result);
						break;
					}

					strcat(result, "[*]Received command:");
					strcat(result, cmd);
					strcat(result, "\r\n");

					strcat(cmd, " > C:\\Users\\Public\\temp.txt");

					res = system(cmd);
					if (res != 0)
					{
						strcat(result, "Invalid command.\r\n");
						send(ns, "Invalid command", 50, 0);
						SetWindowText(controlledActiveTextData, result);
						free(cmd);
						free(buf);
						err++;
					}
					else
					{
						strcat(result, "[*] Command executed successfully.");
						strcat(result, "\r\n");
						SetWindowText(controlledActiveTextData, result);

						file = fopen("C:\\Users\\Public\\temp.txt", "r");
						if (!file)
						{
							strcat(result, "Error opening temporary file.");
							strcat(result, "\r\n");
							SetWindowText(controlledActiveTextData, result);
							send(ns, "Internal Error", 50, 0);
							free(cmd);
							free(buf);

						}
						else
						{
							fread(buf, 10240, 1, file);
							send(ns, buf, 10240, 0);
							strcat(result, "[*] Response sent to controller.");
							strcat(result, "\r\n");
							SetWindowText(controlledActiveTextData, result);
							fclose(file);
							free(cmd);
							free(buf);
							DeleteFile("C:\\Users\\Public\\temp.txt");
						}

					}
				}
				closesocket(ns);
				closesocket(ls);
				WSACleanup();
				free(result);
			}
		}


	}


}

void controlMeActive()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)controlmeActiveThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Error opening Thread.", "Error", MB_ICONERROR);
	}
}

void controllerActiveCmd()
{
	//declare
	char* buf, * cmd, * buf_fin;
	IN_ADDR ip;
	char temp[20] = { 0 };

	//initializes
	cmd = (char*)malloc(300);
	ip.S_un.S_addr = serv_actv.sin_addr.S_un.S_addr;

	if (IS_CONNECTED == FALSE)
	{
		MessageBox(mainWindow, "You are not connected to the remote computer", "Error", MB_ICONERROR);
	}
	else
	{
		GetWindowText(controllerActiveEditCmd, cmd, 300);
		if (strcmp("", cmd) == 0)
		{
			MessageBox(mainWindow, "No command typed", "Warning", MB_ICONEXCLAMATION);
		}
		else if (strcmp("getout", cmd) == 0)
		{
			char* getout = (char*)malloc(500);
			char* resp_gt = (char*)malloc(500);
			strcpy(getout, "[*] Shutdown order sent.\r\n");
			send(con_actv, cmd, 300, 0);
			SetWindowText(controllerActiveTextData, getout);
			recv(con_actv, resp_gt, 500, 0);
			strcat(getout, resp_gt);
			strcat(getout, "\r\n");
			SetWindowText(controllerActiveTextData, getout);


		}
		else
		{
			//functions
			buf = (char*)malloc(10240);
			buf_fin = (char*)malloc(10240 + 500);
			send(con_actv, cmd, 300, 0);
			recv(con_actv, buf, 10240, 0);
			strcpy(buf_fin, "[*] Connected to device:");
			strcat(buf_fin, inet_ntoa(ip));
			strcat(buf_fin, ":");
			sprintf(temp, "%d", ntohs(serv_actv.sin_port));
			strcat(buf_fin, temp);			strcat(buf_fin, "\r\n");
			strcat(buf_fin, "[*] Command sent:");
			strcat(buf_fin, cmd);
			strcat(buf_fin, "\r\n");
			strcat(buf_fin, "[*] Remote device response:");
			strcat(buf_fin, "\r\n\r\n");
			strcat(buf_fin, buf);
			strcat(buf_fin, "\r\n");
			SetWindowText(controllerActiveTextData, buf_fin);

			free(buf);
			free(buf_fin);
			free(cmd);
		}



	}




}

void controllerActiveConnect()
{
	//declare
	WSADATA wsadata;
	int res;
	char* ip, * port, * result_actv;
	char temp[20] = { 0 };

	//initializes
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	ip = (char*)malloc(200);
	port = (char*)malloc(200);

	GetWindowText(controllerActiveEditIP, ip, 200);
	GetWindowText(controllerActiveEditPort, port, 200);
	if (strcmp(ip, "") == 0 || strcmp("port", "") == 0)
	{
		MessageBox(mainWindow, "Enter the IP number and port of the device to be controlled", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		con_actv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		memset(&serv_actv, 0, sizeof(SOCKADDR_IN));
		serv_actv.sin_addr.S_un.S_addr = inet_addr(ip);
		serv_actv.sin_family = AF_INET;
		serv_actv.sin_port = ntohs(atoi(port));
		s_len_actv = sizeof(SOCKADDR_IN);

		//functions
		if ((res = connect(con_actv, (SOCKADDR*)&serv_actv, s_len_actv)) != 0)
		{
			MessageBox(mainWindow, "Connection error", "Error", MB_ICONERROR);
		}
		else
		{
			IS_CONNECTED = TRUE;

			result_actv = (char*)malloc(500);
			strcpy(result_actv, "[*]Connected to device:");
			strcat(result_actv, ip);
			strcat(result_actv, ":");
			strcat(result_actv, port);
			strcat(result_actv, "\r\n\r\n");
			SetWindowText(controllerActiveTextData, result_actv);

		}
	}


}

void controlledPassiveThread()
{
	//declare
	WSADATA wsadata;
	char* ip, * port, * cmd, * buf;
	FILE* file;

	//initilizes
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	ip = (char*)malloc(255);
	port = (char*)malloc(100);
	result = (char*)malloc(10 * 1024);
	cmd = (char*)malloc(200);
	buf = (char*)malloc(10 * 1024);


	//functions
	GetWindowText(controlledPassiveEditIP, ip, 255);
	GetWindowText(controlledPassiveEditPort, port, 100);
	if (strcmp(ip, "") == 0 || strcmp(port, "") == 0)
	{
		MessageBox(mainWindow, "Fill in the IP and Port fields before connecting to the controller.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		memset(&serv, 0, sizeof(SOCKADDR_IN));
		serv.sin_family = AF_INET;
		serv.sin_addr.S_un.S_addr = inet_addr(ip);
		serv.sin_port = ntohs(atoi(port));
		s_len = sizeof(SOCKADDR_IN);

		c_len = sizeof(SOCKADDR_IN);

		ns = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if ((res = connect(ns, (SOCKADDR*)&serv, s_len)) != 0)
		{
			MessageBox(mainWindow, "Failed to connect to controller.", "Error", MB_ICONERROR);
		}
		else
		{
			strcpy(result, "[*] Connected to controller:");
			strcat(result, ip);
			strcat(result, ":");
			strcat(result, port);
			strcat(result, "\r\n[*] Waiting for commands...\r\n");
			SetWindowText(controlledPassiveTextData, result);

			while (TRUE)
			{
				res = recv(ns, cmd, 200, 0);


				if (res != 0)
				{
					if (strcmp(cmd, "getout") == 0)
					{
						strcat(result, "[*] Received disconnect order from controller.\r\n");
						send(ns, "ok!", 4, 0);
						strcat(result, "[*] Connection ended successfully.\r\n");
						SetWindowText(controlledPassiveTextData, result);
						break;
					}
					else
					{
						strcat(cmd, " > C:\\Users\\Public\\Temp.txt");

						if ((res = system(cmd)) != 0)
						{
							strcat(result, "[*] Invalid command:");
							strcat(result, cmd);
							strcat(result, "\r\n");
							SetWindowText(controlledPassiveTextData, result);
							send(ns, "Invalid command", 50, 0);
						}
						else
						{
							file = fopen("C:\\Users\\Public\\Temp.txt", "r");
							if (!file)
							{
								strcat(result, "[*] Failed to create temporary file for command execution.\r\n");
								SetWindowText(controlledPassiveTextData, result);
								send(ns, "[*] Failed to create temporary file for command execution", 150, 0);
							}
							else
							{
								fread(buf, 10240, 1, file);
								send(ns, buf, 10240, 0);
								strcat(result, "[*] Command executed:");
								strcat(result, cmd);
								strcat(result, "\r\n[*] Response sent to controller.\r\n");
								SetWindowText(controlledPassiveTextData, result);
								fclose(file);
								DeleteFile("C:\\Users\\Public\\Temp.txt");

								free(cmd);
								free(buf);

								cmd = (char*)malloc(200);
								buf = (char*)malloc(10 * 1024);


							}
						}
					}

				}

			}
			closesocket(ns);
			WSACleanup();

		}

	}

}

void controlledPassiveConnect()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)controlledPassiveThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Error creating Thread.", "Error", MB_ICONERROR);
	}
}

void controllerPassiveProcessMessagesThread()
{
	//declare
	char* message;
	char* confirm_exit;

	//initializes
	message = (char*)malloc(200);
	confirm_exit = (char*)malloc(4);

	//functions
	GetWindowText(controllerPassiveEditCmd, message, 200);
	if (strcmp(message, "") == 0)
	{
		MessageBox(mainWindow, "Enter a valid command.", "Warning", MB_ICONEXCLAMATION);
	}
	else if (strcmp(message, "getout") == 0)
	{
		send(ns, "getout", 7, 0);
		strcat(result, "[*] Disconnection order sent to controlled device.\r\n");
		SetWindowText(controllerPassiveTextData, result);
	}
	else
	{
		send(ns, message, 200, 0);
		free(message);
		free(confirm_exit);
	}
}

void controllerPassiveProcessMessages()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)controllerPassiveProcessMessagesThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Failed to create Thread.", "Error", MB_ICONERROR);
	}
}

void controllerPassiveUpServerThread()
{
	//declare
	char* port, * buf;
	WSADATA wsadata;
	SOCKADDR_IN cli;
	IN_ADDR ip;

	//initializes
	port = (char*)malloc(100);
	buf = (char*)malloc(10 * 1024);
	result = (char*)malloc(100 * 1024);
	ZeroMemory(&ip, sizeof(IN_ADDR));

	//functions
	GetWindowText(controllerPassiveEditPort, port, 100);
	if (strcmp(port, "") == 0)
	{
		MessageBox(mainWindow, "Enter the port to start the server.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		WSAStartup(MAKEWORD(2, 2), &wsadata);
		ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		memset(&serv, 0, sizeof(SOCKADDR_IN));
		serv.sin_family = AF_INET;
		serv.sin_addr.S_un.S_addr = INADDR_ANY;
		serv.sin_port = ntohs(atoi(port));
		s_len = sizeof(SOCKADDR_IN);

		c_len = sizeof(SOCKADDR_IN);


		if ((res = bind(ls, (SOCKADDR*)&serv, s_len)) != 0)
		{
			MessageBox(mainWindow, "Error uploading server on specified port.", "Error", MB_ICONERROR);
		}
		else
		{
			if ((res = listen(ls, 1)) != 0)
			{
				MessageBox(mainWindow, "Could not listen for connections on the specified port.", "Error", MB_ICONERROR);
			}
			else
			{
				strcpy(result, "[*] Waiting for connection on port");
				strcat(result, port);
				strcat(result, "\r\n");
				SetWindowText(controllerPassiveTextData, result);

				ns = accept(ls, (SOCKADDR*)&cli, &c_len);
				ip.S_un.S_addr = cli.sin_addr.S_un.S_addr;
				strcat(result, "[*] Connection received from the controlled device:");
				strcat(result, inet_ntoa(ip));
				strcat(result, ":");
				sprintf(temp, "%d", ntohs(cli.sin_port));
				strcat(result, temp);
				strcat(result, "\r\n");
				SetWindowText(controllerPassiveTextData, result);
				send(ns, "whoami", 10, 0);

				while (TRUE)
				{
					res = recv(ns, buf, 10240, 0);

					if (strcmp(buf, "ok!") == 0)
					{
						strcat(result, "[*] Connection ended successfully.\r\n");
						SetWindowText(controllerPassiveTextData, result);
						break;
					}
					else
					{
						if (res != 0)
						{
							strcat(result, buf);
							strcat(result, "\r\n");
							SetWindowText(controllerPassiveTextData, result);
							free(buf);
							buf = (char*)malloc(1024 * 10);
						}
					}

				}

				closesocket(ns);
				closesocket(ls);
				WSACleanup();

			}
		}
	}
}

void controllerPassiveUpServer()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)controllerPassiveUpServerThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Failed to create Thread.", "Error", MB_ICONERROR);
	}
}

void finishProcessThread()
{
	//declare
	HANDLE hSnapShot, hProcess;
	PROCESSENTRY32 pEntry;
	BOOL isProc, done;
	char* proc_search;

	//initializes
	pEntry.dwSize = sizeof(PROCESSENTRY32);
	proc_search = (char*)malloc(200);
	result = (char*)malloc(1000);

	//functions
	GetWindowText(endProcessEdit, proc_search, 200);
	if (strcmp(proc_search, "") == 0)
	{
		MessageBox(mainWindow, "Enter the process name.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		if (!hSnapShot)
		{
			MessageBox(mainWindow, "Failed to create process list.", "Error", MB_ICONERROR);
		}
		else
		{
			isProc = Process32First(hSnapShot, &pEntry);
			strcpy(result, "[*] Results:\r\n\r\n");
			while (isProc)
			{
				if (strcmp(pEntry.szExeFile, proc_search) == 0)
				{
					hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ProcessID);
					if (!hProcess)
					{
						MessageBox(mainWindow, "Failed to access the informed process.", "Error", MB_ICONERROR);
					}
					else
					{
						done = TerminateProcess(hProcess, 9);
						strcat(result, "[*] Process No.");
						sprintf(temp, "%d", (int)pEntry.th32ProcessID);
						strcat(result, temp);
						strcat(result, " successfully terminated.\r\n");
						SetWindowText(endProcessTextData, result);
						CloseHandle(hProcess);

					}
				}
				hProcess = Process32Next(hSnapShot, &pEntry);
			}
			free(proc_search);
			free(result);


		}
	}


}

void finishProcess()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)finishProcessThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Failed to create Thread.", "Error", MB_ICONERROR);
	}
}

void listProcessThread()
{
	//declare
	HANDLE hSnapShot;
	PROCESSENTRY32 process;

	BOOL yet;
	char* result_list;
	int count = 0;

	//initializes
	result_list = (char*)malloc(100 * 1024);
	process.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (!hSnapShot)
	{
		MessageBox(mainWindow, "Failed to acquire system process list.", "Error", MB_ICONERROR);
		free(result_list);
	}
	else
	{
		//functions
		yet = Process32First(hSnapShot, &process);
		strcpy(result_list, "[*]Number of processes found:");
		while (yet)
		{
			count++;
			yet = Process32Next(hSnapShot, &process);
		}
		CloseHandle(hSnapShot);
		ZeroMemory(&process, sizeof(PROCESSENTRY32));
		process.dwSize = sizeof(PROCESSENTRY32);

		sprintf(temp, "%d", count);
		strcat(result_list, temp);
		strcat(result_list, "\r\n\r\n");
		SetWindowText(listProcessTextData, result_list);

		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		if (!hSnapShot)
		{
			MessageBox(mainWindow, "Failed to acquire system process list.", "Error", MB_ICONERROR);
			free(result_list);
		}
		else
		{
			yet = Process32First(hSnapShot, &process);
			count = 0;
			while (yet)
			{

				count++;
				strcat(result_list, "[*]Process No.");
				sprintf(temp, "%d", count);
				strcat(result_list, temp);					strcat(result_list, "\r\n");
				strcat(result_list, "Name: ");
				strcat(result_list, process.szExeFile);
				strcat(result_list, "\r\n");
				strcat(result_list, "Original No.(PID): ");
				sprintf(temp, "%d", (int)process.th32ProcessID);
				strcat(result_list, temp);
				strcat(result_list, "\r\n");
				strcat(result_list, "Threads Count: ");
				sprintf(temp, "%d", (int)process.cntThreads);
				strcat(result_list, temp);
				strcat(result_list, "\r\n");
				strcat(result_list, "PID of the creator process:");
				sprintf(temp, "%d", (int)process.th32ParentProcessID);
				strcat(result_list, temp);
				strcat(result_list, "\r\n\r\n");

				SetWindowText(listProcessTextData, result_list);
				yet = Process32Next(hSnapShot, &process);

			}

			CloseHandle(hSnapShot);
			free(result_list);



		}

	}


}

void listProcess()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)listProcessThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Error starting Thread.", "Error", MB_ICONERROR);
	}
}

void mysqlConnectServer()
{
	//declare
	char* ip, * port, * user, * db, * pass;
	char* sql_cmd;
	char* warning;

	//initializes
	ip = (char*)malloc(255);
	port = (char*)malloc(10);
	user = (char*)malloc(100);
	db = (char*)malloc(100);
	pass = (char*)malloc(100);
	sql_cmd = (char*)malloc(500);
	result_mysql = (char*)malloc(100 * 1024);
	warning = (char*)malloc(500);


	//functions
	GetWindowText(mysqlEditHost, ip, 255);
	GetWindowText(mysqlEditPort, port, 10);
	GetWindowText(mysqlEditUser, user, 100);
	GetWindowText(mysqlEditDb, db, 100);
	GetWindowText(mysqlEditPass, pass, 100);

	if (strcmp(db, "") == 0)
	{
		db = NULL;
	}

	if (strcmp(ip, "") == 0 || strcmp(port, "") == 0 || strcmp(user, "") == 0)
	{
		MessageBox(mainWindow, "Enter all the data to connect to the server. The password and database name, if they do not exist, must be left blank.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		con = mysql_init(NULL);
		if (!mysql_real_connect(con, ip, user, pass, db, atoi(port), NULL, 0))
		{
			strcpy(warning, "Unable to connect to the server.\r\n\r\n");
			strcat(warning, mysql_error(con));
			MessageBox(mainWindow, warning, "Error", MB_ICONEXCLAMATION);
		}
		else
		{
			strcpy(result_mysql, "[*] Successfully connected to the device");
			strcat(result_mysql, ip);
			strcat(result_mysql, ":");
			strcat(result_mysql, port);
			strcat(result_mysql, "\r\n");
			strcat(result_mysql, "[*] Waiting for command...\r\n");
			SetWindowText(mysqlTextData, result_mysql);
		}

	}
}

void mysqlPutCmd()
{
	//declare
	char* query;
	char* warning;
	int rc;

	//initializes
	query = (char*)malloc(500);
	warning = (char*)malloc(500);

	//functions
	GetWindowText(mysqlEditCmd, query, 500);
	if (strcmp(query, "") == 0)
	{
		MessageBox(mainWindow, "Enter a valid command.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		if (con == NULL)
		{
			MessageBox(mainWindow, "You are not logged in to send a command.", "Warning", MB_ICONERROR);
		}
		else
		{
			rc = mysql_query(con, query);
			if (rc != 0)
			{
				strcpy(warning, "Error executing command.\r\n\r\n");
				strcat(warning, mysql_error(con));
				MessageBox(mainWindow, warning, "Error", MB_ICONERROR);
				free(warning);
				free(query);
			}
			else
			{
				strcat(result_mysql, "[*] Command executed successfully. Click 'View Query' if you used the 'SELECT' clause. Otherwise, ignore this warning...\r\n");
				SetWindowText(mysqlTextData, result_mysql);
			}
		}
	}
}

void mysqlConsult()
{
	//declare
	int num_fields, num_rows;
	char super_char[500] = { 0 };

	//initializes
	if (con == NULL)
	{
		MessageBox(mainWindow, "You are not logged in to send a command.", "Error", MB_ICONERROR);
	}
	else
	{
		result_set = mysql_store_result(con);
		if (result_set == NULL)
		{
			MessageBox(mainWindow, "There are no results to show.", "Error", MB_ICONERROR);
		}
		else
		{
			//functions
			num_fields = mysql_num_fields(result_set);
			num_rows = mysql_num_rows(result_set);
			strcat(result_mysql, "\r\n[*] Total lines found:");
			sprintf(temp, "%d", num_rows);
			strcat(result_mysql, temp);
			strcat(result_mysql, "\r\n");
			strcat(result_mysql, "[*] Total columns:");
			sprintf(temp, "%d", num_fields);
			strcat(result_mysql, temp);
			strcat(result_mysql, "\r\n\r\n");

			SetWindowText(mysqlTextData, result_mysql);

			while (row = mysql_fetch_row(result_set))
			{

				for (int i = 0; i < num_fields; i++)
				{
					field = mysql_fetch_field_direct(result_set, i);
					strcat(result_mysql, field->name);
					strcat(result_mysql, ":");
					strcat(result_mysql, row[i]);
					strcat(result_mysql, "\r\n");

					if (i == 2)
					{
						strcat(result_mysql, "\r\n");
					}

				}

			}

			SetWindowText(mysqlTextData, result_mysql);

		}
	}




}

void chatUpServerThread()
{
	//declare
		//(GLOBALS)
	char* msg_chat;

	//initializes
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	result_chat = (char*)malloc(10 * 1024);
	ip_chat = (char*)malloc(255);
	port_chat = (char*)malloc(20);
	msg_chat = (char*)malloc(400);

	//functions
	GetWindowText(chatEditIp, ip_chat, 255);
	GetWindowText(chatEditPort, port_chat, 20);

	if (strcmp(port_chat, "") == 0)
	{
		MessageBox(mainWindow, "Enter the port number of the server to start it.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		ZeroMemory(&servChat, sizeof(SOCKADDR_IN));
		servChat.sin_family = AF_INET;
		servChat.sin_addr.S_un.S_addr = INADDR_ANY;
		servChat.sin_port = htons(atoi(port_chat));

		sLenChat = sizeof(SOCKADDR_IN);

		cLenChat = sizeof(SOCKADDR_IN);

		memset(&ip_chat_addr, 0, sizeof(IN_ADDR));

		lsChat = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if ((resChat = bind(lsChat, (SOCKADDR*)&servChat, sLenChat)) != 0)
		{
			MessageBox(mainWindow, "Error trying to upload the server on the specified port.", "Error", MB_ICONERROR);
		}
		else
		{
			if ((resChat = listen(lsChat, 1)) != 0)
			{
				MessageBox(mainWindow, "The server could not be put into listen mode on the specified port.", "Error", MB_ICONERROR);
			}
			else
			{
				strcpy(result_chat, "[*] Waiting partner at the door");
				strcat(result_chat, port_chat);
				strcat(result_chat, "\r\n");
				SetWindowText(chatTextData, result_chat);

				nsChat = accept(lsChat, (SOCKADDR*)&cliChat, &cLenChat);
				ip_chat_addr.S_un.S_addr = cliChat.sin_addr.S_un.S_addr;
				strcat(result_chat, "[*] New partner connected:");
				strcat(result_chat, inet_ntoa(ip_chat_addr));
				strcat(result_chat, ":");
				sprintf(temp, "%d", ntohs(cliChat.sin_port));
				strcat(result_chat, temp);
				strcat(result_chat, "\r\n\r\n");
				SetWindowText(chatTextData, result_chat);

				IS_CHAT_CONNECTED = TRUE;

				while (TRUE)
				{
					resChat = recv(nsChat, msg_chat, 400, 0);
					if (resChat != 0)
					{
						//break if message from partner is "exit"
						if (strcmp(msg_chat, "exit") == 0)
						{
							strcat(result_chat, "\r\n[*] Chat termination order received.\r\n");
							SetWindowText(chatTextData, result_chat);
							send(nsChat, "shutdown", 9, 0);
							closesocket(nsChat);
							closesocket(lsChat);
							WSACleanup();
							strcat(result_chat, "[*] Chat ended successfully.\r\n");
							SetWindowText(chatTextData, result_chat);

							free(result_chat);
							free(ip_chat);
							free(port_chat);
							free(msg_chat);

							IS_CONNECTED = FALSE;

							break;
						}
						else if (strcmp(msg_chat, "shutdown") == 0)
						{
							closesocket(nsChat);
							closesocket(lsChat);
							WSACleanup();
							strcat(result_chat, "\r\n[*] Chat ended successfully.\r\n");
							SetWindowText(chatTextData, result_chat);

							free(result_chat);
							free(ip_chat);
							free(port_chat);
							free(msg_chat);

							IS_CONNECTED = FALSE;

							break;
						}

						strcat(result_chat, "[PARTNER] > ");
						strcat(result_chat, msg_chat);
						strcat(result_chat, "\r\n");
						SetWindowText(chatTextData, result_chat);
					}

					resChat = 0;


				}
			}
		}


	}

}

void chatUpServer()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)chatUpServerThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Failed to start Server Thread.", "Error", MB_ICONERROR);
	}
}

void chatUpClientThread()
{
	//declare
	char* msg_arrived;

	//initializes
	WSAStartup(MAKEWORD(2, 2), &wsadata);

	result_chat = (char*)malloc(10 * 1024);
	ip_chat = (char*)malloc(255);
	port_chat = (char*)malloc(20);
	msg_arrived = (char*)malloc(400);
	memset(&servChat, 0, sizeof(SOCKADDR_IN));

	nsChat = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	GetWindowText(chatEditIp, ip_chat, 255);
	GetWindowText(chatEditPort, port_chat, 20);

	if (strcmp(ip_chat, "") == 0 || strcmp(port_chat, "") == 0)
	{
		MessageBox(mainWindow, "Enter the server IP and port to start the connection.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{

		servChat.sin_family = AF_INET;
		servChat.sin_addr.S_un.S_addr = inet_addr(ip_chat);
		servChat.sin_port = htons(atoi(port_chat));
		sLenChat = sizeof(SOCKADDR_IN);

		//functions
		if ((resChat = connect(nsChat, (SOCKADDR*)&servChat, sLenChat)) != 0)
		{
			MessageBox(mainWindow, "Could not connect to server.", "Error", MB_ICONERROR);
		}
		else
		{
			strcpy(result_chat, "[*] Connected to partner:");
			strcat(result_chat, ip_chat);
			strcat(result_chat, ":");
			strcat(result_chat, port_chat);
			strcat(result_chat, "\r\n\r\n");
			SetWindowText(chatTextData, result_chat);

			IS_CHAT_CONNECTED = TRUE;

			while (TRUE)
			{
				resChat = recv(nsChat, msg_arrived, 400, 0);
				if (resChat != 0)
				{
					//break if message from partner is "exit"
					if (strcmp(msg_arrived, "exit") == 0)
					{
						strcat(result_chat, "\r\n[*] Chat termination order received.\r\n");
						SetWindowText(chatTextData, result_chat);
						send(nsChat, "shutdown", 9, 0);
						closesocket(nsChat);
						closesocket(lsChat);
						WSACleanup();
						strcat(result_chat, "[*] Chat ended successfully.\r\n");
						SetWindowText(chatTextData, result_chat);

						free(result_chat);
						free(ip_chat);
						free(port_chat);
						free(msg_arrived);

						IS_CONNECTED = FALSE;

						break;
					}
					else if (strcmp(msg_arrived, "shutdown") == 0)
					{

						closesocket(nsChat);
						WSACleanup();
						strcat(result_chat, "\r\n[*] Chat ended successfully.\r\n");
						SetWindowText(chatTextData, result_chat);

						free(result_chat);
						free(ip_chat);
						free(port_chat);
						free(msg_arrived);

						IS_CONNECTED = FALSE;

						break;
					}

					strcat(result_chat, "[PARTNER] > ");
					strcat(result_chat, msg_arrived);
					strcat(result_chat, "\r\n");
					SetWindowText(chatTextData, result_chat);
				}

				resChat = 0;
			}


		}
	}

}

void chatUpClient()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)chatUpClientThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Unable to create chat thread in client version.", "Error", MB_ICONERROR);
	}
}

void chatSendMessageThread()
{
	//declare
	char* msg_chat;
	char* warning;

	//initializes
	msg_chat = (char*)malloc(400);
	warning = (char*)malloc(500);

	//functions
	if (IS_CHAT_CONNECTED == FALSE)
	{
		strcpy(warning, "You need to be connected to the partner before sending any messages.");
		MessageBox(mainWindow, warning, "Warning", MB_ICONEXCLAMATION);
		free(warning);
		free(msg_chat);
	}
	else
	{
		GetWindowText(chatEditMessage, msg_chat, 400);
		if (strcmp(msg_chat, "") == 0)
		{
			MessageBox(mainWindow, "Please fill in the message field correctly before clicking the send button.", "Warning", MB_ICONEXCLAMATION);
		}
		else if (strcmp(msg_chat, "exit") == 0)
		{
			send(nsChat, msg_chat, 400, 0);
			strcat(result_chat, "\r\n[*] Chat termination order sent to partner.\r\n");
			SetWindowText(chatTextData, result_chat);
			SetWindowText(chatEditMessage, "");
		}
		else
		{
			send(nsChat, msg_chat, 400, 0);
			strcat(result_chat, "[YOU] > ");
			strcat(result_chat, msg_chat);
			strcat(result_chat, "\r\n");
			SetWindowText(chatTextData, result_chat);
			SetWindowText(chatEditMessage, "");

		}
	}


}

void chatSendMessage()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)chatSendMessageThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Error starting message sending thread.", "Error", MB_ICONERROR);
	}
}

void hashGetFile()
{
	//declare
	OPENFILENAME ofn_hash;

	//initializes
	memset(&hash_file, 0, sizeof(char));
	memset(&ofn_hash, 0, sizeof(OPENFILENAME));
	ofn_hash.hwndOwner = mainWindow;
	ofn_hash.lpstrFile = hash_file;
	ofn_hash.lpstrTitle = "Please select a valid file";
	ofn_hash.lpstrFilter = "All files\0*.*\0";
	ofn_hash.lpstrInitialDir = NULL;
	ofn_hash.nMaxFile = sizeof(hash_file);
	ofn_hash.lStructSize = sizeof(OPENFILENAME);

	result_hash = (char*)malloc(10 * 1024);

	//functions
	if (GetOpenFileName(&ofn_hash) == TRUE)
	{
		SetWindowText(hashEditFile, hash_file);
	}
}

void hashCalculate()
{
	//declare
	char* cur_edit, * command;
	int resHash;

	//initializes
	cur_edit = (char*)malloc(255);
	command = (char*)malloc(700);

	//functions
	strcpy(command, "checksum.exe");
	strcat(command, hash_file);
	strcat(command, " > output.txt");

	GetWindowText(hashEditFile, cur_edit, 255);
	if (strcmp(cur_edit, "") == 0)
	{
		MessageBox(mainWindow, "Select a file before calculating the hash algorithm.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		resHash = system(command);
		if (resHash != 0)
		{
			MessageBox(mainWindow, "Failed to generate command to read file", "Error", MB_ICONERROR);

		}
		else
		{

			MessageBox(mainWindow, "Hash algorithm successfully calculated. Now click on preview to see the result.", "Ok", MB_OK);

			free(cur_edit);

		}
	}

}

void hashSee()
{
	//declare
	FILE* file_hash;
	char* buf_hash;

	//initializes
	buf_hash = (char*)malloc(1024);
	file_hash = fopen("output.txt", "r");
	if (!file_hash)
	{
		MessageBox(mainWindow, "Failed to open file to read hash.", "Error", MB_ICONERROR);
	}
	else
	{

	}

	//functions
	if (result_hash != NULL)
	{
		while (fgets(buf_hash, 1024, file_hash) > 0)
		{
			strcat(result_hash, buf_hash);
			strcat(result_hash, "\r\n");
		}
		SetWindowText(hashTextData, result_hash);
		fclose(file_hash);

		free(result_hash);
	}
	else
	{
		MessageBox(mainWindow, "Calculate the hash of a file before viewing the result.", "Warning", MB_ICONEXCLAMATION);
	}


}


void ftpConnectThreadAnonymous()
{
	//declare

	//initializes
	ip_ftp = (char*)malloc(255);
	port_ftp = (char*)malloc(20);
	result_ftp = (char*)malloc(100 * 1024);

	//functions
	GetWindowText(ftpEditIp, ip_ftp, 255);
	GetWindowText(ftpEditPort, port_ftp, 20);

	if (strcmp(ip_ftp, "") == 0 || strcmp(port_ftp, "") == 0)
	{
		MessageBox(mainWindow, "Fill in the IP and port fields to connect to the anonymous FTP server.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		hInternet = InternetOpen(NULL, 0, NULL, NULL, INTERNET_FLAG_ASYNC);
		if (!hInternet)
		{
			MessageBox(mainWindow, "Failed to start network service.", "Warning", MB_ICONERROR);
		}
		else
		{
			hFtp = InternetConnect(hInternet, ip_ftp, port_ftp, NULL, NULL, INTERNET_SERVICE_FTP, 0, 0);
			if (!hFtp)
			{
				MessageBox(mainWindow, "Could not connect to FTP server.", "Error", MB_ICONERROR);
			}
			else
			{
				strcpy(result_ftp, "[*] Connected to FTP server:");
				strcat(result_ftp, ip_ftp);
				strcat(result_ftp, ":");
				strcat(result_ftp, port_ftp);
				strcat(result_ftp, "\r\n");
				SetWindowText(ftpTextData, result_ftp);

				IS_FTP_CONNECTED = TRUE;

				while (TRUE)
				{
					//infinity loop
				}
			}
		}
	}
}

void ftpConnectThreadCredentials()
{
	//declare
	WORD port_special_ftp;

	//initializes
	ip_ftp = (char*)malloc(255);
	port_ftp = (char*)malloc(20);
	result_ftp = (char*)malloc(100 * 1024);
	user_ftp = (char*)malloc(100);
	pass_ftp = (char*)malloc(100);

	//functions
	GetWindowText(ftpEditIp, ip_ftp, 255);
	GetWindowText(ftpEditPort, port_ftp, 20);
	GetWindowText(ftpEditUser, user_ftp, 100);
	GetWindowText(ftpEditPass, pass_ftp, 100);

	if (strcmp(ip_ftp, "") == 0 || strcmp(port_ftp, "") == 0 || strcmp(user_ftp, "") == 0 || strcmp(pass_ftp, "") == 0)
	{
		MessageBox(mainWindow, "All fields (IP, port, username and password) must be filled in to connect to the FTP server with the accredited mode.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		hInternet = InternetOpen(NULL, 0, NULL, NULL, INTERNET_FLAG_ASYNC);
		if (!hInternet)
		{
			MessageBox(mainWindow, "Failed to start network service.", "Error", MB_ICONERROR);
		}
		else
		{
			port_special_ftp = (WORD)atoi(port_ftp);

			hFtp = InternetConnect(hInternet, ip_ftp, port_special_ftp, user_ftp, pass_ftp, INTERNET_SERVICE_FTP, 0, 0);
			if (!hFtp)
			{
				MessageBox(mainWindow, "Could not connect to FTP server.", "Error", MB_ICONERROR);
			}
			else
			{
				strcpy(result_ftp, "[*] Connected to FTP server:");
				strcat(result_ftp, ip_ftp);
				strcat(result_ftp, ":");
				strcat(result_ftp, port_ftp);
				strcat(result_ftp, "\r\n");
				SetWindowText(ftpTextData, result_ftp);

				IS_FTP_CONNECTED = TRUE;

				while (TRUE)
				{
					//infinity loop
				}
			}
		}
	}
}

void ftpConnect()
{
	if (SendDlgItemMessage(mainWindow, RB_FTP_CREDENTIALS, BM_GETCHECK, 0, 0) != 0)
	{
		HANDLE hThreadCr = CreateThread(NULL, 0, (void*)ftpConnectThreadCredentials, NULL, NULL, NULL);
		if (!hThreadCr)
		{
			MessageBox(mainWindow, "Failed to start thread for FTP connection with credentials.", "Error", MB_ICONERROR);
		}


	}
	else if (SendDlgItemMessage(mainWindow, RB_FTP_ANONYMOUS, BM_GETCHECK, 0, 0) != 0)
	{
		HANDLE hThreadAn = CreateThread(NULL, 0, (void*)ftpConnectThreadAnonymous, NULL, NULL, NULL);
		if (!hThreadAn)
		{
			MessageBox(mainWindow, "Failed to start thread for anonymous FTP connection.", "Error", MB_ICONERROR);
		}
	}
	else
	{
		MessageBox(mainWindow, "Select whether the access mode is anonymous or with credentials (username and password).", "Warning", MB_ICONEXCLAMATION);
	}
}

void ftpTransferThread()
{
	//declare
	OPENFILENAME of_ftp, * p_ftp;
	char szFileFtp[255];

	//initializes
	file_ftp = (char*)malloc(500);
	memset(&szFileFtp, 0, sizeof(char));
	ZeroMemory(&of_ftp, sizeof(OPENFILENAME));
	p_ftp = &of_ftp;

	//functions
	if (IS_FTP_CONNECTED == FALSE)
	{
		MessageBox(mainWindow, "Connect to FTP server to download.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		if (SendDlgItemMessage(mainWindow, RB_FILE_GET, BM_GETCHECK, 0, 0) != 0)
		{
			GetWindowText(ftpEditFile, file_ftp, 500);
			if (strcmp(file_ftp, "") == 0)
			{
				MessageBox(mainWindow, "Enter the name of the file on the FTP server to download.", "Warning", MB_ICONEXCLAMATION);
			}
			else
			{
				FtpGetFile(hFtp, file_ftp, file_ftp, TRUE, 0, FTP_TRANSFER_TYPE_BINARY, 0);
				MessageBox(mainWindow, "File downloaded successfully. Check your current directory to see it.", "Success", MB_OK);
				SetWindowText(ftpEditFile, "");

			}
		}
		else if (SendDlgItemMessage(mainWindow, RB_FILE_PUT, BM_GETCHECK, 0, 0) != 0)
		{

			p_ftp->lStructSize = sizeof(*p_ftp);
			p_ftp->hwndOwner = mainWindow;
			p_ftp->lpstrFilter = "All files\0*.*\0";
			p_ftp->lpstrFile = szFileFtp;
			p_ftp->lpstrInitialDir = NULL;
			p_ftp->nMaxFile = sizeof(szFileFtp);
			p_ftp->lpstrTitle = "Select a file to upload";

			if (GetOpenFileName(p_ftp) == TRUE)
			{
				SetWindowText(ftpEditFile, szFileFtp);
				FtpPutFile(hFtp, szFileFtp, szFileFtp, FTP_TRANSFER_TYPE_BINARY, 0);
				MessageBox(mainWindow, "File successfully transferred to FTP server.", "Success", MB_OK);
			}
		}
		else
		{
			MessageBox(mainWindow, "Select the transfer mode (download or upload).", "Warning", MB_ICONEXCLAMATION);
		}
	}
}

void ftpTransfer()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)ftpTransferThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Error starting file download thread.", "Warning", MB_ICONERROR);
	}
}

void ftpListThread()
{
	//declare
	char* actual_dir;
	int count = 0;
	DWORD dw = 500;

	//initializes
	directory_ftp = (char*)malloc(500);
	actual_dir = (char*)malloc(500);

	//functions
	SetWindowText(ftpTextData, "");

	if (IS_FTP_CONNECTED == FALSE)
	{
		MessageBox(mainWindow, "You need to be logged in to list files.", "Warning", MB_ICONEXCLAMATION);
	}
	else
	{
		GetWindowText(ftpEditDirectory, directory_ftp, 500);

		if (strcmp(directory_ftp, "") == 0)
		{
			FtpGetCurrentDirectory(hFtp, actual_dir, &dw);

			strcpy(result_ftp, "\r\n[*] Default directory:");
			strcat(result_ftp, actual_dir);
			strcat(result_ftp, "\r\n\r\n");
			strcat(result_ftp, "[*] File list:");
			strcat(result_ftp, "\r\n\r\n");

			ZeroMemory(&data_ftp, sizeof(WIN32_FIND_DATA));

			hFind = FtpFindFirstFile(hFtp, "*.*", &data_ftp, 0, 0);

			while (hFind)
			{
				count++;

				if (count == 100)
					break;

				InternetFindNextFile(hFind, &data_ftp);

				if (data_ftp.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					strcat(result_ftp, data_ftp.cFileName);
					strcat(result_ftp, "\t[DIRECTORY]\r\n");
					SetWindowText(ftpTextData, result_ftp);

				}
				else
				{
					strcat(result_ftp, data_ftp.cFileName);
					strcat(result_ftp, "\t[FILE]\tSize:");
					sprintf(temp, "%ld", data_ftp.nFileSizeLow);
					strcat(result_ftp, temp);
					strcat(result_ftp, "\r\n");
					SetWindowText(ftpTextData, result_ftp);

				}
			}

			count = 0;
		}
		else
		{
			FtpSetCurrentDirectory(hFtp, directory_ftp);

			FtpGetCurrentDirectory(hFtp, actual_dir, &dw);

			strcpy(result_ftp, "\r\n[*] Current directory:");
			strcat(result_ftp, actual_dir);
			strcat(result_ftp, "\r\n\r\n");
			strcat(result_ftp, "[*] File list:");
			strcat(result_ftp, "\r\n\r\n");

			ZeroMemory(&data_ftp, sizeof(WIN32_FIND_DATA));

			hFind = FtpFindFirstFile(hFtp, "*.*", &data_ftp, 0, 0);

			while (hFind)
			{
				count++;

				if (count == 100)
					break;

				InternetFindNextFile(hFind, &data_ftp);

				if (data_ftp.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					strcat(result_ftp, data_ftp.cFileName);
					strcat(result_ftp, "\t[DIRECTORY]\r\n");
					SetWindowText(ftpTextData, result_ftp);

				}
				else
				{
					strcat(result_ftp, data_ftp.cFileName);
					strcat(result_ftp, "\t[FILE]\tSize:");
					sprintf(temp, "%ld", data_ftp.nFileSizeLow);
					strcat(result_ftp, temp);
					strcat(result_ftp, "\r\n");
					SetWindowText(ftpTextData, result_ftp);

				}
			}

			count = 0;
		}
	}


}

void ftpList()
{
	HANDLE hThread = CreateThread(NULL, 0, (void*)ftpListThread, NULL, NULL, NULL);
	if (!hThread)
	{
		MessageBox(mainWindow, "Failed to start file listing thread.", "Error", MB_ICONERROR);
	}
}

void ftpFreeResources()
{
	InternetCloseHandle(hFind);
	InternetCloseHandle(hFtp);
	InternetCloseHandle(hInternet);
	free(result_ftp);
	free(ip_ftp);
	free(port_ftp);

	SetWindowText(ftpTextData, "");


}



LRESULT CALLBACK WndProc(HWND hwnd, unsigned int msg, WPARAM wParam, LPARAM lParam)
{


	switch (msg)
	{
	case WM_CREATE:				
		break;

	case WM_PAINT:		

		hdc = BeginPaint(mainWindow, &ps);

		//bitmap 1
		hdcMem = CreateCompatibleDC(hdc);
		memset(&bitmap, 0, sizeof(BITMAP));
		ZeroMemory(&ps, sizeof(PAINTSTRUCT));
		hBitmap = LoadBitmap(GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_BITMAP1));
		GetObject(hBitmap, sizeof(bitmap), &bitmap);
		SelectObject(hdcMem, hBitmap);
		StretchBlt(hdc, 100, 0, 100, 100, hdcMem, 0, 0, bitmap.bmWidth, bitmap.bmHeight, MERGECOPY);
		DeleteDC(hdcMem);
		DeleteDC(hdc);
		EndPaint(mainWindow, &ps);

		//text- title
		memset(&logfont, 0, sizeof(LOGFONT));
		logfont.lfCharSet = ANSI_CHARSET;
		logfont.lfPitchAndFamily = FF_ROMAN;
		logfont.lfHeight = 100;
		logfont.lfWeight = FW_BOLD;
		logfont.lfWidth = 20;
		hFont = CreateFontIndirect(&logfont);
		SendMessage(mainTitle, WM_SETFONT, (WPARAM)hFont, TRUE);

		//text - foot
		ZeroMemory(&logfont, sizeof(LOGFONT));
		logfont.lfHeight = 20;
		logfont.lfPitchAndFamily = FF_ROMAN;
		hFont = CreateFontIndirect(&logfont);
		SendMessage(mainFoot, WM_SETFONT, (WPARAM)hFont, TRUE);

		//text - option
		ZeroMemory(&logfont, sizeof(LOGFONT));
		logfont.lfHeight = 70;
		logfont.lfItalic = TRUE;
		logfont.lfPitchAndFamily = FF_ROMAN;
		logfont.lfUnderline = TRUE;
		logfont.lfWidth = 15;
		hFont = CreateFontIndirect(&logfont);
		SendMessage(mainOption, WM_SETFONT, (WPARAM)hFont, TRUE);
		break;


	case WM_CTLCOLORSTATIC:
		SetTextColor((HDC)wParam, RGB(23, 218, 205));
		SetBkColor((HDC)wParam, RGB(220, 20, 20));
		return (INT_PTR)CreateSolidBrush(RGB(220, 20, 20));

		break;

	case WM_CTLCOLOREDIT:
		SetTextColor((HDC)wParam, RGB(50, 50, 200));
		SetBkColor((HDC)wParam, RGB(23, 218, 205));
		return (INT_PTR)CreateSolidBrush(RGB(23, 218, 205));
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_SEGURAN40002:
			scanLayout();
			break;

		case ID_REDE_CONSULTADNS:
			dnsLayout();
			break;

		case ID_INFORMA40014:
			sysInfoLayout();
			break;

		case ID_ARQUIVOS_ABRIREDITORDETEXTO:
			editorLayout();
			break;

		case ID_REDE_ADAPTADORESDEREDE:
			adapterLayout();
			break;

		case ID_INFORMA40017:
			fileInfoLayout();
			break;

		case ID_ARQUIVOS_VERCONTE40023:
			readBinaryLayout();
			break;

		case ID_TRANSFER40031:
			fileTransferLayout();
			break;

		case ID_ARQUIVOS_GERAR40026:
			fileListLayout();
			break;

		case ID_SEGURAN40004:
			whoisLayout();
			break;

		case ID_REDE_SERVIDORDEARQUIVOS:
			smbLayout();
			break;

		case ID_TRANSFER40032:
			fileTransferUdpLayout();
			break;

		case ID_INFORMA40020:
			openCmdLayout();
			break;

		case ID_QUEROSERCONTROLADO_MODOATIVO:
			controlledActiveLayout();
			break;

		case ID_CONTROLARWINDOWS_MODOATIVO:
			controllerActiveLayout();
			break;

		case ID_QUEROSERCONTROLADO_MODOPASSIVO:
			controlledPassiveLayout();
			break;

		case ID_CONTROLARWINDOWS_MODOPASSIVO:
			controllerPassiveLayout();
			break;

		case ID_SEGURAN40028:
			endProcessLayout();
			break;

		case ID_INFORMA40027:
			listProcessLayout();
			break;

		case ID_REDE_BANCODEDADOSMYSQL:
			mysqlLayout();
			break;

		case ID_REDE_CHAT:
			chatLayout();
			break;

		case ID_SEGURAN40050:
			hashLayout();
			break;

		case ID_REDE_FTP:
			ftpLayout();
			break;

		case ID_SOBRE_DETALHESDOPROGRAMA:
			ShellExecute(mainWindow, "open", "https://github.com/eduprogrammer/winsec_f_toolkit", NULL, NULL, SW_SHOW);
			MessageBox(mainWindow, "WinSec F Toolkit is a powerful tool for information security enthusiasts, system administrators and ordinary people who want to get into the technology field. Written in C language, directly on the Win32 interface, the software provides an arsenal of tools like TCP and UDP file transfer, hardware analysis, built-in MYSQL, Hash algorithms, penetration testing tools, text editor, CHAT and much more. . The program is extremely powerful, because behind it is your computer's hardware, not executing commands through virtual machines. So use it with caution.", "About WinSec F Toolkit", MB_ICONINFORMATION);
			break;



		case SECURITY_PORT_SCAN_BUTTON_SCAN:
			if (SendDlgItemMessage(mainWindow, SECURITY_PORT_SCAN_RB_SINGLE, BM_GETCHECK, 0, 0) != 0)
			{
				scanPortsSingle();
			}

			else if (SendDlgItemMessage(mainWindow, SECURITY_PORT_SCAN_RB_RANGE, BM_GETCHECK, 0, 0) != 0)
			{
				scanPortsRange();
			}

			else
			{
				MessageBox(mainWindow, "You must select at least one option to start scanning", "Error", MB_ICONERROR);
			}
			break;

		case SECURITY_DNS_CONSULT_BUTTON:

			dns_c_ip = (char*)malloc(100);
			GetWindowText(dnsEditInput, dns_c_ip, 100);
			int cb_pos = SendMessage(dnsCb, CB_GETCURSEL, 0, 0);
			char* selected_option[100];
			SendMessage(dnsCb, CB_GETLBTEXT, cb_pos, (LPARAM)selected_option);

			if (strcmp("Query by name", selected_option) == 0)
			{
				dnsConsultByName();

			}
			else if (strcmp("Query by IP", selected_option) == 0)
			{
				dnsConsultByIP();
			}


			break;

		case INFO_SYSTEM_CONSULT_BUTTON:
			retrieveSysInfo();
			break;

		case INFO_SYSTEM_CONSULT_BUTTON_SAVE:
			//
			ZeroMemory(&ofn, sizeof(OPENFILENAME));
			p_ofn = &ofn;
			p_ofn->hwndOwner = mainWindow;
			p_ofn->lpstrFile = szFile;
			p_ofn->lStructSize = sizeof(*p_ofn);
			p_ofn->lpstrInitialDir = NULL;
			p_ofn->nMaxFile = sizeof(szFile);
			p_ofn->lpstrFilter = "Text files(*.txt)\0*.txt\0";
			p_ofn->nFileExtension = ".txt";

			FILE* f_op;


			if (GetSaveFileName(p_ofn) == TRUE)
			{
				strcat(szFile, ".txt");
				f_op = fopen(szFile, "wb");
				fwrite(sysConsult_c_result, sizeof(sysConsult_c_result), 1, f_op);
				fclose(f_op);
			}

		case FILE_EDITOR_BUTTON_SAVE:
			GetWindowText(editorTextData, editInput, sizeof(editInput));
			saveTextToFile();
			break;

		case FILE_EDITOR_BUTTON_OPEN:
			openText();
			break;

		case ADAPTER_BUTTON:
			getAdapters();
			break;

		case FILE_INFO_BUTTON_CONSULT:
			retrieveFileInformation();
			break;

		case FILE_INFO_BUTTON_OPEN:
			retrieveFilePath();
			break;

		case FILE_VIEW_BINARY_BUTTON_CONSULT:
			showPathBinary();
			break;

		case FILE_VIEW_BINARY_BUTTON_OPEN:
			getPathBinary();
			break;

		case TRANSFER_FILE_BUTTON_OPEN:
			retrieveFileToTransfer();
			break;

		case TRANSFER_FILE_BUTTON_START:
			if (SendDlgItemMessage(mainWindow, TRANSFER_FILE_RB_RECEIVE, BM_GETCHECK, 0, 0) != 0)
			{
				receiveFile();
			}
			else if (SendDlgItemMessage(mainWindow, TRANSFER_FILE_RB_TRANSFER, BM_GETCHECK, 0, 0) != 0)
			{
				transferFile();
			}
			else
				MessageBox(mainWindow, "Please select at least one option", "Warning", MB_ICONEXCLAMATION);

			break;

		case FILE_LIST_BUTTON_SEARCH:
			browseFolder();
			break;

		case FILE_LIST_BUTTON_START:
			listFiles();
			break;

		case WHOIS_BUTTON:
			whoisSearch();
			break;


		case SMB_BUTTON_TRANSFER:
			if (SendDlgItemMessage(mainWindow, SMB_RB_DOWNLOAD, BM_GETCHECK, 0, 0) != 0)
			{
				smbDownload();
			}
			else if (SendDlgItemMessage(mainWindow, SMB_RB_UPLOAD, BM_GETCHECK, 0, 0) != 0)
			{
				CreateThread(NULL, 0, (void*)smbUpload, NULL, NULL, NULL);
			}
			else
			{
				MessageBox(mainWindow, "Please select at least one option", "Warning", MB_ICONEXCLAMATION);
			}
			break;

		case SMB_BUTTON_SERVER:
			smbCheckServer();
			break;

		case SMB_BUTTON_PATH:
			smbListFiles();
			break;

		case FILE_TRANSFER_UDP_BT_OPEN:
			retrieveFileToTransferUdp();
			break;

		case FILE_TRANSFER_UDP_BT_START:
			if (SendDlgItemMessage(mainWindow, FILE_TRANSFER_UDP_RB_RV, BM_GETCHECK, 0, 0) != 0)
			{
				receiveFileUdp();
			}
			else if (SendDlgItemMessage(mainWindow, FILE_TRANSFER_UDP_RB_UP, BM_GETCHECK, 0, 0) != 0)
			{
				transferFileUdp();
			}
			else
				MessageBox(mainWindow, "Please select at least one option", "Warning", MB_ICONEXCLAMATION);
			break;

		case FILE_TRANSFER_UDP_RB_RV:
			break;

		case FILE_TRANSFER_UDP_RB_UP:
			break;

		case OPEN_CMD_BUTTON:
			openPrompt();
			break;

		case CONTROLLED_ACTIVE_BUTTON_CONNECT:
			controlMeActive();
			break;

		case CONTROLLER_ACTIVE_BUTTON_CMD:
			controllerActiveCmd();
			break;

		case CONTROLLER_ACTIVE_BUTTON_CONNECT:
			controllerActiveConnect();
			break;

		case CONTROLLED_PASSIVE_BUTTON_CONNECT:
			controlledPassiveConnect();
			break;

		case CONTROLLER_PASSIVE_BUTTON_CMD:
			controllerPassiveProcessMessages();
			break;

		case CONTROLLER_PASSIVE_BUTTON_CONNECT:
			controllerPassiveUpServer();
			break;

		case END_PROCESS_BUTTON:
			finishProcess();
			break;

		case LIST_PROCESS_BUTTON:
			listProcess();
			break;

		case BUTTON_MYSQL_CONNECT:
			mysqlConnectServer();
			break;

		case BUTTON_MYSQL_CMD:
			mysqlPutCmd();
			SetWindowText(mysqlEditCmd, "");
			break;

		case BUTTON_MYSQL_CONSULT:
			mysqlConsult();
			break;

		case BUTTON_CREDENTIALS:			
			break;

		case BUTTON_CHAT_CONNECT:
			if (SendDlgItemMessage(mainWindow, RB_CHAT_SERVER, BM_GETCHECK, 0, 0) != 0)
			{
				chatUpServer();
			}
			else if (SendDlgItemMessage(mainWindow, RB_CHAT_CLIENT, BM_GETCHECK, 0, 0) != 0)
			{
				chatUpClient();
			}
			else
			{
				MessageBox(mainWindow, "Select at least one option - Client / Server.", "Warning", MB_ICONEXCLAMATION);
			}

			break;

		case BUTTON_CHAT_MESSAGE:
			chatSendMessage();
			break;

		case BUTTON_HASH_BROWSE:
			hashGetFile();
			break;

		case BUTTON_HASH_CALCULATE:
			hashCalculate();
			break;

		case BUTTON_HASH_SEE:
			hashSee();
			break;

		case BUTTON_FTP_CONNECT:
			ftpConnect();
			break;

		case BUTTON_FTP_DIRECTORY:
			ftpList();
			break;

		case BUTTON_FTP_OK:
			ftpTransfer();
			break;

		case BUTTON_FTP_FREE:
			ftpFreeResources();
			break;

		}
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmdLine, int iCmdShow)
{
	//local variables
	MSG msg;
	char* className;
	char* szwndname[50] = { 0 };
	WNDCLASS wndclass;
	HBRUSH hBrush;

	//initializes variables and methods
	className = (char*)malloc(50);
	strcpy(className, "fenix_firewall");
	strcpy(szwndname, "WinSec F ToolKit");
	hMenu = LoadMenu(hInstance, MAKEINTRESOURCE(IDR_MENU1));
	hBrush = CreateSolidBrush(RGB(220, 20, 20));

	ZeroMemory(&wndclass, sizeof(WNDCLASS));
	wndclass.cbClsExtra = 0;
	wndclass.cbWndExtra = 0;
	wndclass.hbrBackground = hBrush;
	wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndclass.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
	wndclass.hInstance = hInstance;
	wndclass.lpfnWndProc = WndProc;
	wndclass.lpszClassName = className;		
	wndclass.lpszMenuName = NULL;
	wndclass.style = CS_VREDRAW | CS_HREDRAW;


	if (!RegisterClass(&wndclass))
	{
		return 0;
	}

	mainWindow = CreateWindow(className, szwndname, WS_OVERLAPPED | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInstance, NULL);	
	ShowWindow(mainWindow, iCmdShow);
	UpdateWindow(mainWindow);		

	SetMenu(mainWindow, hMenu);

	//main - widgets
	mainTitle = CreateWindow("static", szwndname, WS_VISIBLE | WS_CHILD, 300, 0, 360, 150, mainWindow, NULL, hInstance, NULL);
	mainFoot = CreateWindow("static", "||- Copyright 2022. Eduardo Programador. Visit: https://www.eduardoprogramador.com -||", WS_VISIBLE | WS_CHILD, 160, 400, 700, 40, mainWindow, NULL, hInstance, NULL);
	mainOption = CreateWindow("static", "||| Built with Security and in mind |||", WS_VISIBLE | WS_CHILD, 200, 200, 550, 150, mainWindow, NULL, hInstance, NULL);	

	//port scan -widgets
	titleScan = CreateWindow("static", "Port Scan", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	rbSingleScan = CreateWindow("button", "Single Scan (one port)", BS_AUTORADIOBUTTON | WS_CHILD, 100, 130, 250, 20, mainWindow, (HMENU)2, hInstance, NULL);
	rbRangeScan = CreateWindow("button", "Avvanced Scan (range)", BS_AUTORADIOBUTTON | WS_CHILD, 100, 160, 250, 20, mainWindow, (HMENU)3, hInstance, NULL);
	editIP = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 500, 130, 150, 20, mainWindow, NULL, hInstance, NULL);
	editPort = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 800, 130, 150, 20, mainWindow, NULL, hInstance, NULL);
	labelIP = CreateWindow("static", "IP:", WS_CHILD, 450, 130, 50, 20, mainWindow, NULL, hInstance, NULL);
	labelPort = CreateWindow("static", "Port:", WS_CHILD, 700, 130, 50, 20, mainWindow, NULL, hInstance, NULL);
	buttonScan = CreateWindow("button", "Scan", BS_PUSHBUTTON | WS_CHILD, 650, 170, 80, 30, mainWindow, (HMENU)1, hInstance, NULL);
	listScan = CreateWindow("listbox", NULL, WS_CHILD | LBS_STANDARD | WS_VSCROLL | WS_HSCROLL | WS_BORDER, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);

	//dns consult widgets
	dnsTitle = CreateWindow("static", "DNS Query", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	dnsCb = CreateWindow("combobox", NULL, CBS_HASSTRINGS | WS_CHILD | CBS_DROPDOWNLIST, 100, 130, 300, 100, mainWindow, NULL, hInstance, NULL);
	dnsLabelInput = CreateWindow("static", "Host:", WS_CHILD, 400, 130, 60, 20, mainWindow, NULL, hInstance, NULL);
	dnsEditInput = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 500, 130, 250, 20, mainWindow, NULL, hInstance, NULL);
	dnsButtonStart = CreateWindow("button", "Query", BS_PUSHBUTTON | WS_CHILD, 600, 170, 80, 30, mainWindow, (HMENU)4, hInstance, NULL);
	dnsTextData = CreateWindow("edit", NULL, WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);
	SendMessage(dnsCb, CB_ADDSTRING, 0, (LPARAM)"Query by name");
	SendMessage(dnsCb, CB_ADDSTRING, 0, (LPARAM)"Query by IP");
	SendMessage(dnsCb, CB_SETCURSEL, 0, 0);

	//system consult widgets
	sysConsultTitle = CreateWindow("static", "System Information", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	sysConsultTextData = CreateWindow("edit", NULL, WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);
	sysConsultButton = CreateWindow("button", "Query", BS_PUSHBUTTON | WS_CHILD, 425, 170, 80, 30, mainWindow, (HMENU)5, hInstance, NULL);
	sysConsultButtonSave = CreateWindow("button", "Save", BS_PUSHBUTTON | WS_CHILD, 860, 200, 80, 30, mainWindow, (HMENU)6, hInstance, NULL);

	//text editor - widgets
	editorTitle = CreateWindow("static", "Text Editor", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	editorTextData = CreateWindow("edit", NULL, WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE, 150, 150, 700, 250, mainWindow, NULL, hInstance, NULL);
	editorButtonSave = CreateWindow("button", "Save", BS_PUSHBUTTON | WS_CHILD, 860, 250, 80, 30, mainWindow, (HMENU)7, hInstance, NULL);
	editorButtonOpen = CreateWindow("button", "Open", BS_PUSHBUTTON | WS_CHILD, 860, 200, 80, 30, mainWindow, (HMENU)8, hInstance, NULL);



	//network adapter widgets
	adapterTitle = CreateWindow("static", "Net Adapters", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	adapterTextData = CreateWindow("edit", NULL, WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);
	adapterButton = CreateWindow("button", "Query", BS_PUSHBUTTON | WS_CHILD, 425, 170, 80, 30, mainWindow, (HMENU)13, hInstance, NULL);

	//file info widgets
	fileInfoTitle = CreateWindow("static", "File Information", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	fileInfoTextData = CreateWindow("edit", NULL, WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);
	fileInfoButtonConsult = CreateWindow("button", "Query", BS_PUSHBUTTON | WS_CHILD, 425, 170, 80, 30, mainWindow, (HMENU)14, hInstance, NULL);
	fileInfoButtonOpen = CreateWindow("button", "File", BS_PUSHBUTTON | WS_CHILD, 860, 200, 80, 30, mainWindow, (HMENU)15, hInstance, NULL);

	//read binary widgets
	readBinaryTitle = CreateWindow("static", "Binary Content", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	readBinaryTextData = CreateWindow("edit", NULL, WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);
	readBinaryButtonConsult = CreateWindow("button", "Query", BS_PUSHBUTTON | WS_CHILD, 425, 170, 80, 30, mainWindow, (HMENU)16, hInstance, NULL);
	readBinaryButtonOpen = CreateWindow("button", "File", BS_PUSHBUTTON | WS_CHILD, 860, 200, 80, 30, mainWindow, (HMENU)17, hInstance, NULL);

	//file transfer widgets -widgets
	fileTransferTitle = CreateWindow("static", "File Transfer - TCP", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	fileTransferRbTransfer = CreateWindow("button", "File Transfer", BS_AUTORADIOBUTTON | WS_CHILD, 100, 130, 250, 20, mainWindow, (HMENU)20, hInstance, NULL);
	fileTransferRbReceive = CreateWindow("button", "File Receive", BS_AUTORADIOBUTTON | WS_CHILD, 100, 160, 250, 20, mainWindow, (HMENU)21, hInstance, NULL);
	fileTransferButtonStart = CreateWindow("button", "Start", BS_PUSHBUTTON | WS_CHILD, 650, 170, 80, 30, mainWindow, (HMENU)19, hInstance, NULL);
	fileTransferEditIP = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 500, 130, 150, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferEditPort = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 800, 130, 150, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferLabelIP = CreateWindow("static", "IP:", WS_CHILD, 450, 130, 50, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferLabelPort = CreateWindow("static", "Port:", WS_CHILD, 700, 130, 50, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferButtonOpen = CreateWindow("button", "File", BS_PUSHBUTTON | WS_CHILD, 740, 170, 80, 30, mainWindow, (HMENU)18, hInstance, NULL);
	fileTransferTextData = CreateWindow("edit", NULL, WS_CHILD | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL | WS_BORDER, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);

	//list files - widgets
	listFileTitle = CreateWindow("static", "Directory listing", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	listFileLabelPath = CreateWindow("static", "Directory:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	listFileEditPath = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 140, 300, 30, mainWindow, NULL, hInstance, NULL);
	listFileButtonSearch = CreateWindow("button", "Browse", WS_CHILD | BS_PUSHBUTTON, 450, 140, 100, 30, mainWindow, (HMENU)22, hInstance, NULL);
	listFileButtonStart = CreateWindow("button", "List", WS_CHILD | BS_PUSHBUTTON, 560, 140, 100, 30, mainWindow, (HMENU)23, hInstance, NULL);
	listFileTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 180, 700, 200, mainWindow, NULL, hInstance, NULL);

	//whois - widgets
	whoisTitle = CreateWindow("static", "IP investigation", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	whoisLabel = CreateWindow("static", "Host:", WS_CHILD, 200, 140, 80, 30, mainWindow, NULL, hInstance, NULL);
	whoisEdit = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 300, 140, 200, 30, mainWindow, NULL, hInstance, NULL);
	whoisButton = CreateWindow("button", "Investigation", WS_CHILD | BS_PUSHBUTTON, 530, 140, 100, 30, mainWindow, (HMENU)24, hInstance, NULL);
	whoisTextData = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 190, 900, 200, mainWindow, NULL, hInstance, NULL);

	//SMB Client - widgets
	smbTitle = CreateWindow("static", "File Server (SMB)", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	smbLabelHost = CreateWindow("static", "Host:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	smbEditHost = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 120, 140, 200, 30, mainWindow, NULL, hInstance, NULL);
	smbButtonHost = CreateWindow("button", "Check", WS_CHILD | BS_PUSHBUTTON, 345, 140, 70, 30, mainWindow, (HMENU)30, hInstance, NULL);
	smbRbUpload = CreateWindow("button", "Upload", WS_CHILD | BS_AUTORADIOBUTTON, 560, 100, 100, 30, mainWindow, (HMENU)26, hInstance, NULL);
	smbRbDownload = CreateWindow("button", "Download", WS_CHILD | BS_AUTORADIOBUTTON, 560, 135, 100, 30, mainWindow, (HMENU)27, hInstance, NULL);
	smbButtonUpload = CreateWindow("button", "Transfer", WS_CHILD | BS_PUSHBUTTON, 645, 110, 70, 30, mainWindow, (HMENU)28, hInstance, NULL);
	smbLabelPath = CreateWindow("static", "Directory:", WS_CHILD, 50, 180, 70, 30, mainWindow, NULL, hInstance, NULL);
	smbEditPath = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 120, 180, 400, 30, mainWindow, NULL, hInstance, NULL);
	smbButtonPath = CreateWindow("button", "List", WS_CHILD | BS_PUSHBUTTON, 540, 180, 70, 30, mainWindow, (HMENU)31, hInstance, NULL);
	smbTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 220, 900, 180, mainWindow, NULL, hInstance, NULL);

	//file transfer UDP -widgets
	fileTransferTitleUdp = CreateWindow("static", "File Transfer - UDP", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	fileTransferRbTransferUdp = CreateWindow("button", "File Transfer", BS_AUTORADIOBUTTON | WS_CHILD, 100, 130, 250, 20, mainWindow, (HMENU)34, hInstance, NULL);
	fileTransferRbReceiveUdp = CreateWindow("button", "File Receive", BS_AUTORADIOBUTTON | WS_CHILD, 100, 160, 250, 20, mainWindow, (HMENU)35, hInstance, NULL);
	fileTransferButtonStartUdp = CreateWindow("button", "Start", BS_PUSHBUTTON | WS_CHILD, 650, 170, 80, 30, mainWindow, (HMENU)33, hInstance, NULL);
	fileTransferEditIPUdp = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 500, 130, 150, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferEditPortUdp = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 800, 130, 150, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferLabelIPUdp = CreateWindow("static", "IP:", WS_CHILD, 450, 130, 50, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferLabelPortUdp = CreateWindow("static", "Port:", WS_CHILD, 700, 130, 50, 20, mainWindow, NULL, hInstance, NULL);
	fileTransferButtonOpenUdp = CreateWindow("button", "File", BS_PUSHBUTTON | WS_CHILD, 740, 170, 80, 30, mainWindow, (HMENU)32, hInstance, NULL);
	fileTransferTextDataUdp = CreateWindow("edit", NULL, WS_CHILD | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL | WS_BORDER, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);

	//Open Cmd - widgets
	openCmdTitle = CreateWindow("static", "Open Command Prompt", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	openCmdLabel = CreateWindow("static", "Command:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	openCmdEdit = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 140, 300, 30, mainWindow, NULL, hInstance, NULL);
	openCmdButton = CreateWindow("button", "OK", WS_CHILD | BS_PUSHBUTTON, 450, 140, 100, 30, mainWindow, (HMENU)36, hInstance, NULL);
	openCmdTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 180, 700, 200, mainWindow, NULL, hInstance, NULL);

	//Controlled Active - widgets
	controlledActiveTitle = CreateWindow("static", "I want to be controlled (Active)", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	controlledActiveLabelPort = CreateWindow("static", "Port:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	controlledActiveEditPort = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 140, 300, 30, mainWindow, NULL, hInstance, NULL);
	controlledActiveButtonServer = CreateWindow("button", "Start", WS_CHILD | BS_PUSHBUTTON, 450, 140, 100, 30, mainWindow, (HMENU)37, hInstance, NULL);
	controlledActiveTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 180, 700, 200, mainWindow, NULL, hInstance, NULL);

	//Controller Active - widgets
	controllerActiveTitle = CreateWindow("static", "Control Device (Active)", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	controllerActiveLabelIP = CreateWindow("static", "IP:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	controllerActiveEditIP = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	controllerActiveLabelPort = CreateWindow("static", "Port:", WS_CHILD, 250, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	controllerActiveEditPort = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 320, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	controllerActiveButtonConnect = CreateWindow("button", "Connect", WS_CHILD | BS_PUSHBUTTON, 450, 140, 100, 30, mainWindow, (HMENU)38, hInstance, NULL);
	controllerActiveLabelCmd = CreateWindow("static", "Command:", WS_CHILD, 50, 180, 60, 30, mainWindow, NULL, hInstance, NULL);
	controllerActiveButtonCmd = CreateWindow("button", "OK", WS_CHILD | BS_PUSHBUTTON, 450, 180, 100, 30, mainWindow, (HMENU)39, hInstance, NULL);
	controllerActiveEditCmd = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 180, 300, 30, mainWindow, NULL, hInstance, NULL);
	controllerActiveTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 230, 900, 150, mainWindow, NULL, hInstance, NULL);

	//Controlled Passive - widgets
	controlledPassiveTitle = CreateWindow("static", "I want to be controlled (Passive)", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	controlledPassiveLabelIP = CreateWindow("static", "IP:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	controlledPassiveEditIP = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	controlledPassiveLabelPort = CreateWindow("static", "Port:", WS_CHILD, 250, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	controlledPassiveEditPort = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 320, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	controlledPassiveButtonConnect = CreateWindow("button", "Connect", WS_CHILD | BS_PUSHBUTTON, 450, 140, 100, 30, mainWindow, (HMENU)40, hInstance, NULL);
	controlledPassiveTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 230, 900, 150, mainWindow, NULL, hInstance, NULL);

	//Controller Passive - widgets
	controllerPassiveTitle = CreateWindow("static", "Control Device (Passive)", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	controllerPassiveLabelPort = CreateWindow("static", "Port:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	controllerPassiveEditPort = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 140, 300, 30, mainWindow, NULL, hInstance, NULL);
	controllerPassiveButtonServer = CreateWindow("button", "Start", WS_CHILD | BS_PUSHBUTTON, 450, 140, 100, 30, mainWindow, (HMENU)41, hInstance, NULL);
	controllerPassiveLabelCmd = CreateWindow("static", "Command:", WS_CHILD, 50, 180, 60, 30, mainWindow, NULL, hInstance, NULL);
	controllerPassiveEditCmd = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 180, 300, 30, mainWindow, NULL, hInstance, NULL);
	controllerPassiveButtonCmd = CreateWindow("button", "Send", WS_CHILD | BS_PUSHBUTTON, 450, 180, 100, 30, mainWindow, (HMENU)42, hInstance, NULL);
	controllerPassiveTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 220, 700, 200, mainWindow, NULL, hInstance, NULL);

	//finsh processes widgets
	endProcessTitle = CreateWindow("static", "End Local Process", WS_CHILD, 360, 100, 550, 30, mainWindow, NULL, hInstance, NULL);
	endProcessLabel = CreateWindow("static", "Name:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	endProcessEdit = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 130, 140, 300, 30, mainWindow, NULL, hInstance, NULL);
	endProcessButton = CreateWindow("button", "OK", WS_CHILD | BS_PUSHBUTTON, 450, 140, 100, 30, mainWindow, (HMENU)43, hInstance, NULL);
	endProcessTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 180, 700, 200, mainWindow, NULL, hInstance, NULL);

	//list process widgets
	listProcessTitle = CreateWindow("static", "List System Processes", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	listProcessTextData = CreateWindow("edit", NULL, WS_CHILD | WS_VSCROLL | WS_HSCROLL | WS_BORDER | ES_MULTILINE, 150, 250, 700, 150, mainWindow, NULL, hInstance, NULL);
	listProcessButton = CreateWindow("button", "List", BS_PUSHBUTTON | WS_CHILD, 425, 170, 80, 30, mainWindow, (HMENU)44, hInstance, NULL);

	//mysql widgets
	mysqlTitle = CreateWindow("static", "MySQL Database", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	mysqlLabelHost = CreateWindow("static", "IP:", WS_CHILD, 50, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	mysqlEditHost = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 120, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	mysqlLabelPort = CreateWindow("static", "Port:", WS_CHILD, 230, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	mysqlEditPort = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 300, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	mysqlButtonConnect = CreateWindow("button", "Connect", BS_PUSHBUTTON | WS_CHILD, 830, 140, 100, 30, mainWindow, (HMENU)45, hInstance, NULL);
	mysqlLabelCmd = CreateWindow("static", "Command:", WS_CHILD, 50, 180, 100, 30, mainWindow, NULL, hInstance, NULL);
	mysqlEditCmd = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 160, 180, 600, 30, mainWindow, NULL, hInstance, NULL);
	mysqlButtonCmd = CreateWindow("button", "Send", BS_PUSHBUTTON | WS_CHILD, 770, 180, 100, 30, mainWindow, (HMENU)46, hInstance, NULL);
	mysqlTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 220, 900, 170, mainWindow, NULL, hInstance, NULL);
	mysqlLabelUser = CreateWindow("static", "User:", WS_CHILD, 370, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	mysqlEditUser = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 480, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	mysqlLabelDb = CreateWindow("static", "Database:", WS_CHILD, 590, 140, 120, 30, mainWindow, NULL, hInstance, NULL);
	mysqlEditDb = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 720, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	mysqlLabelPass = CreateWindow("static", "Password:", WS_CHILD, 730, 100, 60, 30, mainWindow, NULL, hInstance, NULL);
	mysqlEditPass = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD | ES_PASSWORD, 800, 100, 100, 30, mainWindow, NULL, hInstance, NULL);
	mysqlButtonConsult = CreateWindow("button", "See Query", BS_PUSHBUTTON | WS_CHILD, 800, 70, 100, 20, mainWindow, (HMENU)47, hInstance, NULL);

	//chat widgets
	chatTitle = CreateWindow("static", "Fenix Chat", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	chatLbRbMode = CreateWindow("static", "Method:", WS_CHILD, 50, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	chatRbServer = CreateWindow("button", "Server", BS_AUTORADIOBUTTON | WS_CHILD, 160, 140, 100, 30, mainWindow, (HMENU)51, hInstance, NULL);
	chatRbClient = CreateWindow("button", "Client", BS_AUTORADIOBUTTON | WS_CHILD, 160, 160, 100, 30, mainWindow, (HMENU)52, hInstance, NULL);
	chatLbIp = CreateWindow("static", "IP:", WS_CHILD, 50, 230, 50, 30, mainWindow, NULL, hInstance, NULL);
	chatEditIp = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 110, 230, 120, 30, mainWindow, NULL, hInstance, NULL);
	chatLbPort = CreateWindow("static", "Port:", WS_CHILD, 240, 230, 60, 30, mainWindow, NULL, hInstance, NULL);
	chatEditPort = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 310, 230, 100, 30, mainWindow, NULL, hInstance, NULL);
	chatButtonConnect = CreateWindow("button", "Start", BS_PUSHBUTTON | WS_CHILD, 420, 230, 100, 30, mainWindow, (HMENU)49, hInstance, NULL);
	chatTextData = CreateWindow("edit", NULL, WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | WS_CHILD, 50, 270, 800, 100, mainWindow, NULL, hInstance, NULL);
	chatLbMessage = CreateWindow("static", "Message:", WS_CHILD, 50, 380, 100, 30, mainWindow, NULL, hInstance, NULL);
	chatEditMessage = CreateWindow("edit", NULL, WS_BORDER | WS_CHILD, 160, 380, 500, 30, mainWindow, NULL, hInstance, NULL);
	chatButtonMessage = CreateWindow("button", "Send", BS_PUSHBUTTON | WS_CHILD, 670, 380, 100, 30, mainWindow, (HMENU)50, hInstance, NULL);

	//hash widgets
	hashTitle = CreateWindow("static", "Hash Algorithm (Checksum)", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	hashLbFile = CreateWindow("static", "File:", WS_CHILD, 50, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	hashEditFile = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 160, 140, 500, 30, mainWindow, NULL, hInstance, NULL);
	hashButtonBrowse = CreateWindow("button", "Browse", WS_CHILD | BS_PUSHBUTTON, 670, 140, 100, 30, mainWindow, (HMENU)53, hInstance, NULL);
	hashTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 180, 700, 150, mainWindow, NULL, hInstance, NULL);
	hashButtonCalculate = CreateWindow("button", "Calculate", WS_CHILD | BS_PUSHBUTTON, 330, 340, 100, 30, mainWindow, (HMENU)54, hInstance, NULL);
	hashButtonSee = CreateWindow("button", "Result", WS_CHILD | BS_PUSHBUTTON, 440, 340, 100, 30, mainWindow, (HMENU)55, hInstance, NULL);

	//ftp widgets
	ftpTitle = CreateWindow("static", "FTP connection", WS_CHILD, 360, 100, 550, 150, mainWindow, NULL, hInstance, NULL);
	ftpLbIp = CreateWindow("static", "IP:", WS_CHILD, 50, 140, 50, 30, mainWindow, NULL, hInstance, NULL);
	ftpEditIp = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 110, 140, 120, 30, mainWindow, NULL, hInstance, NULL);
	ftpLbPort = CreateWindow("static", "Port:", WS_CHILD, 240, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	ftpEditPort = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 310, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	ftpLbUser = CreateWindow("static", "User:", WS_CHILD, 380, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	ftpEditUser = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 490, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	ftpLbPass = CreateWindow("static", "Password:", WS_CHILD, 600, 140, 60, 30, mainWindow, NULL, hInstance, NULL);
	ftpEditPass = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_PASSWORD, 670, 140, 100, 30, mainWindow, NULL, hInstance, NULL);
	ftpButtonConnect = CreateWindow("button", "Connect", WS_CHILD | BS_PUSHBUTTON, 780, 140, 100, 30, mainWindow, (HMENU)56, hInstance, NULL);
	ftpLbModeAccess = CreateWindow("static", "Access mode:", WS_CHILD, 50, 180, 120, 30, mainWindow, NULL, hInstance, NULL);
	ftpRbCredentials = CreateWindow("button", "By pass", WS_CHILD | BS_AUTORADIOBUTTON, 180, 180, 100, 30, mainWindow, (HMENU)59, hInstance, NULL);
	ftpRbAnonymous = CreateWindow("button", "Anonymous", WS_CHILD | BS_AUTORADIOBUTTON, 180, 200, 100, 30, mainWindow, (HMENU)60, hInstance, NULL);
	ftpLbDirectory = CreateWindow("static", "Directory:", WS_CHILD, 290, 180, 80, 30, mainWindow, NULL, hInstance, NULL);
	ftpEditDirectory = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 380, 180, 200, 30, mainWindow, NULL, hInstance, NULL);
	ftpButtonDirectory = CreateWindow("button", "Go", WS_CHILD | BS_PUSHBUTTON, 590, 180, 50, 30, mainWindow, (HMENU)57, hInstance, NULL);
	ftpButtonFree = CreateWindow("button", "Reset", WS_CHILD | BS_PUSHBUTTON, 650, 180, 60, 30, mainWindow, (HMENU)63, hInstance, NULL);
	ftpLbModeTransfer = CreateWindow("static", "Option:", WS_CHILD, 50, 220, 60, 30, mainWindow, NULL, hInstance, NULL);
	ftpRbPut = CreateWindow("button", "Transfer", WS_CHILD | BS_AUTORADIOBUTTON, 120, 220, 100, 30, mainWindow, (HMENU)61, hInstance, NULL);
	ftpRbGet = CreateWindow("button", "Receive", WS_CHILD | BS_AUTORADIOBUTTON, 120, 240, 100, 30, mainWindow, (HMENU)62, hInstance, NULL);
	ftpLbFile = CreateWindow("static", "File:", WS_CHILD, 230, 220, 100, 30, mainWindow, NULL, hInstance, NULL);
	ftpEditFile = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER, 340, 220, 400, 30, mainWindow, NULL, hInstance, NULL);
	ftpButtonOk = CreateWindow("button", "OK", WS_CHILD | BS_PUSHBUTTON, 750, 220, 50, 30, mainWindow, (HMENU)58, hInstance, NULL);
	ftpTextData = CreateWindow("edit", NULL, WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL, 50, 270, 900, 150, mainWindow, NULL, hInstance, NULL);



	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return msg.wParam;
}

//layout functions
void scanLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_SHOW);

	ShowWindow(rbSingleScan, SW_SHOW);
	ShowWindow(rbRangeScan, SW_SHOW);
	ShowWindow(editIP, SW_SHOW);
	ShowWindow(editPort, SW_SHOW);
	ShowWindow(labelIP, SW_SHOW);
	ShowWindow(labelPort, SW_SHOW);
	ShowWindow(buttonScan, SW_SHOW);
	ShowWindow(listScan, SW_SHOW);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);

	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);



}

void dnsLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_SHOW);
	ShowWindow(dnsTitle, SW_SHOW);
	ShowWindow(dnsCb, SW_SHOW);
	ShowWindow(dnsLabelInput, SW_SHOW);
	ShowWindow(dnsEditInput, SW_SHOW);
	ShowWindow(dnsButtonStart, SW_SHOW);
	ShowWindow(dnsTextData, SW_SHOW);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);

	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);




}

void sysInfoLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_SHOW);
	ShowWindow(sysConsultTextData, SW_SHOW);
	ShowWindow(sysConsultButton, SW_SHOW);
	ShowWindow(sysConsultButtonSave, SW_SHOW);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);

	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);



	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);





}

void editorLayout()
{

	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_SHOW);
	ShowWindow(editorTextData, SW_SHOW);
	ShowWindow(editorButtonSave, SW_SHOW);
	ShowWindow(editorButtonOpen, SW_SHOW);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);

	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);







}

void adapterLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_SHOW);
	ShowWindow(adapterTextData, SW_SHOW);
	ShowWindow(adapterButton, SW_SHOW);

	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);





}

void fileInfoLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_SHOW);
	ShowWindow(readBinaryButtonConsult, SW_SHOW);
	ShowWindow(readBinaryButtonOpen, SW_SHOW);
	ShowWindow(readBinaryTextData, SW_SHOW);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_SHOW);
	ShowWindow(fileInfoTextData, SW_SHOW);
	ShowWindow(fileInfoButtonConsult, SW_SHOW);
	ShowWindow(fileInfoButtonOpen, SW_SHOW);







}

void readBinaryLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_SHOW);
	ShowWindow(readBinaryButtonConsult, SW_SHOW);
	ShowWindow(readBinaryButtonOpen, SW_SHOW);
	ShowWindow(readBinaryTextData, SW_SHOW);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);




}

void fileTransferLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_SHOW);
	ShowWindow(fileTransferRbTransfer, SW_SHOW);
	ShowWindow(fileTransferRbReceive, SW_SHOW);
	ShowWindow(fileTransferEditIP, SW_SHOW);
	ShowWindow(fileTransferEditPort, SW_SHOW);
	ShowWindow(fileTransferLabelIP, SW_SHOW);
	ShowWindow(fileTransferLabelPort, SW_SHOW);
	ShowWindow(fileTransferButtonOpen, SW_SHOW);
	ShowWindow(fileTransferButtonStart, SW_SHOW);
	ShowWindow(fileTransferTextData, SW_SHOW);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);




}

void fileListLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_SHOW);
	ShowWindow(listFileLabelPath, SW_SHOW);
	ShowWindow(listFileEditPath, SW_SHOW);
	ShowWindow(listFileButtonSearch, SW_SHOW);
	ShowWindow(listFileButtonStart, SW_SHOW);
	ShowWindow(listFileTextData, SW_SHOW);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);




}

void whoisLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_SHOW);
	ShowWindow(whoisLabel, SW_SHOW);
	ShowWindow(whoisEdit, SW_SHOW);
	ShowWindow(whoisButton, SW_SHOW);
	ShowWindow(whoisTextData, SW_SHOW);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void smbLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_SHOW);
	ShowWindow(smbButtonHost, SW_SHOW);
	ShowWindow(smbButtonPath, SW_SHOW);
	ShowWindow(smbButtonUpload, SW_SHOW);
	ShowWindow(smbEditHost, SW_SHOW);
	ShowWindow(smbEditPath, SW_SHOW);
	ShowWindow(smbLabelHost, SW_SHOW);
	ShowWindow(smbLabelPath, SW_SHOW);
	ShowWindow(smbRbDownload, SW_SHOW);
	ShowWindow(smbRbUpload, SW_SHOW);
	ShowWindow(smbTextData, SW_SHOW);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void fileTransferUdpLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_SHOW);
	ShowWindow(fileTransferRbTransferUdp, SW_SHOW);
	ShowWindow(fileTransferRbReceiveUdp, SW_SHOW);
	ShowWindow(fileTransferEditIPUdp, SW_SHOW);
	ShowWindow(fileTransferEditPortUdp, SW_SHOW);
	ShowWindow(fileTransferLabelIPUdp, SW_SHOW);
	ShowWindow(fileTransferLabelPortUdp, SW_SHOW);
	ShowWindow(fileTransferButtonOpenUdp, SW_SHOW);
	ShowWindow(fileTransferButtonStartUdp, SW_SHOW);
	ShowWindow(fileTransferTextDataUdp, SW_SHOW);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);






}

void openCmdLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_SHOW);
	ShowWindow(openCmdLabel, SW_SHOW);
	ShowWindow(openCmdEdit, SW_SHOW);
	ShowWindow(openCmdButton, SW_SHOW);
	ShowWindow(openCmdTextData, SW_SHOW);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void controlledActiveLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_SHOW);
	ShowWindow(controlledActiveLabelPort, SW_SHOW);
	ShowWindow(controlledActiveEditPort, SW_SHOW);
	ShowWindow(controlledActiveButtonServer, SW_SHOW);
	ShowWindow(controlledActiveTextData, SW_SHOW);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);







}

void controllerActiveLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_SHOW);
	ShowWindow(controllerActiveTextData, SW_SHOW);
	ShowWindow(controllerActiveLabelIP, SW_SHOW);
	ShowWindow(controllerActiveEditIP, SW_SHOW);
	ShowWindow(controllerActiveButtonConnect, SW_SHOW);
	ShowWindow(controllerActiveLabelPort, SW_SHOW);
	ShowWindow(controllerActiveEditPort, SW_SHOW);
	ShowWindow(controllerActiveLabelCmd, SW_SHOW);
	ShowWindow(controllerActiveEditCmd, SW_SHOW);
	ShowWindow(controllerActiveButtonCmd, SW_SHOW);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void controlledPassiveLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_SHOW);
	ShowWindow(controlledPassiveTextData, SW_SHOW);
	ShowWindow(controlledPassiveLabelIP, SW_SHOW);
	ShowWindow(controlledPassiveEditIP, SW_SHOW);
	ShowWindow(controlledPassiveButtonConnect, SW_SHOW);
	ShowWindow(controlledPassiveLabelPort, SW_SHOW);
	ShowWindow(controlledPassiveEditPort, SW_SHOW);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void controllerPassiveLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_SHOW);
	ShowWindow(controllerPassiveLabelPort, SW_SHOW);
	ShowWindow(controllerPassiveEditPort, SW_SHOW);
	ShowWindow(controllerPassiveButtonServer, SW_SHOW);
	ShowWindow(controllerPassiveTextData, SW_SHOW);
	ShowWindow(controllerPassiveLabelCmd, SW_SHOW);
	ShowWindow(controllerPassiveEditCmd, SW_SHOW);
	ShowWindow(controllerPassiveButtonCmd, SW_SHOW);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);




}

void endProcessLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_SHOW);
	ShowWindow(endProcessLabel, SW_SHOW);
	ShowWindow(endProcessEdit, SW_SHOW);
	ShowWindow(endProcessButton, SW_SHOW);
	ShowWindow(endProcessTextData, SW_SHOW);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void listProcessLayout()
{
	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_SHOW);
	ShowWindow(listProcessButton, SW_SHOW);
	ShowWindow(listProcessTextData, SW_SHOW);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void mysqlLayout()
{
	ShowWindow(mysqlTitle, SW_SHOW);
	ShowWindow(mysqlLabelHost, SW_SHOW);
	ShowWindow(mysqlEditHost, SW_SHOW);
	ShowWindow(mysqlLabelPort, SW_SHOW);
	ShowWindow(mysqlEditPort, SW_SHOW);
	ShowWindow(mysqlButtonConnect, SW_SHOW);
	ShowWindow(mysqlLabelCmd, SW_SHOW);
	ShowWindow(mysqlEditCmd, SW_SHOW);
	ShowWindow(mysqlButtonCmd, SW_SHOW);
	ShowWindow(mysqlTextData, SW_SHOW);
	ShowWindow(mysqlLabelUser, SW_SHOW);
	ShowWindow(mysqlEditUser, SW_SHOW);
	ShowWindow(mysqlLabelDb, SW_SHOW);
	ShowWindow(mysqlEditDb, SW_SHOW);
	ShowWindow(mysqlLabelPass, SW_SHOW);
	ShowWindow(mysqlEditPass, SW_SHOW);
	ShowWindow(mysqlButtonConsult, SW_SHOW);

	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);




	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);






}

void chatLayout()
{
	ShowWindow(chatTitle, SW_SHOW);
	ShowWindow(chatLbRbMode, SW_SHOW);
	ShowWindow(chatRbServer, SW_SHOW);
	ShowWindow(chatRbClient, SW_SHOW);
	ShowWindow(chatLbIp, SW_SHOW);
	ShowWindow(chatEditIp, SW_SHOW);
	ShowWindow(chatLbPort, SW_SHOW);
	ShowWindow(chatEditPort, SW_SHOW);
	ShowWindow(chatButtonConnect, SW_SHOW);
	ShowWindow(chatTextData, SW_SHOW);
	ShowWindow(chatLbMessage, SW_SHOW);
	ShowWindow(chatEditMessage, SW_SHOW);
	ShowWindow(chatButtonMessage, SW_SHOW);

	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);



	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);


	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);



}

void hashLayout()
{
	//main
	ShowWindow(hashTitle, SW_SHOW);
	ShowWindow(hashLbFile, SW_SHOW);
	ShowWindow(hashEditFile, SW_SHOW);
	ShowWindow(hashButtonBrowse, SW_SHOW);
	ShowWindow(hashTextData, SW_SHOW);
	ShowWindow(hashButtonCalculate, SW_SHOW);
	ShowWindow(hashButtonSee, SW_SHOW);

	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);



	//ftp
	ShowWindow(ftpTitle, SW_HIDE);
	ShowWindow(ftpLbIp, SW_HIDE);
	ShowWindow(ftpEditIp, SW_HIDE);
	ShowWindow(ftpLbPort, SW_HIDE);
	ShowWindow(ftpEditPort, SW_HIDE);
	ShowWindow(ftpLbUser, SW_HIDE);
	ShowWindow(ftpEditUser, SW_HIDE);
	ShowWindow(ftpLbPass, SW_HIDE);
	ShowWindow(ftpEditPass, SW_HIDE);
	ShowWindow(ftpButtonConnect, SW_HIDE);
	ShowWindow(ftpLbModeAccess, SW_HIDE);
	ShowWindow(ftpRbCredentials, SW_HIDE);
	ShowWindow(ftpRbAnonymous, SW_HIDE);
	ShowWindow(ftpLbDirectory, SW_HIDE);
	ShowWindow(ftpEditDirectory, SW_HIDE);
	ShowWindow(ftpButtonDirectory, SW_HIDE);
	ShowWindow(ftpLbModeTransfer, SW_HIDE);
	ShowWindow(ftpRbPut, SW_HIDE);
	ShowWindow(ftpRbGet, SW_HIDE);
	ShowWindow(ftpLbFile, SW_HIDE);
	ShowWindow(ftpEditFile, SW_HIDE);
	ShowWindow(ftpButtonOk, SW_HIDE);
	ShowWindow(ftpTextData, SW_HIDE);
	ShowWindow(ftpButtonFree, SW_HIDE);

	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);





}

void ftpLayout()
{
	//main
	ShowWindow(ftpTitle, SW_SHOW);
	ShowWindow(ftpLbIp, SW_SHOW);
	ShowWindow(ftpEditIp, SW_SHOW);
	ShowWindow(ftpLbPort, SW_SHOW);
	ShowWindow(ftpEditPort, SW_SHOW);
	ShowWindow(ftpLbUser, SW_SHOW);
	ShowWindow(ftpEditUser, SW_SHOW);
	ShowWindow(ftpLbPass, SW_SHOW);
	ShowWindow(ftpEditPass, SW_SHOW);
	ShowWindow(ftpButtonConnect, SW_SHOW);
	ShowWindow(ftpLbModeAccess, SW_SHOW);
	ShowWindow(ftpRbCredentials, SW_SHOW);
	ShowWindow(ftpRbAnonymous, SW_SHOW);
	ShowWindow(ftpLbDirectory, SW_SHOW);
	ShowWindow(ftpEditDirectory, SW_SHOW);
	ShowWindow(ftpButtonDirectory, SW_SHOW);
	ShowWindow(ftpLbModeTransfer, SW_SHOW);
	ShowWindow(ftpRbPut, SW_SHOW);
	ShowWindow(ftpRbGet, SW_SHOW);
	ShowWindow(ftpLbFile, SW_SHOW);
	ShowWindow(ftpEditFile, SW_SHOW);
	ShowWindow(ftpButtonOk, SW_SHOW);
	ShowWindow(ftpTextData, SW_SHOW);
	ShowWindow(ftpButtonFree, SW_SHOW);

	//singlescan
	ShowWindow(mainOption, SW_HIDE);

	ShowWindow(rbSingleScan, SW_HIDE);
	ShowWindow(rbRangeScan, SW_HIDE);
	ShowWindow(editIP, SW_HIDE);
	ShowWindow(editPort, SW_HIDE);
	ShowWindow(labelIP, SW_HIDE);
	ShowWindow(labelPort, SW_HIDE);
	ShowWindow(buttonScan, SW_HIDE);
	ShowWindow(listScan, SW_HIDE);

	//dns
	ShowWindow(mainOption, SW_HIDE);
	ShowWindow(dnsTitle, SW_HIDE);
	ShowWindow(dnsCb, SW_HIDE);
	ShowWindow(dnsLabelInput, SW_HIDE);
	ShowWindow(dnsEditInput, SW_HIDE);
	ShowWindow(dnsButtonStart, SW_HIDE);
	ShowWindow(dnsTextData, SW_HIDE);


	//sys info
	ShowWindow(sysConsultTitle, SW_HIDE);
	ShowWindow(sysConsultTextData, SW_HIDE);
	ShowWindow(sysConsultButton, SW_HIDE);
	ShowWindow(sysConsultButtonSave, SW_HIDE);


	//editor 
	ShowWindow(editorTitle, SW_HIDE);
	ShowWindow(editorTextData, SW_HIDE);
	ShowWindow(editorButtonSave, SW_HIDE);
	ShowWindow(editorButtonOpen, SW_HIDE);

	//adapter
	ShowWindow(adapterTitle, SW_HIDE);
	ShowWindow(adapterTextData, SW_HIDE);
	ShowWindow(adapterButton, SW_HIDE);


	//read binary
	ShowWindow(readBinaryTitle, SW_HIDE);
	ShowWindow(readBinaryButtonConsult, SW_HIDE);
	ShowWindow(readBinaryButtonOpen, SW_HIDE);
	ShowWindow(readBinaryTextData, SW_HIDE);


	//file transfer
	ShowWindow(fileTransferTitle, SW_HIDE);
	ShowWindow(fileTransferRbTransfer, SW_HIDE);
	ShowWindow(fileTransferRbReceive, SW_HIDE);
	ShowWindow(fileTransferEditIP, SW_HIDE);
	ShowWindow(fileTransferEditPort, SW_HIDE);
	ShowWindow(fileTransferLabelIP, SW_HIDE);
	ShowWindow(fileTransferLabelPort, SW_HIDE);
	ShowWindow(fileTransferButtonOpen, SW_HIDE);
	ShowWindow(fileTransferButtonStart, SW_HIDE);
	ShowWindow(fileTransferTextData, SW_HIDE);

	//file list
	ShowWindow(listFileTitle, SW_HIDE);
	ShowWindow(listFileLabelPath, SW_HIDE);
	ShowWindow(listFileEditPath, SW_HIDE);
	ShowWindow(listFileButtonSearch, SW_HIDE);
	ShowWindow(listFileButtonStart, SW_HIDE);
	ShowWindow(listFileTextData, SW_HIDE);

	//whois
	ShowWindow(whoisTitle, SW_HIDE);
	ShowWindow(whoisLabel, SW_HIDE);
	ShowWindow(whoisEdit, SW_HIDE);
	ShowWindow(whoisButton, SW_HIDE);
	ShowWindow(whoisTextData, SW_HIDE);


	//sbm
	ShowWindow(smbTitle, SW_HIDE);
	ShowWindow(smbButtonHost, SW_HIDE);
	ShowWindow(smbButtonPath, SW_HIDE);
	ShowWindow(smbButtonUpload, SW_HIDE);
	ShowWindow(smbEditHost, SW_HIDE);
	ShowWindow(smbEditPath, SW_HIDE);
	ShowWindow(smbLabelHost, SW_HIDE);
	ShowWindow(smbLabelPath, SW_HIDE);
	ShowWindow(smbRbDownload, SW_HIDE);
	ShowWindow(smbRbUpload, SW_HIDE);
	ShowWindow(smbTextData, SW_HIDE);


	//file transfer udp
	ShowWindow(fileTransferTitleUdp, SW_HIDE);
	ShowWindow(fileTransferRbTransferUdp, SW_HIDE);
	ShowWindow(fileTransferRbReceiveUdp, SW_HIDE);
	ShowWindow(fileTransferEditIPUdp, SW_HIDE);
	ShowWindow(fileTransferEditPortUdp, SW_HIDE);
	ShowWindow(fileTransferLabelIPUdp, SW_HIDE);
	ShowWindow(fileTransferLabelPortUdp, SW_HIDE);
	ShowWindow(fileTransferButtonOpenUdp, SW_HIDE);
	ShowWindow(fileTransferButtonStartUdp, SW_HIDE);
	ShowWindow(fileTransferTextDataUdp, SW_HIDE);


	//open cmd
	ShowWindow(openCmdTitle, SW_HIDE);
	ShowWindow(openCmdLabel, SW_HIDE);
	ShowWindow(openCmdEdit, SW_HIDE);
	ShowWindow(openCmdButton, SW_HIDE);
	ShowWindow(openCmdTextData, SW_HIDE);


	//controlled active
	ShowWindow(controlledActiveTitle, SW_HIDE);
	ShowWindow(controlledActiveLabelPort, SW_HIDE);
	ShowWindow(controlledActiveEditPort, SW_HIDE);
	ShowWindow(controlledActiveButtonServer, SW_HIDE);
	ShowWindow(controlledActiveTextData, SW_HIDE);


	//controller active
	ShowWindow(controllerActiveTitle, SW_HIDE);
	ShowWindow(controllerActiveTextData, SW_HIDE);
	ShowWindow(controllerActiveLabelIP, SW_HIDE);
	ShowWindow(controllerActiveEditIP, SW_HIDE);
	ShowWindow(controllerActiveButtonConnect, SW_HIDE);
	ShowWindow(controllerActiveLabelPort, SW_HIDE);
	ShowWindow(controllerActiveEditPort, SW_HIDE);
	ShowWindow(controllerActiveLabelCmd, SW_HIDE);
	ShowWindow(controllerActiveEditCmd, SW_HIDE);
	ShowWindow(controllerActiveButtonCmd, SW_HIDE);

	//main
	ShowWindow(controlledPassiveTitle, SW_HIDE);
	ShowWindow(controlledPassiveTextData, SW_HIDE);
	ShowWindow(controlledPassiveLabelIP, SW_HIDE);
	ShowWindow(controlledPassiveEditIP, SW_HIDE);
	ShowWindow(controlledPassiveButtonConnect, SW_HIDE);
	ShowWindow(controlledPassiveLabelPort, SW_HIDE);
	ShowWindow(controlledPassiveEditPort, SW_HIDE);


	//controller passive
	ShowWindow(controllerPassiveTitle, SW_HIDE);
	ShowWindow(controllerPassiveLabelPort, SW_HIDE);
	ShowWindow(controllerPassiveEditPort, SW_HIDE);
	ShowWindow(controllerPassiveButtonServer, SW_HIDE);
	ShowWindow(controllerPassiveTextData, SW_HIDE);
	ShowWindow(controllerPassiveLabelCmd, SW_HIDE);
	ShowWindow(controllerPassiveEditCmd, SW_HIDE);
	ShowWindow(controllerPassiveButtonCmd, SW_HIDE);

	//end process
	ShowWindow(endProcessTitle, SW_HIDE);
	ShowWindow(endProcessLabel, SW_HIDE);
	ShowWindow(endProcessEdit, SW_HIDE);
	ShowWindow(endProcessButton, SW_HIDE);
	ShowWindow(endProcessTextData, SW_HIDE);


	//list process
	ShowWindow(listProcessTitle, SW_HIDE);
	ShowWindow(listProcessButton, SW_HIDE);
	ShowWindow(listProcessTextData, SW_HIDE);


	//mysql
	ShowWindow(mysqlTitle, SW_HIDE);
	ShowWindow(mysqlLabelHost, SW_HIDE);
	ShowWindow(mysqlEditHost, SW_HIDE);
	ShowWindow(mysqlLabelPort, SW_HIDE);
	ShowWindow(mysqlEditPort, SW_HIDE);
	ShowWindow(mysqlButtonConnect, SW_HIDE);
	ShowWindow(mysqlLabelCmd, SW_HIDE);
	ShowWindow(mysqlEditCmd, SW_HIDE);
	ShowWindow(mysqlButtonCmd, SW_HIDE);
	ShowWindow(mysqlTextData, SW_HIDE);
	ShowWindow(mysqlLabelUser, SW_HIDE);
	ShowWindow(mysqlEditUser, SW_HIDE);
	ShowWindow(mysqlLabelDb, SW_HIDE);
	ShowWindow(mysqlEditDb, SW_HIDE);
	ShowWindow(mysqlLabelPass, SW_HIDE);
	ShowWindow(mysqlEditPass, SW_HIDE);
	ShowWindow(mysqlButtonConsult, SW_HIDE);


	//chat 
	ShowWindow(chatTitle, SW_HIDE);
	ShowWindow(chatLbRbMode, SW_HIDE);
	ShowWindow(chatRbServer, SW_HIDE);
	ShowWindow(chatRbClient, SW_HIDE);
	ShowWindow(chatLbIp, SW_HIDE);
	ShowWindow(chatEditIp, SW_HIDE);
	ShowWindow(chatLbPort, SW_HIDE);
	ShowWindow(chatEditPort, SW_HIDE);
	ShowWindow(chatButtonConnect, SW_HIDE);
	ShowWindow(chatTextData, SW_HIDE);
	ShowWindow(chatLbMessage, SW_HIDE);
	ShowWindow(chatEditMessage, SW_HIDE);
	ShowWindow(chatButtonMessage, SW_HIDE);


	//hash
	ShowWindow(hashTitle, SW_HIDE);
	ShowWindow(hashLbFile, SW_HIDE);
	ShowWindow(hashEditFile, SW_HIDE);
	ShowWindow(hashButtonBrowse, SW_HIDE);
	ShowWindow(hashTextData, SW_HIDE);
	ShowWindow(hashButtonCalculate, SW_HIDE);
	ShowWindow(hashButtonSee, SW_HIDE);




	//file info
	//file info
	ShowWindow(fileInfoTitle, SW_HIDE);
	ShowWindow(fileInfoTextData, SW_HIDE);
	ShowWindow(fileInfoButtonConsult, SW_HIDE);
	ShowWindow(fileInfoButtonOpen, SW_HIDE);

}

