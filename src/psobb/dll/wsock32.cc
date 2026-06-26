#include <console.hh>
#include <settings/settings.hh>

#include <MinHook.h>

#include "wsock32.hh"

using namespace AzureFlare;

FARPROC __WSAFDIsSet;
FARPROC closesocket;
FARPROC connect;
FARPROC gethostbyaddr;
FARPROC getsockopt;
FARPROC htons;
FARPROC inet_addr;
FARPROC ntohs;
FARPROC recv;
FARPROC recvfrom;
FARPROC select;
FARPROC send;
FARPROC sendto;
FARPROC setsockopt;
FARPROC shutdown;
FARPROC socket;
FARPROC WSACleanup;
FARPROC WSAGetLastError;
FARPROC WSAStartup;

extern "C" NAKED void ___WSAFDIsSet() { jmp(__WSAFDIsSet); }
extern "C" NAKED void _closesocket()  { jmp(closesocket); }
extern "C" NAKED void _connect()  { jmp(connect); }
extern "C" NAKED void _gethostbyaddr()  { jmp(gethostbyaddr); }
extern "C" NAKED void _getsockopt()  { jmp(getsockopt); }
extern "C" NAKED void _htons()  { jmp(htons); }
extern "C" NAKED void _inet_addr()  { jmp(inet_addr); }
extern "C" NAKED void _ntohs()  { jmp(ntohs); }
extern "C" NAKED void _recv()  { jmp(recv); }
extern "C" NAKED void _recvfrom()  { jmp(recvfrom); }
extern "C" NAKED void _select()  { jmp(select); }
extern "C" NAKED void _send()  { jmp(send); }
extern "C" NAKED void _sendto()  { jmp(sendto); }
extern "C" NAKED void _setsockopt()  { jmp(setsockopt); }
extern "C" NAKED void _shutdown()  { jmp(shutdown); }
extern "C" NAKED void _socket()  { jmp(socket); }
extern "C" NAKED void _WSACleanup()  { jmp(WSACleanup); }
extern "C" NAKED void _WSAGetLastError()  { jmp(WSAGetLastError); }
extern "C" NAKED void _WSAStartup()  { jmp(WSAStartup); }

typedef struct hostent* (WINAPI* OriginalGetHostByName)(const char*);
OriginalGetHostByName pOriginalGetHostByName = nullptr;

void HookLibraryFunctions()
{
    __WSAFDIsSet = GetProcAddress(hDll, "__WSAFDIsSet");
    closesocket = GetProcAddress(hDll, "closesocket");
    connect = GetProcAddress(hDll, "connect");
    gethostbyaddr = GetProcAddress(hDll, "gethostbyaddr");
    getsockopt = GetProcAddress(hDll, "getsockopt");
    htons = GetProcAddress(hDll, "htons");
    inet_addr = GetProcAddress(hDll, "inet_addr");
    ntohs = GetProcAddress(hDll, "ntohs");
    recv = GetProcAddress(hDll, "recv");
    recvfrom = GetProcAddress(hDll, "recvfrom");
    select = GetProcAddress(hDll, "select");
    send = GetProcAddress(hDll, "send");
    sendto = GetProcAddress(hDll, "sendto");
    setsockopt = GetProcAddress(hDll, "setsockopt");
    shutdown = GetProcAddress(hDll, "shutdown");
    socket = GetProcAddress(hDll, "socket");
    WSACleanup = GetProcAddress(hDll, "WSACleanup");
    WSAGetLastError = GetProcAddress(hDll, "WSAGetLastError");
    WSAStartup = GetProcAddress(hDll, "WSAStartup");

    // Load the gethostbyname function separately
	pOriginalGetHostByName = reinterpret_cast<OriginalGetHostByName>(GetProcAddress(hDll, "gethostbyname"));
}

#define REPLACE_SERVER_URL(outBuffer, passedValue, origAddr, newAddr, comment) \
if (newAddr == NULL) \
{ \
    PRINT_DEBUG_N("New hostname for %s is null, using %s", comment, passedValue); \
    strncpy(outBuffer, passedValue, sizeof(outBuffer) - 1); \
    outBuffer[sizeof(outBuffer) - 1] = '\0'; \
} \
else if (strcmp(passedValue, origAddr) == 0) \
{ \
    strncpy(outBuffer, newAddr, sizeof(outBuffer) - 1); \
    outBuffer[sizeof(outBuffer) - 1] = '\0'; \
}

extern "C" hostent* __stdcall _gethostbyname(const char* name)
{
    if (!Settings::EnableServerRedirection) return pOriginalGetHostByName(name);

	char newHostname[256] = "";

	// US Servers
	REPLACE_SERVER_URL(newHostname, name, "patch01.us.segaonline.jp", Settings::GameUrls.USAServerUrls.PatchServerUrl.c_str(), "US Patch Server");
	REPLACE_SERVER_URL(newHostname, name, "game01.us.segaonline.jp", Settings::GameUrls.USAServerUrls.GameServerUrl.c_str(), "US Game Server");

	// JP Servers
	REPLACE_SERVER_URL(newHostname, name, "patch01.psobb.segaonline.jp", Settings::GameUrls.JPServerUrls.PatchServerUrl.c_str(), "JP Patch Server");
	REPLACE_SERVER_URL(newHostname, name, "game01.psobb.segaonline.jp", Settings::GameUrls.JPServerUrls.GameServerUrl.c_str(), "JP Game Server");

	// Episode 4 Servers
	REPLACE_SERVER_URL(newHostname, name, "psobb-ep4-patch.segaonline.jp", Settings::GameUrls.EP4ServerUrls.PatchServerUrl.c_str(), "Ep4 Patch Server");
	REPLACE_SERVER_URL(newHostname, name, "psobb-ep4-db.segaonline.jp", Settings::GameUrls.EP4ServerUrls.GameServerUrl.c_str(), "Ep4 Game Server");

	// CN Servers
	REPLACE_SERVER_URL(newHostname, name, "patch.psobb.cn", Settings::GameUrls.CNServerUrls.PatchServerUrl.c_str(), "CN Patch Server");
	REPLACE_SERVER_URL(newHostname, name, "db.psobb.cn", Settings::GameUrls.CNServerUrls.GameServerUrl.c_str(), "CN Game Server");

	PRINT_DEBUG_N("Hostname: %s => %s", name, newHostname);

	return pOriginalGetHostByName(newHostname);
}

struct sockaddr_in_redirect {
    short          sin_family;
    unsigned short sin_port;
    unsigned long  sin_addr;
    char           sin_zero[8];
};

#define AF_INET_REDIRECT 2

static const unsigned long g_KnownServerIPs[] = {
    0x72C8AC3D,  // 61.172.200.114  (CN game server)
    0x73C8AC3D,  // 61.172.200.115  (CN patch server)
    0xE02919DA,  // 218.25.41.224   (CN patch server)
    0x23EF973D,  // 61.151.239.35   (CN patch server)
    0xB1F888DB,  // 219.136.248.177 (CN patch server)
    0xE46742DA,  // 218.66.103.228  (CN patch server)
    0x06AB59DA,  // 218.89.171.6    (CN patch server)
};

typedef int (WINAPI* OriginalConnect)(int, const void*, int);
static OriginalConnect pRealConnect = nullptr;

extern "C" int WINAPI DetourConnect(int s, const void* name, int namelen)
{
    if (!pRealConnect) return -1;
    if (!Settings::EnableServerRedirection || !name || namelen < (int)sizeof(sockaddr_in_redirect))
        return pRealConnect(s, name, namelen);

    const sockaddr_in_redirect* addr = (const sockaddr_in_redirect*)name;
    if (addr->sin_family != AF_INET_REDIRECT)
        return pRealConnect(s, name, namelen);

    unsigned long dest_ip = addr->sin_addr;
    bool matched = false;
    for (int i = 0; i < 7; i++) {
        if (dest_ip == g_KnownServerIPs[i]) {
            matched = true;
            break;
        }
    }
    if (!matched)
        return pRealConnect(s, name, namelen);

    // Resolve redirect IP from config lazily
    static unsigned long redirect_ip = 0;
    if (redirect_ip == 0) {
        typedef unsigned long (WINAPI* InetAddrFn)(const char*);
        InetAddrFn pInetAddr = (InetAddrFn)inet_addr;
        redirect_ip = pInetAddr(Settings::GameUrls.CNServerUrls.GameServerUrl.c_str());
        if (redirect_ip == 0 || redirect_ip == 0xFFFFFFFF) {
            redirect_ip = pInetAddr(Settings::GameUrls.CNServerUrls.PatchServerUrl.c_str());
        }
    }
    if (redirect_ip == 0 || redirect_ip == 0xFFFFFFFF) {
        PRINT_DEBUG_N("Connect redirect: no valid server IP, passing through");
        return pRealConnect(s, name, namelen);
    }

    sockaddr_in_redirect redirect_addr = *addr;
    redirect_addr.sin_addr = redirect_ip;

    unsigned short port = (addr->sin_port >> 8) | (addr->sin_port << 8);
    PRINT_DEBUG_N("Connect redirect: %d.%d.%d.%d -> %d.%d.%d.%d (port %d)",
        (unsigned char)(dest_ip >> 0), (unsigned char)(dest_ip >> 8),
        (unsigned char)(dest_ip >> 16), (unsigned char)(dest_ip >> 24),
        (unsigned char)(redirect_ip >> 0), (unsigned char)(redirect_ip >> 8),
        (unsigned char)(redirect_ip >> 16), (unsigned char)(redirect_ip >> 24),
        port);

    return pRealConnect(s, &redirect_addr, namelen);
}

void InstallConnectHook()
{
    void* pRealConn = (void*)GetProcAddress(hDll, "connect");
    if (!pRealConn) return;

    MH_STATUS rc = MH_Initialize();
    if (rc != MH_OK && rc != MH_ERROR_ALREADY_INITIALIZED) return;

    void* pTrampoline = nullptr;
    rc = MH_CreateHook(pRealConn, (LPVOID)DetourConnect, &pTrampoline);
    if (rc != MH_OK) {
        PRINT_DEBUG_N("Connect hook: MH_CreateHook failed: %d", (int)rc);
    } else {
        pRealConnect = (OriginalConnect)pTrampoline;
        MH_EnableHook(pRealConn);
        PRINT_DEBUG_N("Connect hook: installed successfully");
    }
}