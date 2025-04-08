// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2025 HighKali (DogeCore Protocol)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net.h"

#include "addrman.h"
#include "chainparams.h"
#include "clientversion.h"
#include "consensus/consensus.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "netbase.h"
#include "primitives/block.h"
#include "protocol.h"
#include "random.h"
#include "sync.h"
#include "timedata.h"
#include "tinyformat.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include <algorithm>
#include <atomic>
#include <deque>
#include <memory>
#include <thread>
#include <unordered_set>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

static const int64_t DEFAULT_CONNECT_TIMEOUT = 5000;
static const int DEFAULT_MAX_CONNECTIONS = 125;
static const int DEFAULT_UPNP = 1;

std::atomic<bool> fNetworkActive(true);

// Dichiarazioni globali richieste
ArgsManager gArgs;
CCriticalSection cs_vNodes;
CCriticalSection cs_mapInboundConnectionTracker;
CCriticalSection cs_semOutbound;
std::unique_ptr<CAddrMan> addrman;

CConnman::CConnman(uint64_t nSeed0In, uint64_t nSeed1In)
    : nSeed0(nSeed0In), nSeed1(nSeed1In), semOutbound(DEFAULT_MAX_CONNECTIONS) {
    setBannedIsDirty = false;
    fAddressesInitialized = false;
}

CConnman::~CConnman() {
    Interrupt();
    Stop();
}

void CConnman::Interrupt() {
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes) {
            pnode->fDisconnect = true;
        }
    }
}

void CConnman::Stop() {
    threadGroup.interrupt_all();
    threadGroup.join_all();

    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes) {
            delete pnode;
        }
        vNodes.clear();
    }
}

bool CConnman::BindListenPort(const CService& addrBind, std::string& strError, bool fWhitelisted) {
    strError = "";
    int nOne = 1;

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        strError = strprintf("Socket creation failed: %s", strerror(errno));
        return false;
    }

#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&nOne, sizeof(int));

    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = addrBind.GetInAddr();
    sockaddr.sin_port = htons(addrBind.GetPort());

    if (::bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) {
        strError = strprintf("Bind failed: %s", strerror(errno));
        close(sockfd);
        return false;
    }

    if (listen(sockfd, SOMAXCONN) == -1) {
        strError = strprintf("Listen failed: %s", strerror(errno));
        close(sockfd);
        return false;
    }

    close(sockfd); // Semplificato per ora
    return true;
}

void CConnman::ThreadSocketHandler() {
    while (!threadGroup.interrupted()) {
        std::vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            for (CNode* pnode : vNodesCopy) {
                pnode->AddRef();
            }
        }

        for (CNode* pnode : vNodesCopy) {
            if (pnode->fDisconnect) {
                {
                    LOCK(cs_vNodes);
                    vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());
                }
                delete pnode;
                continue;
            }
        }

        for (CNode* pnode : vNodesCopy) {
            pnode->Release();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void CConnman::ThreadDNSAddressSeed() {
    if (!gArgs.GetBoolArg("-dnsseed", true)) {
        return;
    }

    const std::vector<CDNSSeedData>& vSeeds = Params().DNSSeeds();
    for (const CDNSSeedData& seed : vSeeds) {
        std::vector<CNetAddr> vIPs;
        LookupHost(seed.host.c_str(), vIPs, 0, true);
        for (const CNetAddr& ip : vIPs) {
            addrman->Add(CAddress(ip, NODE_NETWORK), CNetAddr());
        }
    }
}

void CConnman::ThreadMapPort() {
    if (!gArgs.GetBoolArg("-upnp", DEFAULT_UPNP)) {
        return;
    }

    struct UPNPDev* devlist = nullptr;
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[64];

#ifndef UPNPDISCOVER_SUCCESS
    devlist = upnpDiscover(2000, nullptr, nullptr, 0); // Vecchia versione
#else
    devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, nullptr); // Nuova versione
#endif

    if (!devlist) {
        LogPrintf("UPnP: No devices discovered\n");
        return;
    }

    // Correzione per miniupnpc moderno
    char errorString[256];
    int r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), errorString, sizeof(errorString));
    if (r == 1) {
        LogPrintf("UPnP: Found valid IGD: %s\n", urls.controlURL);

        char externalIPAddress[40];
        r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
        if (r != UPNPCOMMAND_SUCCESS) {
            LogPrintf("UPnP: GetExternalIPAddress failed: %s\n", strupnperror(r));
        } else {
            LogPrintf("UPnP: External IP: %s\n", externalIPAddress);
        }

        int port = GetListenPort();
        char portStr[6];
        snprintf(portStr, sizeof(portStr), "%d", port);

        r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portStr, portStr, lanaddr, "DogeCore", "TCP", nullptr, "86400");
        if (r != UPNPCOMMAND_SUCCESS) {
            LogPrintf("UPnP: AddPortMapping failed: %s\n", strupnperror(r));
        } else {
            LogPrintf("UPnP: Port mapping successful\n");
        }

        FreeUPNPUrls(&urls);
    } else {
        LogPrintf("UPnP: No valid IGD found: %s\n", errorString);
    }

    if (devlist) {
        freeUPNPDevlist(devlist);
    }
}

void CConnman::Start() {
    if (!fAddressesInitialized) {
        addrman = std::make_unique<CAddrMan>();
        fAddressesInitialized = true;
    }

    threadGroup.create_thread([this] { ThreadSocketHandler(); });
    threadGroup.create_thread([this] { ThreadDNSAddressSeed(); });
    threadGroup.create_thread([this] { ThreadMapPort(); });
}

bool CConnman::AddNode(const std::string& strAddr) {
    CService addr;
    if (Lookup(strAddr.c_str(), addr, GetListenPort(), false)) {
        addrman->Add(CAddress(addr, NODE_NETWORK), CNetAddr());
        return true;
    }
    return false;
}

bool CConnman::RemoveAddedNode(const std::string& strAddr) {
    return true; // Stub
}

size_t CConnman::GetNodeCount(ConnmanStats stats) {
    LOCK(cs_vNodes);
    if (stats == CConnman::NUM_CONNECTIONS_ALL) {
        return vNodes.size();
    }
    return 0;
}

void CConnman::DisconnectNode(const std::string& strAddr) {
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (pnode->addr.ToString() == strAddr) {
            pnode->fDisconnect = true;
        }
    }
}

void CConnman::DisconnectNode(NodeId id) {
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (pnode->GetId() == id) {
            pnode->fDisconnect = true;
        }
    }
}

bool CConnman::OpenNetworkConnection(const CAddress& addrConnect, bool fCountFailure, CSemaphoreGrant* grantOutbound, const char* pszDest, bool fOneShot, bool fFeeler, bool manual_connection) {
    // Stub semplificato
    return true;
}

CNode::CNode(NodeId idIn, ServiceFlags nLocalServicesIn, int nMyStartingHeightIn, SOCKET hSocketIn, const CAddress& addrIn, uint64_t nKeyedNetGroupIn, uint64_t nLocalHostNonceIn, const CAddress& addrBindIn, const std::string& addrNameIn, bool fInboundIn)
    : nId(idIn), nLocalServices(nLocalServicesIn), nMyStartingHeight(nMyStartingHeightIn), hSocket(hSocketIn), addr(addrIn), nKeyedNetGroup(nKeyedNetGroupIn), nLocalHostNonce(nLocalHostNonceIn), addrBind(addrBindIn), addrName(addrNameIn), fInbound(fInboundIn) {
    nTimeConnected = GetSystemTimeInSeconds();
}

CNode::~CNode() {
    CloseSocketDisconnect();
}

bool CNode::ReceiveMsgBytes(const char* pch, unsigned int nBytes, bool& complete) {
    complete = true; // Stub
    return true;
}

void CNode::CloseSocketDisconnect() {
    if (hSocket != INVALID_SOCKET) {
        CloseSocket(hSocket);
        hSocket = INVALID_SOCKET;
    }
}

void RegisterNodeSignals() {
    // Stub
}

void UnregisterNodeSignals() {
    // Stub
}

// Funzioni di utilità
void LogPrintf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

int GetListenPort() {
    return Params().GetDefaultPort(); // Definito in chainparams.cpp
}

bool LookupHost(const char* pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup) {
    return CNetAddr::LookupHost(pszName, vIP, nMaxSolutions, fAllowLookup);
}

bool Lookup(const char* pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions) {
    return LookupHost(pszName, vAddr, nMaxSolutions, fAllowLookup);
}

CService LookupNumeric(const char* pszName, int portDefault) {
    return CService(pszName, portDefault);
}

void CloseSocket(SOCKET& hSocket) {
    if (hSocket == INVALID_SOCKET) return;
#ifdef WIN32
    closesocket(hSocket);
#else
    close(hSocket);
#endif
    hSocket = INVALID_SOCKET;
}

int64_t GetSystemTimeInSeconds() {
    return time(nullptr);
}

void CConnman::AddOneShot(const std::string& strDest) {
    // Stub
}
