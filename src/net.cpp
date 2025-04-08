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
#include <boost/thread.hpp>

extern ArgsManager gArgs; // Dichiarazione esterna, definita altrove

std::atomic<bool> fNetworkActive(true);
CCriticalSection cs_vNodes;
CCriticalSection cs_mapInboundConnectionTracker;
CCriticalSection cs_semOutbound;
std::unique_ptr<CAddrMan> addrman;

CConnman::CConnman(uint64_t nSeed0In, uint64_t nSeed1In)
    : nSeed0(nSeed0In), nSeed1(nSeed1In), semOutbound(new CSemaphore(DEFAULT_MAX_OUTBOUND)), threadGroup() {
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
    addrBind.GetSockAddr((struct sockaddr*)&sockaddr, sizeof(sockaddr));
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
    close(sockfd);
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
            }
            pnode->Release();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void CConnman::ThreadDNSAddressSeed() {
    if (!gArgs.GetBoolArg("-dnsseed", true)) return;
    const std::vector<CDNSSeedData>& vSeeds = Params().DNSSeeds();
    for (const CDNSSeedData& seed : vSeeds) {
        std::vector<CNetAddr> vIPs;
        LookupHost(seed.host.c_str(), vIPs, 0, true);
        for (const CNetAddr& ip : vIPs) {
            addrman.Add(CAddress(CService(ip, GetListenPort()), NODE_NETWORK), ip);
        }
    }
}

void CConnman::ThreadMapPort() {
    if (!gArgs.GetBoolArg("-upnp", DEFAULT_UPNP)) return;
    struct UPNPDev* devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, nullptr);
    if (!devlist) {
        LogPrintf("UPnP: No devices discovered\n");
        return;
    }
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[64];
    char errorString[256];
    int r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
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
    freeUPNPDevlist(devlist);
}

bool CConnman::Start(CScheduler& scheduler, std::string& strNodeError, Options options) {
    if (!fAddressesInitialized) {
        addrman = std::make_unique<CAddrMan>();
        fAddressesInitialized = true;
    }
    threadGroup.create_thread([this] { ThreadSocketHandler(); });
    threadGroup.create_thread([this] { ThreadDNSAddressSeed(); });
    threadGroup.create_thread([this] { ThreadMapPort(); });
    return true;
}

bool CConnman::AddNode(const std::string& strAddr) {
    CService addr;
    if (Lookup(strAddr.c_str(), addr, GetListenPort(), false)) {
        addrman.Add(CAddress(addr, NODE_NETWORK), CNetAddr());
        return true;
    }
    return false;
}

bool CConnman::RemoveAddedNode(const std::string& strAddr) {
    return true; // Stub
}

size_t CConnman::GetNodeCount(NumConnections stats) {
    LOCK(cs_vNodes);
    return vNodes.size();
}

bool CConnman::DisconnectNode(const std::string& strAddr) {
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (pnode->addr.ToString() == strAddr) {
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

bool CConnman::DisconnectNode(NodeId id) {
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (pnode->GetId() == id) {
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

bool CConnman::OpenNetworkConnection(const CAddress& addrConnect, bool fCountFailure, CSemaphoreGrant* grantOutbound, const char* pszDest, bool fOneShot, bool fFeeler, bool manual_connection) {
    return true; // Stub
}

CNode::CNode(NodeId idIn, ServiceFlags nLocalServicesIn, int nMyStartingHeightIn, SOCKET hSocketIn, const CAddress& addrIn, uint64_t nKeyedNetGroupIn, uint64_t nLocalHostNonceIn, const std::string& addrNameIn, bool fInboundIn)
    : nId(idIn), nLocalServices(nLocalServicesIn), nMyStartingHeight(nMyStartingHeightIn), hSocket(hSocketIn), addr(addrIn), nKeyedNetGroup(nKeyedNetGroupIn), nLocalHostNonce(nLocalHostNonceIn), addrName(addrNameIn), fInbound(fInboundIn) {
    nTimeConnected = GetSystemTimeInSeconds();
}

CNode::~CNode() {
    CloseSocketDisconnect();
}

bool CNode::ReceiveMsgBytes(const char* pch, unsigned int nBytes, bool& complete) {
    complete = true;
    return true; // Stub
}

void CNode::CloseSocketDisconnect() {
    if (hSocket != INVALID_SOCKET) {
        CloseSocket(hSocket);
        hSocket = INVALID_SOCKET;
    }
}

void RegisterNodeSignals() {}
void UnregisterNodeSignals() {}

unsigned short GetListenPort() {
    return static_cast<unsigned short>(Params().GetDefaultPort());
}

bool LookupHost(const char* pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup) {
    return LookupHost(std::string(pszName), vIP, nMaxSolutions, fAllowLookup);
}

bool Lookup(const char* pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions) {
    return Lookup(std::string(pszName), vAddr, portDefault, fAllowLookup, nMaxSolutions);
}

CService LookupNumeric(const char* pszName, int portDefault) {
    return LookupNumeric(std::string(pszName), portDefault);
}

bool CloseSocket(SOCKET& hSocket) {
    if (hSocket == INVALID_SOCKET) return false;
#ifdef WIN32
    closesocket(hSocket);
#else
    close(hSocket);
#endif
    hSocket = INVALID_SOCKET;
    return true;
}

int64_t GetSystemTimeInSeconds() {
    return time(nullptr);
}

void CConnman::AddOneShot(const std::string& strDest) {}
