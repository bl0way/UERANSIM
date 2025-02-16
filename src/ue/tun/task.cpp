//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/route.h>
#include <mutex>
#include <string>
#include <sys/ioctl.h>
#include <ue/app/task.hpp>
#include <ue/nts.hpp>
#include <unistd.h>
#include <utils/libc_error.hpp>
#include <utils/scoped_thread.hpp>

// TODO: May be reduced to MTU 1500
#define RECEIVER_BUFFER_SIZE 8000

#define DEFAULT_MTU 1500

    static std::mutex configMutex;

struct ReceiverArgs
{
    int fd{};
    int psi{};
    NtsTask *targetTask{};
};

static std::string GetErrorMessage(const std::string &cause)
{
    std::string what = cause;

    int errNo = errno;
    if (errNo != 0)
        what += " (" + std::string{strerror(errNo)} + ")";

    return what;
}

static std::unique_ptr<nr::ue::NmUeTunToApp> NmError(std::string &&error)
{
    auto m = std::make_unique<nr::ue::NmUeTunToApp>(nr::ue::NmUeTunToApp::TUN_ERROR);
    m->error = std::move(error);
    return m;
}

static void ReceiverThread(ReceiverArgs *args)
{
    int fd = args->fd;
    int psi = args->psi;
    NtsTask *targetTask = args->targetTask;

    delete args;

    uint8_t buffer[RECEIVER_BUFFER_SIZE];

    while (true)
    {
        ssize_t n = ::read(fd, buffer, RECEIVER_BUFFER_SIZE);
        if (n < 0)
        {
            targetTask->push(NmError(GetErrorMessage("TUN device could not read")));
            return; // Abort receiver thread
        }

        if (n > 0)
        {
            auto m = std::make_unique<nr::ue::NmUeTunToApp>(nr::ue::NmUeTunToApp::DATA_PDU_DELIVERY);
            m->psi = psi;
            m->data = OctetString::FromArray(buffer, static_cast<size_t>(n));
            targetTask->push(std::move(m));
        }
    }
}

namespace nr::ue
{

ue::TunTask::TunTask(TaskBase *base, int psi) : m_base{base}, m_psi{psi}, m_fd{0}, m_receiver{}
{
}

void TunTask::onStart()
{
    auto *receiverArgs = new ReceiverArgs();
    receiverArgs->fd = m_fd;
    receiverArgs->targetTask = this;
    receiverArgs->psi = m_psi;
    m_receiver =
        new ScopedThread([](void *args) { ReceiverThread(reinterpret_cast<ReceiverArgs *>(args)); }, receiverArgs);
}

void TunTask::onQuit()
{
    delete m_receiver;
    if (this->configureRoute)
        this->RemoveDefaultIpRoute();
    this->RemoveIP();
    ::close(m_fd);
}

void TunTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::UE_APP_TO_TUN: {
        auto &w = dynamic_cast<NmAppToTun &>(*msg);
        ssize_t res = ::write(m_fd, w.data.data(), w.data.length());
        if (res < 0)
            push(NmError(GetErrorMessage("TUN device could not write")));
        else if (res != w.data.length())
            push(NmError(GetErrorMessage("TUN device partially written")));
        break;
    }
    case NtsMessageType::UE_TUN_TO_APP: {
        m_base->appTask->push(std::move(msg));
        break;
    }
    default:
        break;
    }
}

bool TunTask::TunAllocate(const char *ifname, std::string &error)
{
    try
    {
        TunTask::AllocateTun(ifname);
    }
    catch (const LibError &e)
    {
        error = e.what();
        return false;
    }

    return true;
}

bool TunTask::TunConfigure(const std::string &ifname, const std::string &ipAddress, const std::string &requestedNetmask,
                           int mtu, bool configureRouting, std::string &error)
{
    try
    {
        TunTask::ConfigureTun(ifname.c_str(), ipAddress.c_str(), requestedNetmask.c_str(), mtu, configureRouting);
    }
    catch (const LibError &e)
    {
        error = e.what();
        return false;
    }

    return true;
}

void TunTask::AddDefaultIpRoute()
{
    defaultIpRouteMgmt(SIOCADDRT);
}

void TunTask::RemoveDefaultIpRoute()
{
    defaultIpRouteMgmt(SIOCDELRT);
}

void TunTask::defaultIpRouteMgmt(const int method)
{
    struct sockaddr_in *addr;
    // Clear route
    memset( &this->route, 0, sizeof( this->route ) );

    int fd = socket( PF_INET, SOCK_DGRAM,  IPPROTO_IP);

    // Configure default route
    this->route.rt_dev = this->if_name;
    this->route.rt_flags = RTF_UP;

    addr = (struct sockaddr_in*) &this->route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr("0.0.0.0");

    addr = (struct sockaddr_in*) &this->route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr("0.0.0.0");

    if (ioctl( fd, method, &this->route ) < 0)
    {
        if (method == SIOCADDRT)
            throw LibError("Default route not added: ioctl(SIOCADDRT) ", errno);
        else throw LibError("Default route not added: ioctl(SIOCDELRT) ", errno);
    }
    close( fd );
}

void TunTask::AllocateTun(const char *ifName)
{
    // acquire the configuration lock
    const std::lock_guard<std::mutex> lock(configMutex);

    ifreq ifr{};

    if ((m_fd = open("/dev/net/tun", O_RDWR)) < 0)
        throw LibError("Open failure /dev/net/tun");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, ifName, IFNAMSIZ);

    if (ioctl(m_fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        close(m_fd);
        throw LibError("ioctl(TUNSETIFF)", errno);
    }
}

void TunTask::ConfigureTun(const char *tunName, const char *ipAddr, const char *requestedNetmask, int mtu, bool configureRoute)
{
    // acquire the configuration lock
    const std::lock_guard<std::mutex> lock(configMutex);

    // Load into the object
    strcpy(this->if_name, tunName);
    strcpy(this->ipAddr, ipAddr);
    strcpy(this->requestedNetmask, requestedNetmask);
    this->mtu = mtu;
    this->configureRoute = configureRoute;

    TunSetIpAndUp();
    if (configureRoute)
    {
        AddDefaultIpRoute();
    }
}

void TunTask::TunSetIpAndUp()
{
    ifreq ifr{};
    memset(&ifr, 0, sizeof(struct ifreq));

    struct sockaddr_in *sin;

    int sockFd = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, this->if_name, IFNAMSIZ);
    ifr.ifr_addr.sa_family = AF_INET;

    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, this->ipAddr, &sin->sin_addr);

    // Set address
    if (ioctl(sockFd, SIOCSIFADDR, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFADDR)", errno);
    // Set Mask
    inet_pton(AF_INET, this->requestedNetmask, &sin->sin_addr);
    if (ioctl(sockFd, SIOCSIFNETMASK, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFNETMASK)", errno);
    
    // Get flags
    if (ioctl(sockFd, SIOCGIFFLAGS, &ifr) < 0)
        throw LibError("ioctl(SIOCGIFFLAGS)", errno);
    // Set MTU 
    ifr.ifr_mtu = this->mtu;
    if (ioctl(sockFd, SIOCSIFMTU, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFMTU)", errno);

    // if up
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockFd, SIOCSIFFLAGS, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFFLAGS)", errno);

    close(sockFd);
}

void TunTask::RemoveIP()
{
    ifreq ifr{};
    memset(&ifr, 0, sizeof(struct ifreq));

    sockaddr_in sai{};
    memset(&sai, 0, sizeof(struct sockaddr));

    int sockFd;
    char *p;

    sockFd = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, this->if_name);

    sai.sin_family = AF_INET;
    sai.sin_port = 0;

    sai.sin_addr.s_addr = INADDR_ANY;

    p = (char *)&sai;
    memcpy((((char *)&ifr + offsetof(struct ifreq, ifr_addr))), p, sizeof(struct sockaddr));

    if (ioctl(sockFd, SIOCSIFADDR, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFADDR)", errno);

    ifr.ifr_mtu = DEFAULT_MTU;
    if (ioctl(sockFd, SIOCSIFMTU, &ifr) < 0)
        throw LibError("ioctl(SIOCSIFMTU)", errno);

    close(sockFd);
}

} // namespace nr::ue