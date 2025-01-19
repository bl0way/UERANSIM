//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <memory>
#include <thread>
#include <ue/nts.hpp>
#include <ue/types.hpp>
#include <unordered_map>
#include <linux/if.h>
#include <linux/route.h>
#include <utils/logger.hpp>
#include <utils/nts.hpp>
#include <vector>
#include <utils/logger.hpp>
#include <utils/nts.hpp>
#include <vector>

#define SIZE_IP_MAX 128

namespace nr::ue
{

class TunTask : public NtsTask
{
  private:
    TaskBase *m_base;
    int m_psi;
    int m_fd;
    ScopedThread *m_receiver;

    // Tun info
    struct rtentry route;
    char if_name[IFNAMSIZ];
    char ipAddr[SIZE_IP_MAX];
    int mtu;
    bool configureRoute;

    void defaultIpRouteMgmt(const int method);
    void AllocateTun(const char *ifName);
    void ConfigureTun(const char *tunName, const char *ipAddr, int mtu, bool configureRoute);
    void RemoveDefaultIpRoute();
    void AddDefaultIpRoute();
    void TunSetIpAndUp();
    void RemoveIP();

    friend class UeCmdHandler;

  public:
    explicit TunTask(TaskBase *taskBase, int psi);
    ~TunTask() override = default;
    // Called by the "main" process
    bool TunAllocate(const char *namePrefix, std::string &error);
    bool TunConfigure(const std::string &ifname, const std::string &ipAddress, int mtu, bool configureRouting, std::string &error);

  protected:
    void onStart() override;
    void onLoop() override;
    void onQuit() override;
};

} // namespace nr::ue
