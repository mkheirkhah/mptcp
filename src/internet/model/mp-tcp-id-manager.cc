#include "mp-tcp-id-manager.h"
#include "ns3/log.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("MpTcpPathIdManager");

MpTcpPathIdManager::MpTcpPathIdManager() :
  Object()
{
  NS_LOG_INFO(this);
}

MpTcpPathIdManager::~MpTcpPathIdManager()
{
  NS_LOG_INFO(this);
}

}
