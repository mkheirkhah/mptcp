#include "mp-tcp-id-manager.h"
#include "ns3/log.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("MpTcpPathIdManager");


NS_OBJECT_ENSURE_REGISTERED(MpTcpPathIdManager);

TypeId
MpTcpPathIdManager::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpPathIdManager")
      .SetParent<Object>()
//      .AddConstructor<MpTcpSubFlow>()
      // TODO should be inherited
//      .AddTraceSource("cWindow",
//          "The congestion control window to trace.",
//           MakeTraceSourceAccessor(&MpTcpSubFlow::m_cWnd))
    ;
  return tid;
}

MpTcpPathIdManager::MpTcpPathIdManager() :
  Object()
{
  NS_LOG_INFO(this);
}



MpTcpPathIdManager::~MpTcpPathIdManager()
{
  NS_LOG_INFO(this);
}

} // end of ns3
