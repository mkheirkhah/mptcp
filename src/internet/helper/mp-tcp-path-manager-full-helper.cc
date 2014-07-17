     
     
     
      #if 0 
      // TODO That should go into a helper
      // Object from L3 to access to routing protocol, Interfaces and NetDevices and so on.
      Ptr<Ipv4L3Protocol> ipv4 = m_node->GetObject<Ipv4L3Protocol>();
      for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++)
        {
          //Ptr<NetDevice> device = m_node->GetDevice(i);
          Ptr<Ipv4Interface> interface = ipv4->GetInterface(i);
          Ipv4InterfaceAddress interfaceAddr = interface->GetAddress(0);

          // Skip the loop-back
          if (interfaceAddr.GetLocal() == Ipv4Address::GetLoopback())
            continue;

          addrInfo = new MpTcpAddressInfo();
          addrInfo->addrID = i;
          addrInfo->ipv4Addr = interfaceAddr.GetLocal();
          addrInfo->mask = interfaceAddr.GetMask();
      header.AddOptADDR(OPT_ADDR, addrInfo->addrID, addrInfo->ipv4Addr);
      olen += 6;
          m_localAddrs.insert(m_localAddrs.end(), addrInfo);
        }
      #endif 
