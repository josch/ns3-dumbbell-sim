/*
 * Copyright (C) 2013 - Johannes Schauer <j.schauer at email.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * 
 * This code heavily borrows from ns3 itself which are copyright of their
 * respective authors and redistributable under the same conditions.
 *
 */

#include <stddef.h>                     // for size_t
#include <stdint.h>                     // for uint32_t
#include <stdlib.h>                     // for exit
#include <algorithm>                    // for min
#include <iomanip>                      // for operator<<, setw
#include <iostream>                     // for operator<<, basic_ostream, etc
#include <string>                       // for string, allocator, etc
#include <vector>                       // for vector
#include "ns3/address.h"                // for Address
#include "ns3/application-container.h"  // for ApplicationContainer
#include "ns3/application.h"            // for Application
#include "ns3/boolean.h"                // for BooleanValue
#include "ns3/callback.h"               // for MakeCallback
#include "ns3/command-line.h"           // for CommandLine
#include "ns3/config.h"                 // for SetDefault, Connect
#include "ns3/data-rate.h"              // for DataRate
#include "ns3/double.h"                 // for DoubleValue
#include "ns3/enum.h"                   // for EnumValue
#include "ns3/error-model.h"            // for RateErrorModel
#include "ns3/event-id.h"               // for EventId
#include "ns3/fatal-error.h"            // for NS_FATAL_ERROR
#include "ns3/global-value.h"           // for GlobalValue
#include "ns3/header.h"                 // for Header
#include "ns3/inet-socket-address.h"    // for InetSocketAddress
#include "ns3/internet-stack-helper.h"  // for InternetStackHelper
#include "ns3/ipv4-address-helper.h"    // for Ipv4AddressHelper
#include "ns3/ipv4-address.h"           // for operator<<, Ipv4Address, etc
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4-header.h"            // for Ipv4Header
#include "ns3/ipv4-interface-container.h"  // for Ipv4InterfaceContainer
#include "ns3/ipv4.h"                   // for Ipv4
#include "ns3/net-device-container.h"   // for NetDeviceContainer
#include "ns3/net-device.h"             // for NetDevice
#include "ns3/node-container.h"         // for NodeContainer
#include "ns3/node.h"                   // for Node
#include "ns3/nstime.h"                 // for Seconds, Time
#include "ns3/object.h"                 // for CreateObject
#include "ns3/packet-sink-helper.h"     // for PacketSinkHelper
#include "ns3/packet.h"                 // for Packet
#include "ns3/point-to-point-helper.h"  // for PointToPointHelper
#include "ns3/pointer.h"                // for PointerValue
#include "ns3/ptr.h"                    // for Ptr, Create, DynamicCast
#include "ns3/rng-seed-manager.h"       // for SeedManager
#include "ns3/simulator.h"              // for Simulator
#include "ns3/socket.h"                 // for Socket, etc
#include "ns3/string.h"                 // for StringValue
#include "ns3/tcp-header.h"             // for TcpHeader
#include "ns3/tcp-newreno.h"            // for TcpNewReno
#include "ns3/tcp-reno.h"               // for TcpReno
#include "ns3/tcp-socket-factory.h"     // for TcpSocketFactory
#include "ns3/tcp-socket.h"             // for TcpSocket
#include "ns3/tcp-tahoe.h"              // for TcpTahoe
#include "ns3/tcp-westwood.h"           // for TcpWestwood, etc
#include "ns3/type-id.h"                // for TypeIdValue
#include "ns3/udp-header.h"             // for UdpHeader
#include "ns3/udp-socket-factory.h"     // for UdpSocketFactory
#include "ns3/uinteger.h"               // for UintegerValue

/*
 * we need to roll our own app instead of using one of the supplied helpers
 * because of the following reasons:
 *
 *  - bulktransferhelper can't do udp
 *  - onoffhelper doesnt allow access to the underlying sockets
 *  - not having access to the underlying sockets, means that any tracer can
 *    only be registered *after* the app created by the helper is started.
 *    This is ugly as it forces to start multiple tracers manually in synch
 *    with the app start time. Since it has to be multiple tracers, one cannot
 *    anymore use the wildcard mechanism to have a one-tracer-catches-all
 *    setup.
 *
 * this app allows to send an infinite number of tcp or udp packets at a fixed
 * rate
 * */
class LimitedRateApp : public ns3::Application
{
    public:

        LimitedRateApp();
        virtual ~ LimitedRateApp();

        void Setup(ns3::Ptr<ns3::Socket> socket, ns3::Address address,
                uint32_t packetSize, ns3::DataRate dataRate);

    private:
        virtual void StartApplication(void);
        virtual void StopApplication(void);

        void ScheduleTx(void);
        void SendPacket(void);

        ns3::Ptr<ns3::Socket> m_socket;
        ns3::Address m_peer;
        uint32_t m_packetSize;
        ns3::DataRate m_dataRate;
        ns3::EventId m_sendEvent;
        bool m_running;
};

LimitedRateApp::LimitedRateApp()
  : m_socket(0),
    m_peer(),
    m_packetSize(0),
    m_dataRate(0),
    m_sendEvent(),
    m_running(false)
{
}

LimitedRateApp::~LimitedRateApp()
{
    m_socket = 0;
}

    void
LimitedRateApp::Setup(ns3::Ptr<ns3::Socket> socket,
        ns3::Address address, uint32_t packetSize,
        ns3::DataRate dataRate)
{
    m_socket = socket;
    m_peer = address;
    m_packetSize = packetSize;
    m_dataRate = dataRate;
}

void LimitedRateApp::StartApplication(void)
{
    m_running = true;
    m_socket->Bind();
    m_socket->Connect(m_peer);
    SendPacket();
}

void LimitedRateApp::StopApplication(void)
{
    m_running = false;

    if (m_sendEvent.IsRunning()) {
        ns3::Simulator::Cancel(m_sendEvent);
    }

    if (m_socket) {
        m_socket->Close();
    }
}

void LimitedRateApp::SendPacket(void)
{
    ns3::Ptr<ns3::Packet> packet =
        ns3::Create<ns3::Packet>(m_packetSize);
    m_socket->Send(packet);
    ScheduleTx();
}

void LimitedRateApp::ScheduleTx(void)
{
    if (m_running) {
        ns3::Time tNext(ns3::Seconds(
                    m_packetSize * 8 /
                    static_cast<double>(m_dataRate.GetBitRate())));
        m_sendEvent = ns3::Simulator::Schedule(
                tNext, &LimitedRateApp::SendPacket, this);
    }
}

/*
 * this app borrows from the BulkSendApplication but keeps sending for an
 * infinite time (until Stop() is reached) and receives an already created
 * socket instead of creating its own
 *
 * it has unlimited rate in the sense that it pushes new packets into the
 * sending buffer of the socket until it is full and keeps filling that buffer
 * once the socket becomes ready to send again.
 *
 * due to this nature of operation it is only suitable for streaming sockets
 */
class UnlimitedRateApp : public ns3::Application
{
    public:
        UnlimitedRateApp();
        virtual ~ UnlimitedRateApp();

        void Setup(ns3::Ptr<ns3::Socket> socket, ns3::Address address,
                uint32_t packetSize);

    private:
        // inherited from Application base class.
        virtual void StartApplication(void);        // Called at time specified by Start
        virtual void StopApplication(void); // Called at time specified by Stop

        void SendData();

        ns3::Ptr<ns3::Socket> m_socket;  // Associated socket
        ns3::Address m_peer;        // Peer address
        bool m_connected;           // True if connected
        uint32_t m_packetSize;      // Size of data to send each time

        void ConnectionSucceeded(ns3::Ptr<ns3::Socket> socket);
        void ConnectionFailed(ns3::Ptr<ns3::Socket> socket);
        void DataSend(ns3::Ptr<ns3::Socket>, uint32_t);  // for socket's SetSendCallback
        void Ignore(ns3::Ptr<ns3::Socket> socket);
};

UnlimitedRateApp::UnlimitedRateApp()
 :  m_socket(0),
    m_connected(false),
    m_packetSize(512)
{
}

UnlimitedRateApp::~UnlimitedRateApp()
{
    m_socket = 0;
}

    void
UnlimitedRateApp::Setup(ns3::Ptr<ns3::Socket> socket,
        ns3::Address address, uint32_t packetSize)
{
    m_socket = socket;
    m_peer = address;
    m_packetSize = packetSize;

    // Fatal error if socket type is not NS3_SOCK_STREAM or NS3_SOCK_SEQPACKET
    if (m_socket->GetSocketType() != ns3::Socket::NS3_SOCK_STREAM &&
            m_socket->GetSocketType() != ns3::Socket::NS3_SOCK_SEQPACKET) {
        NS_FATAL_ERROR
            ("Using UnlimitedRateApp with an incompatible socket type. "
             "UnlimitedRateApp requires SOCK_STREAM or SOCK_SEQPACKET. "
             "In other words, use TCP instead of UDP.");
    }
}

void UnlimitedRateApp::StartApplication(void)
{
    m_socket->Bind();
    m_socket->Connect(m_peer);
    m_socket->ShutdownRecv();
    m_socket->SetConnectCallback(ns3::MakeCallback(
                &UnlimitedRateApp::ConnectionSucceeded, this),
            ns3::MakeCallback(
                &UnlimitedRateApp::ConnectionFailed, this));
    m_socket->SetSendCallback(ns3::MakeCallback(
                &UnlimitedRateApp::DataSend, this));
    if (m_connected)
        SendData();
}

void UnlimitedRateApp::StopApplication(void)    // Called at time specified by Stop
{
    if (m_socket != 0) {
        m_socket->Close();
        m_connected = false;
    }
}

void UnlimitedRateApp::SendData(void)
{
    // We exit this loop when actual<toSend as the send side
    // buffer is full. The "DataSend" callback will pop when
    // some buffer space has freed ip.
    for (;;) {
        ns3::Ptr<ns3::Packet> packet =
            ns3::Create<ns3::Packet>(m_packetSize);
        int actual = m_socket->Send(packet);
        if ((unsigned) actual != m_packetSize)
            break;
    }
}

void UnlimitedRateApp::ConnectionSucceeded(ns3::Ptr<ns3::Socket> socket)
{
    m_connected = true;
    SendData();
}

void UnlimitedRateApp::ConnectionFailed(ns3::Ptr<ns3::Socket> socket)
{
}

void UnlimitedRateApp::DataSend(ns3::Ptr<ns3::Socket>, uint32_t)
{
    if (m_connected) {          // Only send new data if the connection has completed
        ns3::Simulator::ScheduleNow(&UnlimitedRateApp::SendData, this);
    }
}


/*
 * this app borrows from the BulkSendApplication but instead allows a socket
 * being passed to it instead of creating its own socket internally.
 *
 * it has unlimited rate in the sense that it pushes new packets into the
 * sending buffer of the socket until it is full and keeps filling that buffer
 * once the socket becomes ready to send again.
 *
 * due to this nature of operation it is only suitable for streaming sockets
 */
class LimitedTransferApp : public ns3::Application
{
    public:
        LimitedTransferApp();
        virtual ~ LimitedTransferApp();

        void Setup(ns3::Ptr<ns3::Socket> socket, ns3::Address address,
                uint32_t packetSize, uint32_t maxBytes);

    private:
        // inherited from Application base class.
        virtual void StartApplication(void);        // Called at time specified by Start
        virtual void StopApplication(void); // Called at time specified by Stop

        void SendData();

        ns3::Ptr<ns3::Socket> m_socket;  // Associated socket
        ns3::Address m_peer;        // Peer address
        bool m_connected;           // True if connected
        uint32_t m_packetSize;      // Size of data to send each time
        uint32_t m_totBytes;        // Total bytes sent so far
        uint32_t m_maxBytes;        // Limit total number of bytes sent

        void ConnectionSucceeded(ns3::Ptr<ns3::Socket> socket);
        void ConnectionFailed(ns3::Ptr<ns3::Socket> socket);
        void DataSend(ns3::Ptr<ns3::Socket>, uint32_t);  // for socket's SetSendCallback
        void Ignore(ns3::Ptr<ns3::Socket> socket);
};

LimitedTransferApp::LimitedTransferApp()
  : m_socket(0),
    m_connected(false),
    m_packetSize(512),
    m_totBytes(0),
    m_maxBytes(0)
{
}

LimitedTransferApp::~LimitedTransferApp()
{
    m_socket = 0;
}

    void
LimitedTransferApp::Setup(ns3::Ptr<ns3::Socket> socket,
        ns3::Address address, uint32_t packetSize,
        uint32_t maxBytes)
{
    m_socket = socket;
    m_peer = address;
    m_packetSize = packetSize;
    m_maxBytes = maxBytes;

    // Fatal error if socket type is not NS3_SOCK_STREAM or NS3_SOCK_SEQPACKET
    if (m_socket->GetSocketType() != ns3::Socket::NS3_SOCK_STREAM &&
            m_socket->GetSocketType() != ns3::Socket::NS3_SOCK_SEQPACKET) {
        NS_FATAL_ERROR
            ("Using LimitedTransferApp with an incompatible socket type. "
             "LimitedTransferApp requires SOCK_STREAM or SOCK_SEQPACKET. "
             "In other words, use TCP instead of UDP.");
    }
}

void LimitedTransferApp::StartApplication(void)
{
    m_socket->Bind();
    m_socket->Connect(m_peer);
    m_socket->ShutdownRecv();
    m_socket->SetConnectCallback(MakeCallback(
                &LimitedTransferApp::ConnectionSucceeded, this),
            MakeCallback(
                &LimitedTransferApp::ConnectionFailed, this));
    m_socket->SetSendCallback(
            ns3::MakeCallback(&LimitedTransferApp::DataSend, this));
    if (m_connected)
        SendData();
}

void LimitedTransferApp::StopApplication(void)  // Called at time specified by Stop
{
    if (m_socket != 0) {
        m_socket->Close();
        m_connected = false;
    }
}

void LimitedTransferApp::SendData(void)
{
    while (m_totBytes<m_maxBytes) {
        uint32_t toSend = m_packetSize;
        // Make sure we don't send too many
        if (m_maxBytes> 0) {
            toSend = std::min(m_packetSize, m_maxBytes - m_totBytes);
        }
        ns3::Ptr<ns3::Packet> packet =
            ns3::Create<ns3::Packet>(toSend);
        int actual = m_socket->Send(packet);
        if (actual> 0) {
            m_totBytes += actual;
        }
        // We exit this loop when actual<toSend as the send side
        // buffer is full. The "DataSent" callback will pop when
        // some buffer space has freed ip.
        if ((unsigned) actual != toSend) {
            break;
        }
    }
    // Check if time to close (all sent)
    if (m_totBytes == m_maxBytes && m_connected) {
        m_socket->Close();
        m_connected = false;
    }
}

void LimitedTransferApp::ConnectionSucceeded(ns3::Ptr<ns3::Socket>
        socket)
{
    m_connected = true;
    SendData();
}

void LimitedTransferApp::ConnectionFailed(ns3::Ptr<ns3::Socket> socket)
{
}

void LimitedTransferApp::DataSend(ns3::Ptr<ns3::Socket>, uint32_t)
{
    if (m_connected) {          // Only send new data if the connection has completed
        ns3::Simulator::ScheduleNow(&LimitedTransferApp::SendData, this);
    }
}

static void CwndTracer(std::string context, uint32_t oldval,
        uint32_t newval)
{
    if (newval> 2147483648) {
        std::cerr << "impossibly high cwnd value: " << newval << std::endl;
        return;
    }
    std::cout << std::setw(8) << ns3::Simulator::Now().GetSeconds() << " ";
    std::cout << context << " " << newval << std::endl;
}

static void SsThreshTracer(std::string context, uint32_t oldval,
        uint32_t newval)
{
    std::cout << std::setw(8) << ns3::Simulator::Now().GetSeconds() << " ";
    std::cout << context << " " << newval << std::endl;
}

static void PacketSinkRxTracer(std::string context,
        ns3::Ptr<const ns3::Packet> p,
        const ns3::Address & addr)
{
    std::cout << std::setw(8) << ns3::Simulator::Now().GetSeconds() << " ";
    std::cout << context << " " << p->GetSize() << std::endl;
}

static void TxQueueDropTracer(std::string context,
        ns3::Ptr<const ns3::Packet> p)
{
    ns3::Ipv4Header ipv4h;
    uint32_t len = p->PeekHeader(ipv4h);
    if (len == 0) {
        std::cout << std::setw(8) <<
            ns3::Simulator::Now().GetSeconds() << " ";
        std::cout << context << " 0" << std::endl;
    } else {
        std::cout << std::setw(8) <<
            ns3::Simulator::Now().GetSeconds() << " ";
        std::cout << context << " " << ipv4h.GetSource() <<
            " " << ipv4h.GetDestination() << std::endl;
    }
}

static void PhyRxDropTracer(std::string context,
        ns3::Ptr<const ns3::Packet> p)
{
    std::cout << std::setw(8) << ns3::Simulator::Now().GetSeconds() << " ";
    std::cout << context << " 0" << std::endl;
}

void printHeaderSizes()
{
    ns3::Header * temp_header = new ns3::Ipv4Header();
    uint32_t ip_header = temp_header->GetSerializedSize();
    std::cerr << "IP Header size is: " << ip_header << std::endl;
    delete temp_header;
    temp_header = new ns3::TcpHeader();
    uint32_t tcp_header = temp_header->GetSerializedSize();
    std::cerr << "TCP Header size is: " << tcp_header << std::endl;
    delete temp_header;
    temp_header = new ns3::UdpHeader();
    uint32_t udp_header = temp_header->GetSerializedSize();
    std::cerr << "UDP Header size is: " << udp_header << std::endl;
    delete temp_header;
}

int main(int argc, char *argv[])
{
    std::string transport_prot = "TcpNewReno";
    double error_p = 0.0;
    std::string bottleneck_bandwidth = "1Mbps";
    std::string access_bandwidth = "10Mbps";
    std::string bottleneck_delay = "50ms";
    std::string access_delay = "1ms";
    uint32_t run = 0;
    double simstop = 0.0;
    bool pcaptracing = false;

    ns3::CommandLine cmd;
    cmd.AddValue("tcpcaa",
            "Default TCP congestion-avoidance algorithm to use: "
            "TcpTahoe, TcpReno, TcpNewReno, TcpWestwood, TcpWestwoodPlus ",
            transport_prot);
    cmd.AddValue("error_p", "Packet error rate", error_p);
    cmd.AddValue("bandwidth", "Bottleneck link bandwidth",
            bottleneck_bandwidth);
    cmd.AddValue("access_bandwidth", "Access link bandwidth",
            access_bandwidth);
    cmd.AddValue("delay", "Bottleneck link delay", bottleneck_delay);
    cmd.AddValue("access delay", "Access link delay", access_delay);
    cmd.AddValue("run", "Run index (for setting repeatable seeds)", run);
    cmd.AddValue("simstop", "Stop simulator after this many seconds",
            simstop);
    cmd.AddValue("tracing", "Flag to enable/disable pcap tracing",
            pcaptracing);
    cmd.Parse(argc, argv);

    ns3::SeedManager::SetSeed(1);
    ns3::SeedManager::SetRun(run);

    if (transport_prot.compare("TcpTahoe") == 0)
        ns3::Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                ns3::TypeIdValue(ns3::TcpTahoe::GetTypeId()));
    else if (transport_prot.compare("TcpReno") == 0)
        ns3::Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                ns3::TypeIdValue(ns3::TcpReno::GetTypeId()));
    else if (transport_prot.compare("TcpNewReno") == 0)
        ns3::Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                ns3::TypeIdValue(ns3::TcpNewReno::GetTypeId()));
    else if (transport_prot.compare("TcpWestwood") == 0) {
        ns3::Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                ns3::TypeIdValue(ns3::TcpWestwood::GetTypeId()));
        ns3::Config::SetDefault("ns3::TcpWestwood::FilterType",
                ns3::EnumValue(ns3::TcpWestwood::TUSTIN));
    } else if (transport_prot.compare("TcpWestwoodPlus") == 0) {
        ns3::Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                ns3::TypeIdValue(ns3::TcpWestwood::GetTypeId()));
        ns3::Config::SetDefault("ns3::TcpWestwood::ProtocolType",
                ns3::EnumValue(ns3::TcpWestwood::WESTWOODPLUS));
        ns3::Config::SetDefault("ns3::TcpWestwood::FilterType",
                ns3::EnumValue(ns3::TcpWestwood::TUSTIN));
    } else {
        std::cerr << "Invalid TCP version";
        exit(1);
    }

    /* the default is to not calculate checksums but if we want pcap traces
     * then we calculate them */
    if (pcaptracing)
        ns3::GlobalValue::Bind("ChecksumEnabled", ns3::BooleanValue(true));

    // read in traffic definitions from standard input
    std::cerr << "Reading traffic descriptions from standard input..."
        << std::endl;
    std::vector<std::string> inputlines;
    std::string input_line;
    for (std::string s; std::getline(std::cin, s);) {
        inputlines.push_back(s);
    }

    uint32_t number_of_clients = inputlines.size();
    std::cerr << "creating " << number_of_clients <<
        " data streams" << std::endl;

    ns3::PointToPointHelper bottleNeckLink;
    bottleNeckLink.SetDeviceAttribute("DataRate",
            ns3::StringValue(bottleneck_bandwidth));
    bottleNeckLink.SetChannelAttribute("Delay",
            ns3::StringValue(bottleneck_delay));

    ns3::PointToPointHelper pointToPointLeaf;
    pointToPointLeaf.SetDeviceAttribute("DataRate",
            ns3::StringValue(access_bandwidth));
    pointToPointLeaf.SetChannelAttribute("Delay",
            ns3::StringValue(access_delay));

    int port = 9000;

    /* we cannot use the PointToPointDumbbellHelper because it hides the
     * NetDeviceContainer it creates from us. Therefore, we are creating the
     * dumbbell topology manually */
    // create all the nodes
    ns3::NodeContainer routers;
    routers.Create(2);
    ns3::NodeContainer leftleaves;
    leftleaves.Create(number_of_clients);
    ns3::NodeContainer rightleaves;
    rightleaves.Create(number_of_clients);

    // error model
    ns3::Ptr<ns3::RateErrorModel> em =
        ns3::CreateObject<ns3::RateErrorModel>();
    em->SetAttribute("ErrorRate", ns3::DoubleValue(error_p));

    // add the link connecting the routers
    ns3::NetDeviceContainer routerdevices =
        bottleNeckLink.Install(routers);

    ns3::NetDeviceContainer leftrouterdevices;
    ns3::NetDeviceContainer leftleafdevices;
    ns3::NetDeviceContainer rightrouterdevices;
    ns3::NetDeviceContainer rightleafdevices;

    // add links on both sides
    for (uint32_t i = 0; i<number_of_clients; ++i) {
        // add the left side links
        ns3::NetDeviceContainer cleft =
            pointToPointLeaf.Install(routers.Get(0), leftleaves.Get(i));
        leftrouterdevices.Add(cleft.Get(0));
        leftleafdevices.Add(cleft.Get(1));
        cleft.Get(0)->SetAttribute("ReceiveErrorModel",
                ns3::PointerValue(em));
        // add the right side links
        ns3::NetDeviceContainer cright =
            pointToPointLeaf.Install(routers.Get(1), rightleaves.Get(i));
        rightrouterdevices.Add(cright.Get(0));
        rightleafdevices.Add(cright.Get(1));
        cright.Get(0)->SetAttribute("ReceiveErrorModel",
                ns3::PointerValue(em));
    }

    // install internet stack on all nodes
    ns3::InternetStackHelper stack;
    stack.Install(routers);
    stack.Install(leftleaves);
    stack.Install(rightleaves);

    // assign ipv4 addresses (ipv6 addresses apparently are still not fully
    // supported by ns3)
    ns3::Ipv4AddressHelper routerips =
        ns3::Ipv4AddressHelper("10.3.0.0", "255.255.255.0");
    ns3::Ipv4AddressHelper leftips =
        ns3::Ipv4AddressHelper("10.1.0.0", "255.255.255.0");
    ns3::Ipv4AddressHelper rightips =
        ns3::Ipv4AddressHelper("10.2.0.0", "255.255.255.0");

    ns3::Ipv4InterfaceContainer routerifs;
    ns3::Ipv4InterfaceContainer leftleafifs;
    ns3::Ipv4InterfaceContainer leftrouterifs;
    ns3::Ipv4InterfaceContainer rightleafifs;
    ns3::Ipv4InterfaceContainer rightrouterifs;

    // assign addresses to connection connecting routers
    routerifs = routerips.Assign(routerdevices);

    // assign addresses to connection between routers and leaves
    for (uint32_t i = 0; i<number_of_clients; ++i) {
        // Assign to left side
        ns3::NetDeviceContainer ndcleft;
        ndcleft.Add(leftleafdevices.Get(i));
        ndcleft.Add(leftrouterdevices.Get(i));
        ns3::Ipv4InterfaceContainer ifcleft = leftips.Assign(ndcleft);
        leftleafifs.Add(ifcleft.Get(0));
        leftrouterifs.Add(ifcleft.Get(1));
        leftips.NewNetwork();
        // Assign to right side
        ns3::NetDeviceContainer ndcright;
        ndcright.Add(rightleafdevices.Get(i));
        ndcright.Add(rightrouterdevices.Get(i));
        ns3::Ipv4InterfaceContainer ifcright = rightips.Assign(ndcright);
        rightleafifs.Add(ifcright.Get(0));
        rightrouterifs.Add(ifcright.Get(1));
        rightips.NewNetwork();
    }

    ns3::ApplicationContainer sinkApps, udpApp;
    ns3::Address sinkLocalAddress(
            ns3::InetSocketAddress(
                ns3::Ipv4Address::GetAny(), port));
    ns3::PacketSinkHelper TcpPacketSinkHelper("ns3::TcpSocketFactory",
            sinkLocalAddress);
    ns3::PacketSinkHelper UdpPacketSinkHelper("ns3::UdpSocketFactory",
            sinkLocalAddress);

    // create all the source and sink apps
    for (size_t i = 0; i<inputlines.size(); ++i) {
        ns3::Ptr<ns3::Socket> sockptr;
        unsigned int pkgsize;
        float start;

        std::stringstream ss(inputlines[i]);
        std::string app, transport;
        ss >> app >> transport >> pkgsize >> start;

        if (transport.compare("TCP") == 0) {
            // setup source socket
            sockptr =
                ns3::Socket::CreateSocket(leftleaves.Get(i),
                        ns3::TcpSocketFactory::GetTypeId());
            ns3::Ptr<ns3::TcpSocket> tcpsockptr =
                ns3::DynamicCast<ns3::TcpSocket> (sockptr);
            tcpsockptr->SetAttribute("SegmentSize",
                    ns3::UintegerValue(pkgsize));
            std::stringstream nodeidss;
            nodeidss << leftleaves.Get(i)->GetId();
            std::string prefix = "/NodeList/" + nodeidss.str();
            sockptr->TraceConnect("CongestionWindow",
                    prefix +
                    "/$ns3::TcpL4Protocol/SocketList/0/CongestionWindow",
                    ns3::MakeCallback(&CwndTracer));
            sockptr->TraceConnect("SlowStartThreshold",
                    prefix +
                    "/$ns3::TcpL4Protocol/SocketList/0/SlowStartThreshold",
                    ns3::MakeCallback(&SsThreshTracer));
            // setup sink
            sinkApps.Add(TcpPacketSinkHelper.Install(rightleaves.Get(i)));
        } else if (transport.compare("UDP") == 0) {
            // setup source socket
            sockptr =
                ns3::Socket::CreateSocket(leftleaves.Get(i),
                        ns3::UdpSocketFactory::GetTypeId());
            // setup sink
            sinkApps.Add(UdpPacketSinkHelper.Install(rightleaves.Get(i)));
        } else {
            std::cerr << "unknown transport type: " <<
                transport << std::endl;
            exit(1);
        }

        if (app.compare("LR") == 0) {
            /* additionally read stop time and rate */
            float stop;
            std::string rate;
            ss >> stop >> rate;
            ns3::Ptr<LimitedRateApp> app =
                ns3::CreateObject<LimitedRateApp> ();
            app->Setup(sockptr,
                    ns3::InetSocketAddress(rightleafifs.GetAddress(i),
                        port), pkgsize,
                    ns3::DataRate(rate));
            leftleaves.Get(i)->AddApplication(app);
            app->SetStartTime(ns3::Seconds(start));
            app->SetStopTime(ns3::Seconds(stop));
        } else if (app.compare("UR") == 0) {
            /* additionally read stop time */
            float stop;
            ss >> stop;
            ns3::Ptr<UnlimitedRateApp> app =
                ns3::CreateObject<UnlimitedRateApp> ();
            app->Setup(sockptr,
                    ns3::InetSocketAddress(rightleafifs.GetAddress(i),
                        port), pkgsize);
            leftleaves.Get(i)->AddApplication(app);
            app->SetStartTime(ns3::Seconds(start));
            app->SetStopTime(ns3::Seconds(stop));
        } else if (app.compare("LT") == 0) {
            /* additionally read maxtransfer */
            unsigned int maxtransfer;
            ss >> maxtransfer;
            ns3::Ptr<LimitedTransferApp> app =
                ns3::CreateObject<LimitedTransferApp> ();
            app->Setup(sockptr,
                    ns3::InetSocketAddress(rightleafifs.GetAddress(i),
                        port), pkgsize, maxtransfer);
            leftleaves.Get(i)->AddApplication(app);
            app->SetStartTime(ns3::Seconds(start));
        } else {
            std::cerr << "unknown app type: " << app << std::endl;
            exit(1);
        }
    }

    sinkApps.Start(ns3::Seconds(0.0));

    ns3::Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // connect to some trace sources
    ns3::Config::Connect("/NodeList/*/DeviceList/*/TxQueue/Drop",
            ns3::MakeCallback(&TxQueueDropTracer));
    ns3::Config::Connect("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx",
            ns3::MakeCallback(&PacketSinkRxTracer));
    ns3::Config::Connect("/NodeList/*/DeviceList/*/$ns3::PointToPointNetDevice/PhyRxDrop",
            ns3::MakeCallback(&PhyRxDropTracer));

    // pcap tracing
    if (pcaptracing)
        pointToPointLeaf.EnablePcapAll(argv[0], true);

    if (simstop > 0.0) {
        ns3::Simulator::Stop(ns3::Seconds(simstop));
    }
    ns3::Simulator::Run();

    std::cerr << "Dumbbell Left Bottleneck NodeID " <<
        routers.Get(0)->GetId() << std::endl;
    std::cerr << "Dumbbell Right Bottleneck NodeID " <<
        routers.Get(1)->GetId() << std::endl;
    for (uint32_t i = 0; i<number_of_clients; ++i) {
        std::cerr << "Dumbbell Left Leaf " << i << " NodeID " <<
            leftleaves.Get(i)->GetId() << " IP Addr " <<
            leftleafifs.GetAddress(i) << std::endl;
    }
    for (uint32_t i = 0; i<number_of_clients; ++i) {
        std::cerr << "Dumbbell Right Leaf " << i << " NodeID " <<
            rightleaves.Get(i)->GetId() << " IP Addr " << rightleafifs.
            GetAddress(i) << std::endl;
    }

    ns3::Simulator::Destroy();
    return 0;
}
