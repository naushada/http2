#ifndef __services_main_hpp__
#define __services_main_hpp__

#include <memory>
#include <unordered_map>

#include "services_http.hpp"
#include "json.hpp"
#include <fstream>
#include <iostream>

extern "C" {
    #include <sys/epoll.h>
    #include <getopt.h>
    #include <sys/signalfd.h>
    #include <signal.h>
    #include <sys/inotify.h>
}

using json = nlohmann::json;

class Services {
    public:
        enum ServiceType:std::uint8_t {
            ServiceWebServer=0,
            ServiceAppServer,
            ServiceTelemetryServer,
            ServiceWebConnectedClient,
            ServiceAppConnectedClient,
            ServiceTelemetryConnectedClient,
            ServiceClient,
            ServiceTimer,
            ServiceSignal,
            ServiceNotifier,
            ServiceInvalid
        };
        
        enum ServiceApplicationProtocolType:std::uint8_t {REST=0, LwM2M=1, File=2, ProtocolInvalid=3};
        enum ServiceTransportType:std::uint8_t {TCP=0, UDP=1, TransportInvalid=2};
        enum ServiceSecurityType:std::uint8_t {TLS=0, DTLS=1, SecurityNone=2};
        enum ConnectionStatus:std::uint8_t {Inprogress=0, Connected=1, ConnectionNone=2};

        Services();
        Services& init();
        Services& start();
        Services& stop();
        std::int32_t handleDataFromConnectedClient(std::int32_t channel, ServiceType st, ServiceApplicationProtocolType sap, ServiceTransportType stt, ServiceSecurityType sst);
        std::int32_t handleClientConnection(std::int32_t handle, ServiceType st, ServiceApplicationProtocolType sap, ServiceTransportType stt, ServiceSecurityType sst, ConnectionStatus cs);
        std::int32_t handleIO(std::int32_t handle, ServiceType st, ServiceApplicationProtocolType sap, ServiceTransportType stt, ServiceSecurityType sst);
        virtual ~Services();

        std::int32_t createWebServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                    const std::string& _localHost, const std::uint16_t& _localPort);
        
        std::int32_t createTelemetryServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                    const std::string& _localHost, const std::uint16_t& _localPort);
        
        std::int32_t createAppServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                    const std::string& _localHost, const std::uint16_t& _localPort);

        std::int32_t createNotifierClient(const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, 
                 const std::string& _peerHost, const std::uint16_t& _peerPort, const std::string& _localHost, const std::uint16_t& _localPort);

        std::int32_t createRestClient(const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, 
                 const std::string& _peerHost, const std::uint16_t& _peerPort, const std::string& _localHost, const std::uint16_t& _localPort);

        std::int32_t deleteClient(std::int32_t channel, ServiceType st);
        bool isConnected(ServiceType st);
        std::shared_ptr<HTTPServer> webServer() const;
        std::shared_ptr<HTTPServer> appServer() const;
        std::shared_ptr<HTTPClient> notifierClient() const;
        std::shared_ptr<HTTPClient> restClient() const;
        std::shared_ptr<HTTPServer> telemetryServer() const;
        void userid(std::string uid);
        void password(std::string pwd);
        std::string userid() const;
        std::string password() const;

    private:
        std::int32_t m_epollFd;
        std::shared_ptr<HTTPServer> m_telemetryServer;
        std::shared_ptr<HTTPServer> m_webServer;
        std::shared_ptr<HTTPServer> m_appServer;
        std::shared_ptr<HTTPClient> m_notifierClient;
        std::shared_ptr<HTTPClient> m_restClient;
        std::vector<struct epoll_event> m_events;
        sigset_t m_mask;
        std::string m_userid;
        std::string m_password;
        std::int32_t m_inotifyList;
        std::int32_t m_iFd;
};








#endif /*__services_main_hpp__*/