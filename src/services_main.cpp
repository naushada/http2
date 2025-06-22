#ifndef __services_main_cpp__
#define __services_main_cpp__

#include <variant>
#include <vector>
#include <algorithm>
#include <cerrno>
#include <cstring>

#include "services_main.hpp"
#include "command_line_argument.hpp"

Services::Services(): m_epollFd(-1), m_notifierClient(nullptr), m_webServer(nullptr),
                      m_restClient(nullptr), m_appServer(nullptr), m_telemetryServer(nullptr) {
    if(m_epollFd < 0) {
        m_epollFd = ::epoll_create1(EPOLL_CLOEXEC);
    }
}

std::int32_t Services::handleDataFromConnectedClient(std::int32_t channel, ServiceType st, ServiceApplicationProtocolType sap,
                                                     ServiceTransportType stt, ServiceSecurityType sst) {
    std::shared_ptr<Client> clnt = nullptr;
    if(ServiceType::ServiceSignal == st) {
        std::string out;
        ::recv(channel, (void*)out.data(), 128, 0);
        exit(0);
    }

    switch(st) {
        case ServiceType::ServiceAppConnectedClient:
            clnt = appServer()->get_client(channel);
            break;
        case ServiceType::ServiceTelemetryConnectedClient:
            std::cout << basename(__FILE__) <<":" <<__FUNCTION__ <<":" << __LINE__
                      <<" From Telemetry Client on Fd:" << channel << " sst:" << std::to_string(sst) << std::endl;
            clnt = telemetryServer()->get_client(channel);
            break;
        case ServiceType::ServiceWebConnectedClient:
            clnt = webServer()->get_client(channel);
            break;
        case ServiceType::ServiceClient:
            clnt = restClient();
            break;
        case ServiceType::ServiceNotifier:
            clnt = notifierClient();
            break;
    }

    if(nullptr == clnt) {
        std::cout << basename(__FILE__) << ":" <<__FUNCTION__ <<":" << __LINE__ 
                  << " Unable to retrieve the client for Fd:" << channel << std::endl;
        return(-1);
    }

    std::string out;
    out.reserve(1024);
    std::stringstream ss;

    if(nullptr != clnt && ServiceSecurityType::SecurityNone == sst) {
        auto ret = clnt->rx(out);
        if(ret > 0) {
            out.resize(ret);
            std::cout << basename(__FILE__) <<":" << __FUNCTION__ <<":"<< __LINE__
                      <<":"<<" Received:\n"<< out << "\nlength:" << ret <<std::endl;
            Http ht(out);

            std::int32_t effectiveLength;

            if(!ht.value("Content-Length").empty()) {
                ///Content-Length Field is present.
                std::cout << basename(__FILE__) << ":" << __FUNCTION__ <<":"<< __LINE__<<":"
                          <<" Content-Length: "<<  std::stoi(ht.value("Content-Length")) 
                          <<" actual Length: " << ret << " header_length:" << ht.header().length() 
                          << std::endl;

                effectiveLength = (ht.header().length() + std::stoi(ht.value("Content-Length"))) - ret;
            }

            std::cout << basename(__FILE__) <<":" <<__FUNCTION__ <<":"<< __LINE__<<":"
                      <<" Effective Length:" << effectiveLength << std::endl;
            ss << out;

            std::int32_t offset = 0;
            while(offset != effectiveLength) {
                ret = clnt->rx(out, (effectiveLength-offset));
                if(ret > 0) {
                    out.resize(ret);
                    ss << out;
                    offset += ret;
                } else {
                    break;
                }
            }

            if(!ss.str().empty()) {
                out = ss.str();
                Http http(out);

                if((http.method() == "POST") || (http.method() == "GET")) {
                    if("/api/v1/notify/sos" == http.uri()) {
                        ///@brief Received from Command & COntrol Centre.
                    
                    } else if("/api/v1/notify/sos/clear" == http.uri()) {

                    } else if("/api/v1/telemetry/data" == http.uri()) {
                        if(restClient() && notifierClient()) {
                            ///@brief Received Telemetry Data from MQTT Client.
                            auto req = restClient()->buildHeader(HTTPClient::HTTPUriName::NotifyTelemetry, http.body());
                            auto len = notifierClient()->tx(req);
                            std::cout << basename(__FILE__) <<":" <<__FUNCTION__<<":" << __LINE__
                                      <<" Sent Telemetry Data to Command & Control Centre: " << req << std::endl;
                            ///@brief Build & send Response to Telemetry Client.
                            auto rsp = restClient()->buildResponse(std::string());
                            if(!rsp.empty()) {
                                clnt->tx(rsp);
                            }
                            std::cout <<basename(__FILE__) <<":"<<__FUNCTION__<<":" << __LINE__
                                      <<" Empty Response sent to Telemetry client: " << rsp << std::endl;
                        }
                    } else if("/api/v1/notify/location" == http.uri()) {
                        ///@brief Command & Control received location information.
                        std::cout <<basename(__FILE__)<<":"<<__FUNCTION__<<":" << __LINE__
                                  <<" Location Data Received:\n" << http.body() << std::endl;
                    } else if("/api/v1/notify/telemetry" == http.uri()) {
                        ///@brief Command & Control received telemetry data.
                        std::cout <<basename(__FILE__) <<":"<<__FUNCTION__<<":" << __LINE__
                                  <<" Received Telemetry Data: " << http.body() << std::endl;
                    }
                } else if(http.status_code() == "200") {
                    ///@brief This is an ACK.
                }
            }
        } else if(!ret) {
            std::cout << basename(__FILE__) <<":"<<__FUNCTION__ <<":"<< __LINE__<<":"
                      <<" Connected Client is closed: "<< std::endl;

            if(st == ServiceType::ServiceNotifier) {
                /// @brief Server is down or restarted.
                std::string peerHost = notifierClient()->peerHost();
                std::string localHost = notifierClient()->peerHost();
                std::uint16_t peerPort = notifierClient()->peerPort();
                std::uint16_t localPort = notifierClient()->localPort();
                deleteClient(channel, st);
                ///@brief Attempt to Connect to Command & Control Centre.
                createNotifierClient(IPPROTO_TCP, false, true, peerHost, peerPort, localHost, localPort);
            } else {
                /// @brief This is the case for running role=server and connected client is closed.
                deleteClient(channel, st);
            }
        } else {
            std::cout <<basename(__FILE__) <<":" <<__FUNCTION__ <<":"<< __LINE__<<":"
                      <<" App Client Error on channel: "<< channel << " error string->" << std::strerror(errno) << std::endl;
        }
    } else if(nullptr != clnt && ServiceSecurityType::TLS == sst && st == ServiceType::ServiceClient) {
        std::string request;
        std::size_t len = 1024;
        std::size_t actualLength = restClient()->tls()->read(request, len);
        std::stringstream ss;
        if(!actualLength) {
            /// @brief Peer has closed the connection
            /// @brief Server is down or restarted.
            std::string peerHost = restClient()->peerHost();
            std::string localHost = restClient()->peerHost();
            std::uint16_t peerPort = restClient()->peerPort();
            std::uint16_t localPort = restClient()->localPort();

            deleteClient(channel, st);
            ///@brief Attempt to Connect to Command & Control Centre.
            createRestClient(IPPROTO_TCP, true, true, peerHost, peerPort, localHost, localPort);
        } else {
            Http http(request);
            std::int32_t effectiveLength = http.header().length() - actualLength;
            if(http.value("Content-Length").length()) {
                ///Content-Length Field is present.
                effectiveLength = (http.header().length() + std::stoi(http.value("Content-Length"))) - actualLength;
            }

            ss << request;
            std::int32_t offset = 0;
            while(offset != effectiveLength) {
                len = restClient()->tls()->read(request, effectiveLength - offset);
                if(len > 0) {
                    ss << request;
                    offset += len;
                } else if(len < 0) {
                    ///Error handling
                    std::cout << basename(__FILE__)<<":" << basename(__FILE__) <<":" << __LINE__ 
                              << " Error recv failed" << std::endl;
                    break;
                }
            }

            restClient()->onReceive(ss.str());
            if(HTTPClient::HTTPUriName::GetChangeEventsNotification == restClient()->sentURI()) {
                ///@brief Build payload and send to Notifier Server.
                if(isConnected(ServiceType::ServiceNotifier)) {
                    auto notify = json::object();
                    notify = {
                        {"product", restClient()->model()},
                        {"endPoint", restClient()->serialNumber()},
                        {"latitude", restClient()->latitude()},
                        {"longitude", restClient()->longitude()}
                    };

                    auto req = restClient()->buildHeader(HTTPClient::HTTPUriName::NotifyLocation, notify.dump());
                    auto len = notifierClient()->tx(req);
                    std::cout << basename(__FILE__) <<":" <<__FUNCTION__<<":" << __LINE__
                              <<" Location Data sent to Command & Control\n"<< req << std::endl;
                }
            }
        }
    }
    return(0);
}

std::int32_t Services::handleClientConnection(std::int32_t handle, ServiceType st, ServiceApplicationProtocolType sap,
                                              ServiceTransportType stt, ServiceSecurityType sst, ConnectionStatus cs) {
    if(cs == ConnectionStatus::Inprogress) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);

        if(getpeername(handle, (struct sockaddr *)&peer, &peer_len)) {
            ///@brief Error...
            std::cout << basename(__FILE__) << ":"<<__FUNCTION__ <<":" << __LINE__ <<":"<< " getpeername failed: " << strerror(errno) << std::endl;
            if(ENOTCONN == errno) {
                //int so_error = -1;
                //socklen_t len = sizeof(so_error);
                //if(getsockopt(handle, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                //    std::cerr << "getsockopt failed: " << strerror(errno) << std::endl;
                    std::string peerHost = notifierClient()->peerHost();
                    std::string localHost = notifierClient()->peerHost();
                    std::uint16_t peerPort = notifierClient()->peerPort();
                    std::uint16_t localPort = notifierClient()->localPort();
                    std::cout << basename(__FILE__) << ":"<<__FUNCTION__ <<":" << __LINE__ <<":" << "Peer server: " << peerHost<<":" <<std::to_string(peerPort) 
                            << " is Down Attempting to Connect..." << std::endl;
                    deleteClient(handle, st);
                    ///@brief Attempt to Connect to Command & Control Centre.
                    if(st == ServiceType::ServiceNotifier) {
                        createNotifierClient(IPPROTO_TCP, false, true, peerHost, peerPort, localHost, localPort);
                    }
                    return(-1);
                //} else if(!so_error) {
                //    std::cout << basename(__FILE__) << ":"<<__FUNCTION__ <<":" << __LINE__ <<":" << "Notifier Client is connected" << std::endl;
                //    return(0);
                //}
            }
        } else {
            return(0);
        }
    }
    return(-2);
}

bool Services::isConnected(ServiceType st) {
    auto it = std::find_if(m_events.begin(), m_events.end(), [&](auto& ent) -> bool {
        return(st == (((ent.data.u64 & 0xFFFFFFFF) >> 24U) & 0xFF));
    });

    if(it != m_events.end()) {
        ConnectionStatus status = static_cast<ConnectionStatus>(it->data.u64 & 0xF);
        return(status == ConnectionStatus::Connected);
    }

    return(false);
}

std::int32_t Services::deleteClient(std::int32_t channel,ServiceType st) {
    if(channel < 0) {
        return(-1);
    }

    ::epoll_ctl(m_epollFd, EPOLL_CTL_DEL, channel, nullptr);
    auto it = std::remove_if(m_events.begin(), m_events.end(), [&](auto& ent) -> bool {
        return(channel == static_cast<std::int32_t>(((ent.data.u64 & 0xFFFFFFFF00000000) >> 32) & 0xFFFFFFFF));
    });

    switch (st)
    {
        case ServiceType::ServiceNotifier:
            m_notifierClient.reset();
            m_notifierClient = nullptr;
            break;
        case ServiceType::ServiceClient:
            m_restClient.reset();
            m_restClient = nullptr;
            break;
        case ServiceType::ServiceAppConnectedClient:
            appServer()->remove_client(channel);
            break;
        case ServiceType::ServiceWebConnectedClient:
            webServer()->remove_client(channel);
            break;
        case ServiceType::ServiceTelemetryConnectedClient:
            telemetryServer()->remove_client(channel);
            break;

        default:
            break;
    }
    return(0);
}

std::int32_t Services::handleIO(std::int32_t channel, ServiceType st, ServiceApplicationProtocolType sap, ServiceTransportType stt, ServiceSecurityType sst) {
    std::string out;
    if(ServiceType::ServiceWebServer == st) {
        /// @brief New Connection , accept it.
        std::int32_t Fd = webServer()->accept();
        if(Fd > 0) {
            struct epoll_event evt;
            evt.events = EPOLLIN;
            evt.data.u64 = (((static_cast<std::uint64_t>(Fd & 0xFFFFFFFFU)) << 32U) |
                              static_cast<std::uint64_t>(((ServiceType::ServiceWebConnectedClient & 0xFFU) << 24U) |
                                                         ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                         ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                         (((ServiceTransportType::TCP & 0xF) << 4U) |
                                                           (ConnectionStatus::ConnectionNone & 0xF)));
            ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, Fd, &evt);
            m_events.push_back(evt);
            std::cout << basename(__FILE__)<<":" << __FUNCTION__ <<":"<< __LINE__<<":" 
                      <<" New Notifier is connected on channel:" << Fd << std::endl;
        }
    } else if(ServiceType::ServiceAppServer == st) {
        /// @brief New Connection , accept it.
        std::int32_t Fd = appServer()->accept();
        if(Fd > 0) {
            struct epoll_event evt;
            evt.events = EPOLLIN;
            evt.data.u64 = (((static_cast<std::uint64_t>(Fd & 0xFFFFFFFFU)) << 32U) |
                              static_cast<std::uint64_t>(((ServiceType::ServiceAppConnectedClient & 0xFFU) << 24U) |
                                                         ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                         ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                         (((ServiceTransportType::TCP & 0xF) << 4U) |
                                                           (ConnectionStatus::ConnectionNone & 0xF)));
            ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, Fd, &evt);
            m_events.push_back(evt);
            std::cout << basename(__FILE__) <<":"<< __FUNCTION__ <<":"<< __LINE__<<":" 
                      <<" New App Client is connected on channel:" << Fd << std::endl;
        }
    } else if(ServiceType::ServiceTelemetryServer == st) {
        /// @brief New Connection , accept it.
        std::int32_t Fd = telemetryServer()->accept();
        if(Fd > 0) {
            struct epoll_event evt;
            evt.events = EPOLLIN;
            evt.data.u64 = (((static_cast<std::uint64_t>(Fd & 0xFFFFFFFFU)) << 32U) |
                              static_cast<std::uint64_t>(((ServiceType::ServiceTelemetryConnectedClient & 0xFFU) << 24U) |
                                                         ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                         ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                         (((ServiceTransportType::TCP & 0xF) << 4U) |
                                                           (ConnectionStatus::ConnectionNone & 0xF)));
            ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, Fd, &evt);
            m_events.push_back(evt);
            std::cout << basename(__FILE__)<<":" <<__FUNCTION__ <<":"<< __LINE__<<":" 
                      <<" Telemetry Client is connected on channel:" << Fd << std::endl;
        }
    } else {
        handleDataFromConnectedClient(channel, st, sap, stt, sst);
    }
    return(0);
}

std::int32_t Services::createWebServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                                        const std::string& _localHost, const std::uint16_t& _localPort) {
    m_webServer = std::make_shared<HTTPServer>(_qsize,_protocol,_blocking, _ipv4, _localHost, _localPort);
    std::int32_t channel = m_webServer->handle();
    if(channel > 0) {
        struct epoll_event evt;
        evt.events = EPOLLHUP | EPOLLIN;
        evt.data.u64 = (((static_cast<std::uint64_t>(channel & 0xFFFFFFFFU)) << 32U) |
                          static_cast<std::uint64_t>(((ServiceType::ServiceWebServer & 0xFFU) << 24U) |
                                                     ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                     ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                     (((ServiceTransportType::TCP & 0xF) << 4U) |
                                                       (ConnectionStatus::ConnectionNone & 0xF)));
        ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, channel, &evt);
        m_events.push_back(evt);
    }
    return(0);
}

std::int32_t Services::createTelemetryServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                                             const std::string& _localHost, const std::uint16_t& _localPort) {
    m_telemetryServer = std::make_shared<HTTPServer>(_qsize,_protocol,_blocking, _ipv4, _localHost, _localPort);
    std::int32_t channel = m_telemetryServer->handle();

    if(channel > 0) {
        struct epoll_event evt;
        evt.events = EPOLLHUP | EPOLLIN;
        evt.data.u64 = (((static_cast<std::uint64_t>(channel & 0xFFFFFFFFU)) << 32U) |
                          static_cast<std::uint64_t>(((ServiceType::ServiceTelemetryServer & 0xFFU) << 24U) |
                                                     ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                     ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                     (((ServiceTransportType::TCP & 0xF) << 4U) |
                                                       (ConnectionStatus::ConnectionNone & 0xF)));
        ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, channel, &evt);
        m_events.push_back(evt);
    }
    return(0);
}

std::int32_t Services::createAppServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                                           const std::string& _localHost, const std::uint16_t& _localPort) {
    m_appServer = std::make_shared<HTTPServer>(_qsize,_protocol,_blocking, _ipv4, _localHost, _localPort);
    std::int32_t channel = m_appServer->handle();
    if(channel > 0) {
        struct epoll_event evt;
        evt.events = EPOLLHUP | EPOLLIN;
        evt.data.u64 = (((static_cast<std::uint64_t>(channel & 0xFFFFFFFFU)) << 32U) |
                          static_cast<std::uint64_t>(((ServiceType::ServiceAppServer & 0xFFU) << 24U) |
                                                     ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                     ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                     (((ServiceTransportType::TCP & 0xF) << 4U) |
                                                       (ConnectionStatus::ConnectionNone & 0xF)));
        ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, channel, &evt);
        m_events.push_back(evt);
    }
    return(0);
}

std::int32_t Services::createNotifierClient(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                                        const std::string& _peerHost, const std::uint16_t& _peerPort, const std::string& _localHost, const std::uint16_t& _localPort) {
    m_notifierClient = std::make_shared<HTTPClient>(_protocol, _blocking, _ipv4, _peerHost, _peerPort, _localHost, _localPort);
    
    std::int32_t conErr =  notifierClient()->connect();
    struct epoll_event evt;
    Services::ConnectionStatus cs=Services::ConnectionStatus::ConnectionNone;
    if(!conErr) {
        std::cout << basename(__FILE__) <<":"<< __FUNCTION__ <<":"<< __LINE__<<":"
                  <<" Connected to Notifier peer->" << notifierClient()->peerHost() << ":" << notifierClient()->peerPort() << std::endl;
        evt.events = EPOLLHUP | EPOLLIN;
        cs=Services::ConnectionStatus::Connected;
    } else if(conErr == EINPROGRESS) {
        std::cout << basename(__FILE__) <<":" <<__FUNCTION__ <<":"<< __LINE__<<":"
                  <<" Connecting... to Notifier peer->" << notifierClient()->peerHost() << ":" << notifierClient()->peerPort() << std::endl;
        evt.events = EPOLLHUP | EPOLLOUT;
        cs=Services::ConnectionStatus::Inprogress;
    } else {
        std::cout << basename(__FILE__) <<":" << __FUNCTION__ <<":"<< __LINE__<<":"
                  <<" Error... to Notifier peer->" << notifierClient()->peerHost() << ":" << notifierClient()->peerPort() << std::endl;
    }

    std::int32_t channel = notifierClient()->handle();
        
    evt.data.u64 = (((static_cast<std::uint64_t>(channel & 0xFFFFFFFFU)) << 32U) |
                      static_cast<std::uint64_t>(   ((ServiceType::ServiceNotifier & 0xFFU) << 24U) |
                                                    ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                    ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                  ( ((ServiceTransportType::TCP & 0xF) << 4U) |
                                                     (cs & 0xF)));
        
    ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, channel, &evt);
    m_events.push_back(evt);

#if 0
    /// @brief Add inotify for Telemetry events.
    m_iFd = inotify_init();
    m_inotifyList = inotify_add_watch(m_iFd, "/tmp/telemetry", (IN_MODIFY | IN_CREATE | IN_DELETE));
    std::cout <<__FUNCTION__ <<":" << __LINE__ << "m_iFd:" << m_iFd << std::endl;
    evt.data.u64 = (((static_cast<std::uint64_t>(m_iFd & 0xFFFFFFFFU)) << 32U) |
                      static_cast<std::uint64_t>(((ServiceType::ServiceNotifier & 0xFFU) << 24U) |
                                                  ((ServiceApplicationProtocolType::File & 0xFFU) << 16U) |
                                                  ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                   (ServiceTransportType::TCP & 0xFF));
    evt.events = EPOLLIN;          
    ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_iFd, &evt);
    m_events.push_back(evt);
#endif
    return(0);
}

std::int32_t Services::createRestClient(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                                        const std::string& _peerHost, const std::uint16_t& _peerPort, const std::string& _localHost, const std::uint16_t& _localPort) {
    m_restClient = std::make_shared<HTTPClient>(_protocol, _blocking, _ipv4, _peerHost, _peerPort, _localHost, _localPort);
    std::int32_t conErr =  restClient()->connect();
    struct epoll_event evt;

    //if(EINPROGRESS !=conErr) {
    if(!conErr) {
        std::cout << basename(__FILE__) <<":"<<__FUNCTION__ <<":"<< __LINE__<<":"
                  <<" Connected to peer->" << restClient()->peerHost() << ":" << restClient()->peerPort() << std::endl;
        /// @brief -- Use TLS now.
        restClient()->tls()->init(restClient()->handle());
        /// @brief initiate TLS handshake now.
        restClient()->tls()->client();
        /// @brief Get the AUTH Token from REST Server.
        //auto req = restClient()->buildGetTokenRequest(userid(), password());
        auto req = restClient()->buildGetTokenRequest("user", "Pin@411048");
        std::cout << "REQ:"<<std::endl << req << std::endl;
        if(!req.empty()) {
            auto len = restClient()->tls()->write(req, req.length());
            std::cout << basename(__FILE__) <<":" << __FUNCTION__ <<":"<<__LINE__
                      <<" Sent to REST Server len:" << len << std::endl;
            restClient()->sentURI(HTTPClient::GetTokenForSession);
        }
        evt.events = EPOLLHUP | EPOLLIN;
    } else {
        std::cout << basename(__FILE__) <<":"<<__FUNCTION__ <<":"<< __LINE__<<":"
                  <<" Connecting... to peer->" << restClient()->peerHost() << ":" << restClient()->peerPort() << std::endl;
        evt.events = EPOLLHUP | EPOLLOUT;
    }

    std::int32_t channel = restClient()->handle();
        
    evt.data.u64 = (((static_cast<std::uint64_t>(channel & 0xFFFFFFFFU)) << 32U) |
                      static_cast<std::uint64_t>( ((ServiceType::ServiceClient & 0xFFU) << 24U) |
                                                  ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                  ((ServiceSecurityType::TLS & 0xFFU) << 8U)) |
                                                ( ((ServiceTransportType::TCP & 0xF) << 4U) |
                                                   (ConnectionStatus::ConnectionNone & 0xF)));

    ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, channel, &evt);
    m_events.push_back(evt);
    return(0);
}

Services& Services::init() {
    /// @brief Adding Signal Processing.
    sigemptyset(&m_mask);
    sigaddset(&m_mask, SIGINT);
    sigaddset(&m_mask, SIGQUIT);
    sigaddset(&m_mask, SIGHUP|SIGTERM|SIGTSTP);
    
    sigprocmask(SIG_BLOCK, &m_mask, NULL);
    
    std::int32_t sfd = signalfd(-1, &m_mask, SFD_NONBLOCK);
    if(sfd > 0) {
        struct epoll_event evt;
        evt.events = EPOLLHUP | EPOLLIN;
        evt.data.u64 = (((static_cast<std::uint64_t>(sfd & 0xFFFFFFFFU)) << 32U) |
                          static_cast<std::uint64_t>( ((ServiceType::ServiceSignal & 0xFFU) << 24U) |
                                                      ((ServiceApplicationProtocolType::ProtocolInvalid & 0xFFU) << 16U) |
                                                      ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                     (((ServiceTransportType::TransportInvalid & 0xF) << 4U) |
                                                       (ConnectionStatus::ConnectionNone & 0xF)));
        ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, sfd, &evt);
        m_events.push_back(evt);
    }

    return(*this);
}

Services& Services::start() {
    std::vector<struct epoll_event> events;
    bool infinite = true;
#if 0
    if(nullptr != httpClient()) {
        std::int32_t conErr =  httpClient()->connectAsync();
        std::cout << " Connecting to peer->" << httpClient()->peerHost() << ":" << httpClient()->peerPort() << std::endl;
        if(EINPROGRESS ==conErr) {
            struct epoll_event evt;
            std::int32_t channel = httpClient()->handle();
            struct epoll_event evt;
            evt.events = EPOLLHUP | EPOLLOUT;
            evt.data.u64 = (((static_cast<std::uint64_t>(channel & 0xFFFFFFFFU)) << 32U) |
                            static_cast<std::uint64_t>(((ServiceType::ServiceClient & 0xFFU) << 24U) |
                                                        ((ServiceApplicationProtocolType::REST & 0xFFU) << 16U) |
                                                        ((ServiceSecurityType::SecurityNone & 0xFFU) << 8U)) |
                                                        (ServiceTransportType::TCP & 0xFF));
            ::epoll_ctl(m_epollFd, EPOLL_CTL_ADD, channel, &evt);
            m_events.push_back(evt);
        }
    }
#endif

    while(infinite) {
        events.resize(m_events.size());
        auto eventCount = ::epoll_wait(m_epollFd, events.data(), events.size(), 2000);

        if(!eventCount) {
            /// @brief This is a period of inactivity.
        } else if(eventCount > 0) {
            ///event is received.
            events.resize(eventCount);

            for(const auto& event: events) {
                struct epoll_event ent = event;
                auto elm = ent.data.u64;

                auto handle = (elm >> 32) & 0xFFFFFFFFU;
                ServiceType st = static_cast<ServiceType>((elm & 0xFF000000U) >> 24U);
                ServiceApplicationProtocolType sap = static_cast<ServiceApplicationProtocolType>((elm & 0x00FF0000U) >> 16U);
                ServiceSecurityType sst = static_cast<ServiceSecurityType>((elm & 0x0000FF00U) >> 8U);
                ServiceTransportType stt = static_cast<ServiceTransportType>((elm & 0x000000F0U) >> 4U);
                ConnectionStatus cs = static_cast<ConnectionStatus>(elm & 0x0000000FU);

                std::cout << basename(__FILE__)<< ":" << __LINE__ << " channel:" << handle << " ServiceType:"
                          << std::to_string(st) << " ServiceApplicationProtocolType:" << std::to_string(sap) << " ServiceTransportType:" << std::to_string(stt) 
                          << " ServiceSecurityType: " << std::to_string(sst) 
                          << " ConnectionStatus: " << std::to_string(cs)
                          << std::endl;

                if(ServiceType::ServiceSignal == st) {
                    std::cout <<__FUNCTION__ <<":"<< __LINE__<<":"<<"Signal is received" << std::endl;
                    infinite = false;
                }

                
                #if 0
                if(ent.events & EPOLLHUP) {
                    ///connection is closed by peer and read on socket will return 0 byte.
                    if(ServiceType::ServiceClient == st || ServiceType::ServiceNotifier == st) {
                        std::cout << basename(__FILE__) << ":" << __FUNCTION__ <<":" << __LINE__ <<":" << " EPOLLHUP is received" <<std::endl;
                        deleteClient(handle,st);
                    }
                }
                #endif

                if(ent.events & EPOLLIN) {
                    //std::cout << "ent.events: EPOLLIN" << std::endl;
                    handleIO(handle, st, sap, stt, sst);
                } else if(/*(ent.events & EPOLLERR) || */(ent.events & EPOLLHUP)) {
                    ///Error on socket.
                    std::cout << basename(__FILE__) <<":" <<__FUNCTION__ <<":"<< __LINE__<<":"
                              <<" ent.events: EPOLLHUP" << std::endl;
                    handleClientConnection(handle, st, sap, stt, sst, cs);
                } else if(ent.events & EPOLLOUT) {
                    std::cout <<basename(__FILE__) <<":"<< __LINE__<<":"<<" ent.events: EPOLLOUT" << std::endl;
                    if(!handleClientConnection(handle, st, sap, stt, sst, cs)) {
                        if(ServiceType::ServiceClient == st) {
                            std::cout << basename(__FILE__) <<":" <<__FUNCTION__ <<":"<< __LINE__<<":"
                                      <<" Connected to REST Server" << std::endl;
                            ent.events = EPOLLHUP | EPOLLIN;
                            ::epoll_ctl(m_epollFd, EPOLL_CTL_MOD, handle, &ent);
                        } else if(ServiceType::ServiceNotifier == st) {
                            std::cout << basename(__FILE__) <<":"<<__FUNCTION__ <<":"<< __LINE__<<":"
                                      <<" Connected to Notifier Server" << std::endl;
                            cs = ConnectionStatus::Connected;
                            ent.data.u64 = ((elm & 0xFFFFFFFFFFFFFFF0) | (cs & 0x0F)); 
                            ent.events = EPOLLHUP|EPOLLIN;
                            ::epoll_ctl(m_epollFd, EPOLL_CTL_MOD, handle, &ent);
                            auto notify = json::object();

                            /* send last known location to CnC - Command And Control */
                            if(nullptr != restClient()) {
                                notify = {
                                    {"product", restClient()->model()},
                                    {"endPoint", restClient()->serialNumber()},
                                    {"latitude", restClient()->latitude()},
                                    {"longitude", restClient()->longitude()}
                                };

                                auto req = restClient()->buildHeader(HTTPClient::HTTPUriName::NotifyLocation, notify.dump());
                                auto len = notifierClient()->tx(req);
                                std::cout << basename(__FILE__) <<":" <<__FUNCTION__<<":" << __LINE__
                                        <<" Location Data sent to Command & Control\n"<< req << std::endl;
                            }
                        }
                    }
                } else if(ent.events & EPOLLET) {
                    std::cout << basename(__FILE__) <<":" <<__FUNCTION__ <<":"<< __LINE__<<":"
                              <<" ent.events: EPOLLET" << std::endl;
                }
            }
        }
    }

    return(*this);
}

Services& Services::stop() {
    if(m_notifierClient) {
        m_notifierClient.reset();
    }
    if(m_webServer) {
        m_webServer.reset();
    }
    if(m_appServer) {
        m_appServer.reset();
    }
    if(m_telemetryServer) {
        m_telemetryServer.reset();
    }

    if(m_restClient) {
        m_restClient.reset();
    }
    return(*this);
}

Services::~Services() {
    inotify_rm_watch(m_iFd, m_inotifyList);
}

std::shared_ptr<HTTPServer> Services::webServer() const {
    return(m_webServer);
}

std::shared_ptr<HTTPServer> Services::telemetryServer() const {
    return(m_telemetryServer);
}

std::shared_ptr<HTTPServer> Services::appServer() const {
    return(m_appServer);
}

std::shared_ptr<HTTPClient> Services::notifierClient() const {
    return(m_notifierClient);
}

std::shared_ptr<HTTPClient> Services::restClient() const {
    return(m_restClient);
}

void Services::userid(std::string uid) {
    m_userid = uid;
}

void Services::password(std::string pwd) {
    m_password = pwd;
}

std::string Services::userid() const {
    return(m_userid);
}

std::string Services::password() const {
    return(m_password);
}

int main(std::int32_t argc, char* argv[]) {
    Services svcInst;
    std::string out;
    std::uint16_t port;
    Value value;
    CommandLineArgument options(argc, argv);
    if(options.getValue("role", value) && value.getString(out) && !out.empty()) {

        if(!out.compare("client") && options.getValue("peer-host", value) && value.getString(out) && !out.empty()) {

            options.getValue("peer-port", value);
            value.getUint16(port);
            std::cout << "peer-host:" << out << " peer-port:" << std::to_string(port) << std::endl;
            svcInst.createNotifierClient(IPPROTO_TCP, false, true, out, port, "0.0.0.0", 0);
            svcInst.createRestClient(IPPROTO_TCP, true, true, "192.168.1.1", 443, "0.0.0.0", 0);
            options.getValue("local-host", value);
            value.getString(out);
            options.getValue("local-port", value);
            value.getUint16(port);
            svcInst.createAppServer(10, IPPROTO_TCP, true, true, out, port);
            svcInst.createTelemetryServer(10, IPPROTO_TCP, true, true, out, 28989);

            if(options.getValue("userid", value) && value.getString(out)) {
                svcInst.userid(out);
            }

            if(options.getValue("password", value) && value.getString(out)) {
                svcInst.password(out);
            }

        } else if(!out.compare("server") && options.getValue("local-host", value) && value.getString(out) && !out.empty()) {

            options.getValue("local-port", value);
            value.getUint16(port);
            std::cout << basename(__FILE__) <<":" << __FUNCTION__ <<":"<<__LINE__<<":"<< "local-host:" << out << " local-port:" << std::to_string(port) << std::endl;
            svcInst.createWebServer(10, IPPROTO_TCP, true, true, out, port);

        } else if(!out.compare("both")) {


        } else {
            /// @brief TODO:
        }
    }
    
    svcInst.init().start().stop();

    return(0);
}


#endif /*__services_main_cpp__*/