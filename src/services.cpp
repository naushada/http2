#ifndef __services_cpp__
#define __services_cpp__

#include "services.hpp"

Socket::Socket(const std::int32_t& _protocol, const bool& _blocking) {
    m_protocol = _protocol;
    m_blocking = _blocking;
}

Socket& Socket::createIPv4Socket() {
    m_ipv4 = true;
    switch (m_protocol)
        {
            case IPPROTO_TCP:
                (m_blocking == true) ? (m_handle = ::socket(AF_INET, SOCK_STREAM, m_protocol))
                                     : (m_handle = ::socket(AF_INET, (SOCK_STREAM | SOCK_NONBLOCK), m_protocol));
                break;
            case IPPROTO_UDP:
                (m_blocking == true) ? (m_handle = ::socket(AF_INET, SOCK_DGRAM, m_protocol))
                                     : (m_handle = ::socket(AF_INET, (SOCK_DGRAM | SOCK_NONBLOCK), m_protocol));
                break;

            default:
                break;
        }

    return(*this);
}

Socket& Socket::createIPv6Socket() {
    m_ipv4 = false;
    switch (m_protocol)
        {
            case IPPROTO_TCP:
                (m_blocking == true) ? (m_handle = ::socket(AF_INET6, SOCK_STREAM, m_protocol))
                                     : (m_handle = ::socket(AF_INET6, (SOCK_STREAM | SOCK_NONBLOCK), m_protocol));
                break;
            case IPPROTO_UDP:
                (m_blocking == true) ? (m_handle = ::socket(AF_INET6, SOCK_DGRAM, m_protocol))
                                     : (m_handle = ::socket(AF_INET6, (SOCK_DGRAM | SOCK_NONBLOCK), m_protocol));
                break;
            default:
                    break;
        }

    return(*this);
}

std::int32_t Socket::handle() const {
    return(m_handle);
}
void Socket::handle(std::int32_t _handle) {
    m_handle = _handle;
}
        
std::int32_t Socket::protocol() const {
    return(m_protocol);
}

bool Socket::ipv4() const {
    return(m_ipv4);
}
void Socket::ipv4(bool _ipv4) {
    m_ipv4 = _ipv4;
}

bool Socket::blocking() const {
    return(m_blocking);
}

void Socket::blocking(bool _blocking) {
    m_blocking = _blocking;
}

Socket::~Socket() {
    if(m_handle > 0) {
        ::close(m_handle);
    }
}

Client::Client(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, const std::string& _peerHost, const std::uint16_t& _peerPort,
               const std::string& _localHost, const std::uint16_t& _localPort): Socket(_protocol, _blocking) {
    peerHost(_peerHost);
    peerPort(_peerPort);
    localHost(_localHost);
    localPort(_localPort);
    blocking(_blocking);

    if(_ipv4) {
        createIPv4Socket();
    } else {
        createIPv6Socket();
    }
}

Client::Client(const std::int32_t& _handle, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, const std::string& _peerHost, const std::uint16_t& _peerPort,
               const std::string& _localHost, const std::uint16_t& _localPort): Socket(_protocol, _blocking) {
    Socket::handle(_handle);
    ipv4(_ipv4);
    peerHost(_peerHost);
    peerPort(_peerPort);
    localHost(_localHost);
    localPort(_localPort);
}

Client::Client(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, const std::string& _localHost, const std::uint16_t& _localPort): Socket(_protocol, _blocking) {
    ipv4(_ipv4);
    peerHost("0.0.0.0");
    peerPort(0);
    localHost(_localHost);
    localPort(_localPort);

    if(ipv4()) {
        createIPv4Socket();
    } else {
        createIPv6Socket();
    }
}

std::string Client::peerHost() const {
    return(m_peerHost);
}

std::string Client::localHost() const {
    return(m_localHost);
}

std::uint16_t Client::peerPort() const {
    return(m_peerPort);
}

std::uint16_t Client::localPort() const {
    return(m_localPort);
}

void Client::peerHost(std::string _host) {
    m_peerHost = _host;
}

void Client::localHost(std::string _host) {
    m_localHost = _host;
}

void Client::peerPort(std::uint16_t port) {
    m_peerPort = port;

}

void Client::localPort(std::uint16_t port) {
    m_localPort = port;
}

std::int32_t Client::connect() {
    std::int32_t ret = -1;

    if(ipv4()) {
        if(handle() > 0) {
            struct addrinfo *result;
            struct sockaddr_in peerAddr;
            auto s = getaddrinfo(peerHost().data(), std::to_string(peerPort()).c_str(), nullptr, &result);

            if (!s) {
                peerAddr = *((struct sockaddr_in*)(result->ai_addr));
                freeaddrinfo(result);
            }

            ret = ::connect(handle(), (struct sockaddr *)&peerAddr, sizeof(peerAddr));
            if(ret < 0) {
                // TODO:: Add Error log
                ret = errno;
            }
        }
    } else {
        if(handle() > 0) {
            struct addrinfo *result;
            struct sockaddr_in6 peerAddr6;
            auto s = getaddrinfo(peerHost().data(), std::to_string(peerPort()).c_str(), nullptr, &result);

            if (!s) {
                peerAddr6 = *((struct sockaddr_in6*)(result->ai_addr));
                freeaddrinfo(result);
            }

            ret = ::connect(handle(), (struct sockaddr *)&peerAddr6, sizeof(peerAddr6));
            if(ret < 0) {
                // TODO:: Add Error log
                ret = errno;        
            }
        }
    }
    return(ret);
}

std::int32_t Client::connectAsync() {
    std::int32_t ret = -1;

    if(blocking() && handle() > 0) {
        // Make the socket unblocking now.
        std::int32_t on = 1;
        ret = ::ioctl(handle(), FIONBIO, (char *)&on);
        if(ret < 0) {
            // TODO:: Error Handling
            return(ret);
        }
    }

    if(ipv4()) {
        if(handle() > 0) {
            struct addrinfo *result;
            struct sockaddr_in peerAddr;
            auto s = getaddrinfo(peerHost().data(), std::to_string(peerPort()).c_str(), nullptr, &result);

            if (!s) {
                peerAddr = *((struct sockaddr_in*)(result->ai_addr));
                freeaddrinfo(result);
            }

            ret = ::connect(handle(), (struct sockaddr *)&peerAddr, sizeof(peerAddr));
            if(ret < 0) {
                ret = errno;
                #if 0
                if(errno == EINPROGRESS) {
                    return(EINPROGRESS);
                } else if(errno == ECONNREFUSED) {
                    //Server is not strated yet
                    return(-1);
                } else {
                    std::cout << basename(__FILE__) <<":" << __LINE__ << " error:"<< std::strerror(errno) << std::endl;
                    return(-1);
                }
                #endif
                // TODO:: Add Error log        
            }
        }
    } else {
        if(handle() > 0) {
            struct addrinfo *result;
            struct sockaddr_in6 peerAddr6;
            auto s = getaddrinfo(peerHost().data(), std::to_string(peerPort()).c_str(), nullptr, &result);

            if (!s) {
                peerAddr6 = *((struct sockaddr_in6*)(result->ai_addr));
                freeaddrinfo(result);
            }

            ret = ::connect(handle(), (struct sockaddr *)&peerAddr6, sizeof(peerAddr6));
            if(ret < 0) {
                // TODO:: Add Error log
                ret = errno;
            }
        }
    }
    return(ret);
}

std::int32_t Client::rx(const std::int32_t& fd, std::string& out, const std::int32_t& len) {
    std::int32_t ret = -1;

    switch (protocol())
    {
        case IPPROTO_TCP:
        {
            std::string buffer;
            std::int32_t offset = 0;
            auto ret = ::recv(fd, (void *)buffer.data(), len - offset, 0);
            if(ret > 0) {
                buffer.resize(ret);
                out = buffer;
            } else if(!ret) {
                // TODO:: Add Error log
                out.clear();
                return(ret);
            }
        }
            break;
        
        case IPPROTO_UDP:
        {

            if(ipv4()) {

                struct sockaddr_in peerAddr;
                socklen_t slen = sizeof(peerAddr);

                auto ret = ::recvfrom(fd,(void *) out.data(), len, 0, (struct sockaddr *)&peerAddr, &slen);
                if(ret < 0) {
                    // TODO:: Add Error log        
                } else {
                    out.resize(ret);
                    peerPort(::ntohs(peerAddr.sin_port));
                    peerHost(::inet_ntoa(peerAddr.sin_addr));
                }

            } else {

                struct sockaddr_in6 peerAddr6;
                socklen_t slen6 = sizeof(peerAddr6);

                auto ret = ::recvfrom(handle(),(void *) out.data(), len, 0, (struct sockaddr *)&peerAddr6, &slen6);
                if(ret < 0) {
                    // TODO:: Add Error log        
                } else {
                    out.resize(ret);
                    peerPort(::ntohs(peerAddr6.sin6_port));
                    std::string ipv6Addr(reinterpret_cast<char*>(peerAddr6.sin6_addr.s6_addr), sizeof(peerAddr6.sin6_addr.s6_addr)*sizeof(std::uint8_t));
                    peerHost(ipv6Addr);
                }
            }
        }
            break;
        
        default:
            break;
    }

    return(ret);
}

std::int32_t Client::rx(std::string& out, const std::int32_t& len) {
    std::int32_t ret = -1;

    if(len < 0) {
        std::cout << basename(__FILE__) <<":"<<__FUNCTION__ <<":" <<__LINE__ <<" value of len:"<< len << std::endl;
        return(ret);
    }

    switch (protocol())
    {
        case IPPROTO_TCP:
        {
            std::stringstream ss;
            std::vector<std::uint8_t> buffer(len);
            std::int32_t fd = handle();
            ret = ::recv(fd, (void *)buffer.data(), len, 0);
            if(ret > 0) {
                buffer.resize(ret);
                ss.write(reinterpret_cast<char *>(buffer.data()), ret);
            } else if(!ret) {
                return(ret);
            } else {
                std::cout << basename(__FILE__) <<":"<< __FUNCTION__ <<":" <<__LINE__ <<" Erro on recv for channel:"<< handle() << std::strerror(errno) << std::endl;
            }
            if(!ss.str().empty()) {
                out.assign(ss.str());
                ret = ss.str().length();
            }
        }
            break;
        
        case IPPROTO_UDP:
        {

            if(ipv4()) {

                struct sockaddr_in peerAddr;
                socklen_t slen = sizeof(peerAddr);

                auto ret = ::recvfrom(handle(),(void *) out.data(), len, 0, (struct sockaddr *)&peerAddr, &slen);
                if(ret < 0) {
                    // TODO:: Add Error log        
                } else {
                    out.resize(ret);
                    peerPort(::ntohs(peerAddr.sin_port));
                    peerHost(::inet_ntoa(peerAddr.sin_addr));
                }

            } else {

                struct sockaddr_in6 peerAddr6;
                socklen_t slen6 = sizeof(peerAddr6);

                auto ret = ::recvfrom(handle(),(void *) out.data(), len, 0, (struct sockaddr *)&peerAddr6, &slen6);
                if(ret < 0) {
                    // TODO:: Add Error log        
                } else {
                    out.resize(ret);
                    peerPort(::ntohs(peerAddr6.sin6_port));
                    std::string ipv6Addr(reinterpret_cast<char*>(peerAddr6.sin6_addr.s6_addr), sizeof(peerAddr6.sin6_addr.s6_addr)*sizeof(std::uint8_t));
                    peerHost(ipv6Addr);
                }
            }
        }
            break;
        
        default:
            break;
    }

    return(ret);
}

std::int32_t Client::tx(const std::string& in) {
    std::int32_t ret = -1;
    std::int32_t len = in.length();
    switch (protocol())
    {
        case IPPROTO_TCP:
            if(handle() > 0) {

                std::int32_t offset = 0;
                do {
                    ret = ::send(handle(), (void *)(in.data() + offset), len - offset, 0);
                    if(ret > 0) {
                        offset += ret;
                    } else {
                        // TODO:: Add Error log
                        std::cout << basename(__FILE__) <<":"<< __FUNCTION__ << ":" << __LINE__ << "tx error ret:" << ret << std::endl;
                        break;
                    }
                } while(offset != len);

                ret = offset;
            }
            break;
        
        case IPPROTO_UDP:
        {
            if(ipv4()) {
                if(handle() > 0) {
                    struct addrinfo *result;
                    struct sockaddr_in peerAddr;
                    auto s = getaddrinfo(peerHost().data(), std::to_string(peerPort()).c_str(), nullptr, &result);

                    if (!s) {
                        peerAddr = *((struct sockaddr_in*)(result->ai_addr));
                        freeaddrinfo(result);
                    }

                    ret = ::sendto(handle(), in.data(), len, 0, (struct sockaddr *)&peerAddr, sizeof(peerAddr));
                    if(ret < 0) {
                        // TODO:: Add Error log        
                    }
                }
            } else {
                if(handle() > 0) {
                    struct addrinfo *result;
                    struct sockaddr_in6 peerAddr6;
                    auto s = getaddrinfo(peerHost().data(), std::to_string(peerPort()).c_str(), nullptr, &result);

                    if (!s) {
                        peerAddr6 = *((struct sockaddr_in6*)(result->ai_addr));
                        freeaddrinfo(result);
                    }

                    ret = ::sendto(handle(), in.data(), len, 0, (struct sockaddr *)&peerAddr6, sizeof(peerAddr6));
                    if(ret < 0) {
                        // TODO:: Add Error log        
                    }
                }
            }
        }
            break;
        
        default:
            break;
    }

    return(ret);
}

std::int32_t Client::onReceive(const std::string& out) {

}

Server::Server(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, const std::string& _localHost, const std::uint16_t& _localPort)
       : Client(_protocol, blocking, _ipv4, _localHost, _localPort) {

    bind();
    listen(_qsize);
}

Server::Server(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, const std::string& _localHost, const std::uint16_t& _localPort)
       : Client(_protocol, _blocking, _ipv4, _localHost, _localPort) {
    bind();
}

std::int32_t Server::listen(const std::int32_t& _qsize) {
    if(handle() > 0) {
        return(::listen(handle(), _qsize));
    }
    return(-1);
}

std::int32_t Server::bind() {
    std::int32_t ret = -1;

    if(ipv4()) {
        struct sockaddr_in selfAddr;
        struct addrinfo *result;

        auto s = getaddrinfo(localHost().data(), std::to_string(localPort()).c_str(), nullptr, &result);
        if (!s) {
            selfAddr = *((struct sockaddr_in*)(result->ai_addr));
            //std::cout << basename(__FILE__) <<":" << __LINE__ << " self address is FQDN" << std::endl;
            freeaddrinfo(result);
        }

        const int enable = 1;
        setsockopt(handle(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
        setsockopt(handle(), SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int));
    
        socklen_t len = sizeof(selfAddr);
        ret = ::bind(handle(), (struct sockaddr *)&selfAddr, len);
        if(ret < 0) {
            std::cout << basename(__FILE__) <<":"<< __FUNCTION__<<":" << __LINE__ << " bind failed error:"<< std::endl;
        }

    } else {

        struct sockaddr_in6 selfAddr;
        struct addrinfo *result;

        auto s = getaddrinfo(localHost().data(), std::to_string(localPort()).c_str(), nullptr, &result);
        if (!s) {
            selfAddr = *((struct sockaddr_in6*)(result->ai_addr));
            std::cout << basename(__FILE__) <<":"<<__FUNCTION__<<":" << __LINE__ << " self address is FQDN" << std::endl;
            freeaddrinfo(result);
        }

        socklen_t len = sizeof(selfAddr);
        ret = ::bind(handle(), (struct sockaddr *)&selfAddr, len);
        if(ret < 0) {
            //std::cout << basename(__FILE__) <<":" << __LINE__ << " bind failed error:"<< std::strerror(errno) << std::endl;
        }
    }

    return(ret);
}

std::int32_t Server::accept() {
    std::int32_t ret = -1;

    if(ipv4()) {
        std::int32_t newFd = -1;
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        newFd = ::accept(handle(), (struct sockaddr *)&addr, &addr_len);

        if(newFd > 0) {
            std::uint16_t PORT = ntohs(addr.sin_port);
            std::string IP(inet_ntoa(addr.sin_addr));
            std::shared_ptr<Client> client = std::make_shared<Client>(newFd, IPPROTO_TCP, true, true, IP, PORT);
            add_client(client);
            ret = newFd;
        }

    } else {
        std::int32_t newFd = -1;
        struct sockaddr_in6 addr;
        socklen_t addr_len = sizeof(addr);
        newFd = ::accept(handle(), (struct sockaddr *)&addr, &addr_len);

        if(newFd > 0) {
            std::uint16_t PORT = ntohs(addr.sin6_port);
            std::string IP(reinterpret_cast<char*>(addr.sin6_addr.s6_addr), sizeof(addr.sin6_addr));
            std::shared_ptr<Client> client = std::make_shared<Client>(newFd, IPPROTO_TCP, true, false, IP, PORT);
            add_client(client);
            ret = newFd;
        }
    }

    return(ret);
}

std::vector<std::pair<std::int32_t, std::shared_ptr<Client>>>& Server::clients() {
    return(m_clients);
}

bool Server::add_client(std::shared_ptr<Client> _client) {
    std::pair<std::int32_t, std::shared_ptr<Client>> clnt = std::make_pair(_client->handle(), _client);
    m_clients.push_back(clnt);
    return(true);
}

bool Server::remove_client(const std::int32_t& _fd) {
    auto clnt = get_client(_fd);
    clnt.reset();
    auto it = std::remove_if(m_clients.begin(), m_clients.end(),[&](auto &ent) -> bool {
        return(ent.first == _fd);
    });

    return(true);
}

std::shared_ptr<Client> Server::get_client(const std::int32_t& _fd) {

    auto it = std::find_if(m_clients.begin(), m_clients.end(), [&](auto& ent) -> bool {
        return(ent.first == _fd);
    });

    if(it != m_clients.end()) {
        return(it->second);
    }

    return(nullptr);
}

std::int32_t Server::onReceive(const std::string& out) {
    std::cout <<basename(__FILE__) <<":" << __FUNCTION__ << ":" << __LINE__<<" Server out:" << out << std::endl;
}

#endif /*__services_cpp__*/