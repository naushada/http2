#ifndef __services_hpp__
#define __services_hpp__

#include <iostream>
#include <vector>
#include <sstream>
#include <memory>
#include <algorithm>
#include <string>
#include <cerrno>
#include <cstring>

extern "C" {
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/epoll.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <netdb.h>
    #include <stdio.h>
    #include <stdarg.h> 
    #include <sys/timerfd.h>
    #include <time.h>

}

class Socket {
    public:
        /// @brief 
        /// @param _protocol 
        /// @param isBlocking 
        Socket(const std::int32_t& _protocol, const bool& isBlocking=true);
        Socket& createIPv4Socket();
        Socket& createIPv6Socket();
        std::int32_t handle() const;
        std::int32_t protocol() const;
        bool ipv4() const;
        bool blocking() const;
        virtual ~Socket();
        void handle(std::int32_t _handle);
        void ipv4(bool _ipv4);
        void blocking(bool _blocking);

    private:
        std::int32_t m_handle;
        std::int32_t m_protocol;
        bool m_blocking;
        bool m_ipv4;
};

class Client: public Socket {
    public:
        /// @brief 
        /// @param _protocol 
        /// @param blocking 
        /// @param ipv4 
        /// @param peerHost 
        /// @param peerPort 
        /// @param localHost 
        /// @param localPort 
        Client(const std::int32_t& _protocol, const bool& blocking, const bool& ipv4, const std::string& peerHost, const std::uint16_t& peerPort,
               const std::string& localHost, const std::uint16_t& localPort);

        /// @brief 
        /// @param _handle 
        /// @param _protocol 
        /// @param blocking 
        /// @param _ipv4 
        /// @param _peerHost 
        /// @param _peerPort 
        /// @param _localHost 
        /// @param _localPort 
        Client(const std::int32_t& _handle, const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, const std::string& _peerHost, const std::uint16_t& _peerPort,
               const std::string& _localHost="0.0.0.0", const std::uint16_t& _localPort=0);

        /// @brief 
        /// @param _protocol 
        /// @param blocking 
        /// @param _ipv4 
        /// @param _localHost 
        /// @param _localPort 
        Client(const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, const std::string& _localHost, const std::uint16_t& _localPort);

        virtual ~Client() = default;
        Client() = delete;

        std::string peerHost() const;
        std::string localHost() const;
        std::uint16_t peerPort() const;
        std::uint16_t localPort() const;
        void peerHost(std::string _host);
        void localHost(std::string _host);
        void peerPort(std::uint16_t port);
        void localPort(std::uint16_t port);
        std::int32_t connect();
        std::int32_t connectAsync();

        /// @brief This provides the default implementation and can be overridden by subclass.
        /// @param out 
        /// @param len 
        /// @return

        std::int32_t rx(std::string& out, const std::int32_t& len=1024);
        /// @brief 
        /// @param in 
        /// @param len 
        /// @return
        std::int32_t rx(const std::int32_t& fd, std::string& out, const std::int32_t& len=1024);
        std::int32_t tx(const std::string& in);
        virtual std::int32_t onReceive(const std::string& out);

    private:
        std::string m_peerHost;
        std::uint16_t m_peerPort;
        std::string m_localHost;
        std::uint16_t m_localPort;
};

class Server: public Client {
    public:
        /// @brief 
        /// @param _qsize 
        /// @param _protocol 
        /// @param blocking 
        /// @param _ipv4 
        /// @param _localHost 
        /// @param _localPort 
        Server(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, const std::string& _localHost="0.0.0.0", const std::uint16_t& _localPort=0);
    
        /// @brief 
        /// @param _protocol 
        /// @param blocking 
        /// @param _ipv4 
        /// @param _localHost 
        /// @param _localPort 
        Server(const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, const std::string& _localHost="0.0.0.0", const std::uint16_t& _localPort=0);
        /// @brief 
        virtual ~Server() = default;
        /// @brief 
        Server() = delete;

        std::int32_t listen(const std::int32_t& _qsize);
        std::int32_t bind();
        std::int32_t accept();
        bool add_client(std::shared_ptr<Client> _client);
        bool remove_client(const std::int32_t& _fd);
        std::shared_ptr<Client> get_client(const std::int32_t& _fd);
        std::vector<std::pair<std::int32_t, std::shared_ptr<Client>>>& clients();
        virtual std::int32_t onReceive(const std::string& out);

    private:
        std::vector<std::pair<std::int32_t, std::shared_ptr<Client>>> m_clients;
};




#endif /*__services_hpp__*/