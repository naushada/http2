#ifndef __services_http_cpp__
#define __services_http_cpp__

#include "services_http.hpp"

HTTPServer::HTTPServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, const std::string& _localHost, const std::uint16_t& _localPort)
            : Server(_qsize, _protocol, _blocking, _ipv4, _localHost, _localPort) {

}

HTTPServer::~HTTPServer() {

}

std::string HTTPServer::buildHeader(const std::string& path, const std::string& payload) {
    std::stringstream ss;
    std::string method = "POST";

    if(payload.empty()) {
        method.assign("GET");
    }

    ss << method <<" " << path << " HTTP/1.1\r\n"
       << "Host: " << "192.168.1.1" << ":" << std::to_string(443) << "\r\n"
       << "User-Agent: " << "Embedded" << "\r\n"
       << "Connection: keep-alive\r\n"
       << "Accept: */*\r\n" 
       << "Accept-Encoding: gzip, deflate\r\n"
       << "Accept-Language: en-US,en;q=0.9\r\n";
    
    if(!method.compare(0, 4, "POST")) {
        ss << "Content-Type: application/vnd.api+json\r\n"
           << "Content-Length: " << payload.length() << "\r\n"
           //delimeter for body.
           << "\r\n"
           << payload;
    } else {
        //delimeter for body.
        ss  << "\r\n";
    }

    return(ss.str());
}

std::int32_t HTTPServer::onReceive(const std::string& out) {
    std::cout << __FUNCTION__ <<":" << __LINE__ << "request:" << out << std::endl;
    if(!out.empty()) {
        Http http(out);
        if("/api/v1/notify/sos" == http.uri()) {
            
        } else if("/api/v1/notify/location" == http.uri()) {
            if(!http.body().empty()) {
                json ent = json::parse(http.body());
                if(ent.is_object() && ent["endPoint"].is_string()) {
                    entry(ent["endPoint"].get<std::string>(), http.body());
                }
            }
        } else if("/api/v1/notify/sos/clear" == http.uri()) {

        }
    }
    return(0);
}

HTTPClient::HTTPClient(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, const std::string& _peerHost, const std::uint16_t& _peerPort, const std::string& _localHost, const std::uint16_t& _localPort)
            : Client(_protocol, _blocking, _ipv4, _peerHost, _peerPort, _localHost, _localPort) {
    m_speed = 0;
    m_rpm = 0;
    m_tls = std::make_unique<Tls>();
    m_uri = {
        {HTTPUriName::GetChangeEventsNotification, ("/api/v1/events?timeout=" + std::to_string(30))},
        {HTTPUriName::GetDataPoints, "/api/v1/db/get"},
        {HTTPUriName::SetDataPoints, "/api/v1/db/set"},
        {HTTPUriName::RegisterDataPoints, "/api/v1/register/db?fetch=true"},
        {HTTPUriName::GetTokenForSession, "/api/v1/auth/tokens"},
        {HTTPUriName::RegisterLocation, "/api/v1/register/location"},
        {HTTPUriName::NotifySOS, "/api/v1/notify/sos"},
        {HTTPUriName::NotifySOSClear, "/api/v1/notify/sos/clear"},
        {HTTPUriName::NotifyLocation, "/api/v1/notify/location"},
        {HTTPUriName::NotifyTelemetry, "/api/v1/notify/telemetry"},
    };

    /// @brief Add All data points that are to be registered for change notification.
    m_datapoints = {
        "device",
        "location.gnss.altitude",
        "location.gnss.latitude",
        "location.gnss.longitude",
        //"location.gnss.satcount"
    };

}

HTTPClient::~HTTPClient() {

}

std::int32_t HTTPClient::onReceive(const std::string& out) {
    //std::string req(out.data(), out.size());
    Http http(out);
    if("/api/v1/notify/sos" == http.uri()) {
        sosEntry(http.body());
    }

    //std::cout << __FUNCTION__<<":"<<__LINE__ << "Request:" << req << std::endl;
    std::string rsp = processRequestAndBuildResponse(out);
    std::cout << __FUNCTION__<<":"<<__LINE__ << "Request sent:" << rsp << std::endl;
    if(!rsp.empty()) {
        tls()->write(rsp, rsp.length());
    }
    return(0);
}

std::unique_ptr<Tls>& HTTPClient::tls() {
    return(m_tls);
}

std::string HTTPClient::endPoint() {
    return(m_endPoint);
}

void HTTPClient::endPoint(std::string ep) {
    m_endPoint = ep;
}

std::string HTTPClient::buildGetEventsNotificationRequest() {
    return(buildHeader(HTTPClient::HTTPUriName::GetChangeEventsNotification, std::string()));
}

std::string HTTPClient::processRequestAndBuildResponse(const std::string& in) {

    HTTPUriName whichResponse = sentURI();
    
    switch(whichResponse) {
        case HTTPUriName::GetChangeEventsNotification:
        {
            /// @brief Process Events Notification
            std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " HTTPUriName::GetChangeEventsNotification in:\n" << std::endl << in << std::endl;
            if(handleEventsNotificationResponse(in)) {
                /// @brief session token is obtained successfully.
                return(buildGetEventsNotificationRequest());
            } else {
                /// @brief Error Handling
                std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " HTTPUriName::GetChangeEventsNotification" << std::endl;
            }
        }
        break;
        case HTTPUriName::GetDataPoints:
        {
            std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " HTTPUriName::GetDataPoints in:\n" << std::endl << in << std::endl;
            if(handleGetDatapointResponse(in)) {
                /// @brief session token is obtained successfully.
                sentURI(HTTPUriName::GetDataPoints);
                return(buildGetEventsNotificationRequest());
            } else {
                /// @brief Error Handling
                std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " HTTPUriName::GetDataPoints" << std::endl;
            }

        }
        break;
        case HTTPUriName::GetTokenForSession:
        {
            /// @brief handle token for session.
            std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " HTTPUriName::GetTokenForSession in:\n" << std::endl << in << std::endl;
            if(handleGetTokenResponse(in)) {
                /// @brief session token is obtained successfully.
                sentURI(HTTPUriName::RegisterDataPoints);
                return(buildRegisterDatapointsRequest());
            } else {
                /// @brief Error Handling
            }
        }

        break;
        case HTTPUriName::RegisterDataPoints:
        {
            std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " HTTPUriName::RegisterDataPoints in:" << std::endl << in << std::endl;
            if(handleRegisterDatapointsResponse(in)) {
                sentURI(HTTPUriName::GetChangeEventsNotification);
                return(buildGetEventsNotificationRequest());
            } else {
                /// @brief Error Handling
                std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " HTTPUriName::RegisterDataPoints" << std::endl;
            }
        }
        break;
        case HTTPUriName::SetDataPoints:
        {

        }
        break;
        case HTTPUriName::ErrorUnknown:
        default:
        {

        }
        break;
    }
    return(std::string());
}

std::string HTTPClient::buildRegisterDatapointsRequest() {
    json payload = json::object();
    payload = {
        {"last", m_datapoints}
    };

    return(buildHeader(HTTPClient::HTTPUriName::RegisterDataPoints, payload.dump()));
}

std::string HTTPClient::buildHeader(HTTPUriName path, const std::string& payload) {
    std::stringstream ss;
    std::string method = "POST";

    if(payload.empty()) {
        method.assign("GET");
    }

    ss << method <<" " << uri(path) << " HTTP/1.1\r\n"
       << "Host: " << "192.168.1.1" << ":" << std::to_string(443) << "\r\n"
       << "User-Agent: " << "Embedded" << "\r\n"
       << "Connection: keep-alive\r\n"
       << "Accept: */*\r\n" 
       << "Accept-Encoding: gzip, deflate\r\n"
       << "Accept-Language: en-US,en;q=0.9\r\n";

    if(!cookie().empty()) {
        ss << "Cookie: " << cookie() << "\r\n";
    }

    if(!token().empty()) {
        ss << "Authorization: Bearer " << token() << "\r\n";
    }

    if(!method.compare(0, 4, "POST")) {
        ss << "Content-Type: application/vnd.api+json\r\n"
           << "Content-Length: " << payload.length() << "\r\n"
           //delimeter for body.
           << "\r\n"
           << payload;
    } else {
        //delimeter for body.
        ss  << "\r\n";
    }

    return(ss.str());
}

std::string HTTPClient::buildResponse(const std::string& payload) {
    std::stringstream ss;
    
    ss << "HTTP/1.1 200 OK" <<"\r\n"
       << "Host: 192.168.1.100:38989\r\n"   
       << "Server: " << "Embedded Server" << "\r\n"
       << "Connection: keep-alive\r\n"
       << "Content-Type: application/vnd.api+json\r\n";

    if(!payload.empty()) {
        ss << "Content-Length: " << payload.length() <<"\r\n\r\n"
           << payload;
    } else {
        ss << "Content-Length: 0" <<"\r\n";
    }

    return(ss.str());
}

std::string HTTPClient::buildGetTokenRequest(const std::string& userid, const std::string& pwd) {
    json payload = json::object();
    payload = {
        {"login", userid},
        {"password", pwd}
    };

    return(buildHeader(HTTPUriName::GetTokenForSession, payload.dump()));
}

bool HTTPClient::handleGetTokenResponse(const std::string& in) {
    Http http(in);
    std::uint32_t successCode = 200;

    if(successCode == std::stoi(http.status_code())) {
        if(!http.body().empty()) {
            json response = json::parse(http.body());
            if(!response.empty() && !response["data"]["access_token"].empty()) {
                token(response["data"]["access_token"]);
                std::stringstream ss;
                json last_status = json::object();

                last_status = {
                    {"success_last", response["data"]["success_last"].get<std::string>()},
                    {"success_from", response["data"]["success_from"].get<std::string>()},
                    {"failures", response["data"]["failures"].get<std::int32_t>()}
                };

                ss << "unity_token=" << token() <<"; "<<"unity_login=" << userid() << "; " << "last_connection="<< last_status.dump();
                cookie(ss.str());
                return(true);
            }
        }
    } else if(400 /* Invalid payload or bad credentials*/ == std::stoi(http.status_code()) ||
              401 /* Missing authentication token*/ == std::stoi(http.status_code()) ||
              403 /* Invalid authentication token.*/ == std::stoi(http.status_code()) ||
              500 /* Device could not check the provided credentials.*/ == std::stoi(http.status_code())) {
        /// @brief TODO: Error Handling
    } else {
        token(std::string());
        cookie(std::string());
    }
    return(false);
}

bool HTTPClient::handleRegisterDatapointsResponse(const std::string& in) {
    std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " handleRegisterDatapointsResponse:\n"<< in << std::endl;
    bool ret = false;
    Http http(in);
    auto payload = http.body();
    auto successCode = 200;

    if(successCode == std::stoi(http.status_code())) {
        if(!http.body().empty()) {
            json datapoints = json::parse(http.body());
            if(!datapoints.empty() && datapoints["data"] != nullptr) {
                for(auto const& [key, value]: datapoints["data"].items()) {
                    processKeyValue(key, value);
                }
            }
            ret = true;
        }
    } else {
        /// @brief Error Handling
    }
    return(true);
}

bool HTTPClient::handleEventsNotificationResponse(const std::string& in) {
    bool ret = false;
    Http http(in);
    auto payload = http.body();
    auto successCode = 200;
    auto noContent = 204;

    if(successCode == std::stoi(http.status_code()) ||
       noContent == std::stoi(http.status_code())) {
        if(!http.body().empty()) {
            json datapoints = json::parse(http.body());
            if(!datapoints.empty() && datapoints["data"]["db"]["last"] != nullptr) {
                for(auto const& [key, value]: datapoints["data"]["db"]["last"].items()) {
                    processKeyValue(key, value);
                }
            }
        }
        ret = true;
    } else {
        /// @brief Error Handling
    }
    return(ret);
}

void HTTPClient::processKeyValue(std::string const& key, json value) {
    
    if(!key.compare(0, 22, "location.gnss.latitude") && !value.empty()) {
        /// @brief Extract hostname and port number ---- e.g. coaps://lw.eu.airvantage.net:5686
        m_latitude = std::to_string(value.get<double>());
    } else if(!key.compare(0, 23, "location.gnss.longitude") && !value.empty()) {
        m_longitude = std::to_string(value.get<double>());
    } else if(!key.compare(0, 26, "device.provisioning.serial") && !value.empty()) {
        m_serialNumber = value.get<std::string>();
        ///@brief send to mqtt_adapter
        std::fprintf(stderr, "%d %s", m_serialNumber.length(), m_serialNumber.c_str());
        std::cout << basename(__FILE__) <<":" << __LINE__ << " serialNumber:" << m_serialNumber << std::endl;
    } else if(!key.compare(0, 14, "device.product") && !value.empty()) {
        m_model = value.get<std::string>();
    }
}
bool HTTPClient::handleSetDatapointResponse(const std::string& in) {
    std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " handleSetDatapointResponse " << std::endl;
    return(false);
}

bool HTTPClient::handleGetDatapointResponse(const std::string& in) {
    std::cout << basename(__FILE__) << ":" <<__FUNCTION__<<":"<< __LINE__ << " handleSetDatapointResponse " << std::endl;
    return(false);
}

#endif /*__services_http_hpp_cpp__*/