#include "services_http.hpp"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cstring>

// HTTP/2 HPACK Implementation
HPACK::Encoder::Encoder() : m_max_table_size(4096) {}

std::string HPACK::Encoder::encode(const std::vector<HeaderField>& headers) {
    std::stringstream encoded;
    
    for (const auto& header : headers) {
        if (header.indexed) {
            // Use indexed representation
            encoded << static_cast<char>(0x80); // Indexed header field
            encoded << static_cast<char>(1); // Index 1 for common headers
        } else {
            // Use literal representation
            encoded << static_cast<char>(0x40); // Literal header field
            encoded << static_cast<char>(header.name.length());
            encoded << header.name;
            encoded << static_cast<char>(header.value.length());
            encoded << header.value;
        }
    }
    
    return encoded.str();
}

HPACK::Decoder::Decoder() = default;

std::vector<HPACK::HeaderField> HPACK::Decoder::decode(const std::string& encoded_data) {
    std::vector<HeaderField> headers;
    std::istringstream input(encoded_data);
    
    while (input.good()) {
        std::uint8_t first_byte = input.get();
        
        if (first_byte & 0x80) {
            // Indexed header field
            std::uint8_t index = first_byte & 0x7F;
            // In a real implementation, you would look up the header in the table
            headers.emplace_back(":method", "GET", true);
        } else if (first_byte & 0x40) {
            // Literal header field with incremental indexing
            std::string name = readString(input);
            std::string value = readString(input);
            headers.emplace_back(name, value, false);
        } else {
            // Literal header field without indexing
            std::string name = readString(input);
            std::string value = readString(input);
            headers.emplace_back(name, value, false);
        }
    }
    
    return headers;
}

std::string HPACK::Decoder::readString(std::istringstream& input) {
    std::uint8_t length = input.get();
    std::string result;
    result.resize(length);
    input.read(&result[0], length);
    return result;
}

// HTTP/2 Flow Control Implementation
FlowControl::FlowControl(std::uint32_t initial_size) 
    : m_initial_window_size(initial_size), m_current_window_size(initial_size) {}

bool FlowControl::canSendData(std::uint32_t stream_id, std::uint32_t data_size) {
    auto& stream_window = m_stream_windows[stream_id];
    if (stream_window == 0) {
        stream_window = m_initial_window_size;
    }
    
    return data_size <= stream_window && data_size <= m_current_window_size;
}

void FlowControl::consumeWindow(std::uint32_t stream_id, std::uint32_t data_size) {
    auto& stream_window = m_stream_windows[stream_id];
    stream_window -= data_size;
    m_current_window_size -= data_size;
}

void FlowControl::updateWindow(std::uint32_t stream_id, std::uint32_t increment) {
    if (stream_id == 0) {
        m_current_window_size += increment;
    } else {
        m_stream_windows[stream_id] += increment;
    }
}

std::uint32_t FlowControl::getWindowSize(std::uint32_t stream_id) const {
    if (stream_id == 0) {
        return m_current_window_size;
    }
    
    auto it = m_stream_windows.find(stream_id);
    return (it != m_stream_windows.end()) ? it->second : m_initial_window_size;
}

// HTTP/2 Stream Management
StreamManager::StreamManager() : m_next_client_stream_id(1), m_next_server_stream_id(2) {}

std::uint32_t StreamManager::createClientStream() {
    std::uint32_t stream_id = m_next_client_stream_id;
    m_next_client_stream_id += 2; // Client streams use odd numbers
    m_streams[stream_id] = "";
    return stream_id;
}

std::uint32_t StreamManager::createServerStream() {
    std::uint32_t stream_id = m_next_server_stream_id;
    m_next_server_stream_id += 2; // Server streams use even numbers
    m_streams[stream_id] = "";
    return stream_id;
}

void StreamManager::closeStream(std::uint32_t stream_id) {
    m_streams.erase(stream_id);
}

bool StreamManager::isStreamOpen(std::uint32_t stream_id) const {
    return m_streams.find(stream_id) != m_streams.end();
}

void StreamManager::addStreamData(std::uint32_t stream_id, const std::string& data) {
    m_streams[stream_id] += data;
}

std::string StreamManager::getStreamData(std::uint32_t stream_id) const {
    auto it = m_streams.find(stream_id);
    return (it != m_streams.end()) ? it->second : "";
}

void StreamManager::clearStreamData(std::uint32_t stream_id) {
    auto it = m_streams.find(stream_id);
    if (it != m_streams.end()) {
        it->second.clear();
    }
}

// HTTP/2 Client Implementation
Http2Client::Http2Client(const std::string& host, std::uint16_t port) 
    : m_host(host), m_port(port), m_connection_established(false) {
    m_tls = std::make_unique<Tls>();
    m_flow_control = std::make_unique<FlowControl>();
    m_stream_manager = std::make_unique<StreamManager>();
    m_hpack_encoder = std::make_unique<HPACK::Encoder>();
    m_settings = Http2::createDefaultSettings();
}

bool Http2Client::connect() {
    // Send connection preface
    std::string preface = Http2Utils::createConnectionPreface();
    if (m_tls) {
        m_tls->write(preface, preface.length());
    }
    
    // Send initial settings
    std::string settings_frame = Http2Utils::createSettingsFrame(m_settings);
    if (m_tls) {
        m_tls->write(settings_frame, settings_frame.length());
    }
    
    m_connection_established = true;
    return true;
}

std::string Http2Client::sendRequest(const std::string& method, const std::string& path, 
                                   const std::string& body, 
                                   const std::unordered_map<std::string, std::string>& headers) {
    if (!m_connection_established) {
        return "";
    }

    // Create stream
    std::uint32_t stream_id = m_stream_manager->createClientStream();

    // Create headers using HPACK
    std::vector<HPACK::HeaderField> header_fields;
    header_fields.emplace_back(":method", method);
    header_fields.emplace_back(":path", path);
    header_fields.emplace_back(":authority", m_host + ":" + std::to_string(m_port));
    header_fields.emplace_back(":scheme", "https");
    
    for (const auto& [key, value] : headers) {
        header_fields.emplace_back(key, value);
    }

    std::string encoded_headers = m_hpack_encoder->encode(header_fields);

    // Create HTTP/2 HEADERS frame
    Http2::HeaderFrame header_frame;
    header_frame.sd(stream_id);
    header_frame.data(encoded_headers);
    
    // Serialize HEADERS frame
    Http2::FrameFormat frame_format;
    frame_format.fType(static_cast<std::uint8_t>(Http2::FType::HEADERS));
    frame_format.fFlags(Http2::Flags::END_HEADERS);
    frame_format.fStream(stream_id);
    frame_format.fPayload(header_frame.serialize());
    
    std::string frame_data = frame_format.serialize();

    // Add DATA frame if body exists and flow control allows
    if (!body.empty() && m_flow_control->canSendData(stream_id, body.length())) {
        Http2::DataFrame data_frame;
        data_frame.contents(body);
        
        Http2::FrameFormat data_frame_format;
        data_frame_format.fType(static_cast<std::uint8_t>(Http2::FType::DATA));
        data_frame_format.fFlags(Http2::Flags::END_STREAM);
        data_frame_format.fStream(stream_id);
        data_frame_format.fPayload(data_frame.serialize());
        
        frame_data += data_frame_format.serialize();
        
        // Update flow control
        m_flow_control->consumeWindow(stream_id, body.length());
    }

    // Send frame data
    if (m_tls) {
        m_tls->write(frame_data, frame_data.length());
    }
    
    return frame_data;
}

std::string Http2Client::receiveResponse() {
    if (!m_connection_established || !m_tls) {
        return "";
    }

    std::string response_data;
    std::vector<char> buffer(4096);
    
    // Read response data
    auto bytes_read = m_tls->read(response_data, buffer.size());
    if (bytes_read > 0) {
        return parseHttp2Response(response_data);
    }
    
    return "";
}

void Http2Client::sendWindowUpdate(std::uint32_t stream_id, std::uint32_t increment) {
    std::string window_update_frame = Http2Utils::createWindowUpdateFrame(stream_id, increment);
    if (m_tls) {
        m_tls->write(window_update_frame, window_update_frame.length());
    }
    m_flow_control->updateWindow(stream_id, increment);
}

void Http2Client::sendPing() {
    std::string ping_frame = Http2Utils::createPingFrame();
    if (m_tls) {
        m_tls->write(ping_frame, ping_frame.length());
    }
}

std::string Http2Client::createHeadersBlock(const std::string& method, const std::string& path,
                                          const std::unordered_map<std::string, std::string>& headers) {
    // Create HPACK-encoded headers (simplified implementation)
    std::stringstream ss;
    
    // Method
    ss << ":method:" << method << "\n";
    
    // Path
    ss << ":path:" << path << "\n";
    
    // Authority (host)
    ss << ":authority:" << m_host << ":" << m_port << "\n";
    
    // Scheme
    ss << ":scheme:https\n";
    
    // Additional headers
    for (const auto& [key, value] : headers) {
        ss << key << ":" << value << "\n";
    }
    
    return ss.str();
}

std::string Http2Client::parseHttp2Response(const std::string& frame_data) {
    // Parse HTTP/2 frames and extract response
    std::string response;
    
    size_t offset = 0;
    while (offset < frame_data.length()) {
        if (frame_data.length() - offset < 9) {
            break; // Incomplete frame header
        }

        // Parse frame header
        Http2::FrameFormat frame = Http2::parseFrame(frame_data.substr(offset));
        
        // Process frame based on type
        switch (static_cast<Http2::FType>(frame.fType())) {
            case Http2::FType::HEADERS: {
                // Extract headers from payload
                response += "HTTP/2.0 200 OK\r\n";
                response += parseHeadersPayload(frame.fPayload());
                break;
            }
            case Http2::FType::DATA: {
                // Extract data payload
                Http2::DataFrame data_frame;
                data_frame.deserialize(frame.fPayload(), frame.fFlags());
                response += data_frame.contents();
                
                // Update flow control
                m_flow_control->consumeWindow(frame.fStream(), data_frame.contents().length());
                
                // Send window update if needed
                if (m_flow_control->getWindowSize(frame.fStream()) < 16384) {
                    sendWindowUpdate(frame.fStream(), 32768);
                }
                break;
            }
            case Http2::FType::SETTINGS: {
                // Handle settings frame
                Http2::Settings settings;
                settings.deserialize(frame.fPayload());
                break;
            }
            case Http2::FType::WINDOW_UPDATE: {
                // Handle window update
                Http2::WindowUpdate window_update;
                window_update.deserialize(frame.fPayload());
                m_flow_control->updateWindow(frame.fStream(), window_update.windowSizeIncrement());
                break;
            }
            case Http2::FType::GOAWAY: {
                // Handle connection termination
                Http2::Goaway goaway;
                goaway.deserialize(frame.fPayload());
                m_connection_established = false;
                break;
            }
            default:
                // Ignore other frame types for now
                break;
        }
        
        offset += 9 + frame.fLength(); // Move to next frame
    }
    
    return response;
}

std::string Http2Client::parseHeadersPayload(const std::string& payload) {
    // Simplified header parsing (in real implementation, use HPACK decoder)
    std::string headers;
    std::istringstream iss(payload);
    std::string line;
    
    while (std::getline(iss, line)) {
        if (line.empty()) break;
        
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string name = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            
            // Skip pseudo-headers
            if (name[0] != ':') {
                headers += name + ": " + value + "\r\n";
            }
        }
    }
    
    return headers;
}

// HTTP/2 Server Implementation
Http2Server::Http2Server() : m_next_stream_id(2) { // Even numbers for server-initiated streams
    m_flow_control = std::make_unique<FlowControl>();
    m_stream_manager = std::make_unique<StreamManager>();
    m_hpack_decoder = std::make_unique<HPACK::Decoder>();
    m_hpack_encoder = std::make_unique<HPACK::Encoder>();
    m_settings = Http2::createDefaultSettings();
}

std::string Http2Server::handleRequest(const std::string& frame_data) {
    std::string response_frames;
    
    size_t offset = 0;
    while (offset < frame_data.length()) {
        if (frame_data.length() - offset < 9) {
            break;
        }

        // Parse incoming frame
        Http2::FrameFormat frame = Http2::parseFrame(frame_data.substr(offset));
        
        // Process frame
        switch (static_cast<Http2::FType>(frame.fType())) {
            case Http2::FType::HEADERS: {
                response_frames += handleHeadersFrame(frame);
                break;
            }
            case Http2::FType::DATA: {
                response_frames += handleDataFrame(frame);
                break;
            }
            case Http2::FType::SETTINGS: {
                response_frames += handleSettingsFrame(frame);
                break;
            }
            case Http2::FType::PING: {
                response_frames += handlePingFrame(frame);
                break;
            }
            case Http2::FType::WINDOW_UPDATE: {
                response_frames += handleWindowUpdateFrame(frame);
                break;
            }
            default:
                // Send GOAWAY for unsupported frame types
                response_frames += createGoawayFrame(Http2::ErrorCodes::PROTOCOL_ERROR);
                break;
        }
        
        offset += 9 + frame.fLength();
    }
    
    return response_frames;
}

std::string Http2Server::handleHeadersFrame(const Http2::FrameFormat& frame) {
    std::string response;
    
    // Parse headers using HPACK
    std::vector<HPACK::HeaderField> headers = m_hpack_decoder->decode(frame.fPayload());
    
    // Extract method and path
    std::string method, path;
    for (const auto& header : headers) {
        if (header.name == ":method") {
            method = header.value;
        } else if (header.name == ":path") {
            path = header.value;
        }
    }
    
    // Generate response headers
    std::vector<HPACK::HeaderField> response_headers;
    response_headers.emplace_back(":status", "200");
    response_headers.emplace_back("content-type", "text/plain");
    response_headers.emplace_back("server", "Http2Server");
    
    std::string encoded_response_headers = m_hpack_encoder->encode(response_headers);
    
    Http2::HeaderFrame response_header_frame;
    response_header_frame.sd(frame.fStream());
    response_header_frame.data(encoded_response_headers);
    
    // Serialize response headers frame
    Http2::FrameFormat headers_frame;
    headers_frame.fType(static_cast<std::uint8_t>(Http2::FType::HEADERS));
    headers_frame.fFlags(Http2::Flags::END_HEADERS);
    headers_frame.fStream(frame.fStream());
    headers_frame.fPayload(response_header_frame.serialize());
    
    response = headers_frame.serialize();
    
    // Add response data if needed and flow control allows
    std::string response_body = generateResponseBody(method, path);
    if (!response_body.empty() && m_flow_control->canSendData(frame.fStream(), response_body.length())) {
        Http2::DataFrame data_frame;
        data_frame.contents(response_body);
        
        Http2::FrameFormat data_frame_format;
        data_frame_format.fType(static_cast<std::uint8_t>(Http2::FType::DATA));
        data_frame_format.fFlags(Http2::Flags::END_STREAM);
        data_frame_format.fStream(frame.fStream());
        data_frame_format.fPayload(data_frame.serialize());
        
        response += data_frame_format.serialize();
        
        // Update flow control
        m_flow_control->consumeWindow(frame.fStream(), response_body.length());
    }
    
    return response;
}

std::string Http2Server::handleDataFrame(const Http2::FrameFormat& frame) {
    // Store data for the stream
    m_stream_manager->addStreamData(frame.fStream(), frame.fPayload());
    
    // Update flow control
    m_flow_control->consumeWindow(frame.fStream(), frame.fPayload().length());
    
    // Send window update if needed
    if (m_flow_control->getWindowSize(frame.fStream()) < 16384) {
        return Http2Utils::createWindowUpdateFrame(frame.fStream(), 32768);
    }
    
    return ""; // No immediate response needed
}

std::string Http2Server::handleSettingsFrame(const Http2::FrameFormat& frame) {
    // Parse and apply settings
    Http2::Settings settings;
    settings.deserialize(frame.fPayload());
    
    // Send settings acknowledgment
    Http2::FrameFormat ack_frame;
    ack_frame.fType(static_cast<std::uint8_t>(Http2::FType::SETTINGS));
    ack_frame.fFlags(Http2::Flags::END_HEADERS); // ACK flag
    ack_frame.fStream(0); // Settings frames use stream 0
    ack_frame.fPayload(""); // Empty payload for ACK
    
    return ack_frame.serialize();
}

std::string Http2Server::handlePingFrame(const Http2::FrameFormat& frame) {
    // Echo back the ping data
    Http2::Ping ping;
    ping.opaqueData(0x123456789ABCDEF0); // Example ping data
    
    Http2::FrameFormat ping_frame;
    ping_frame.fType(static_cast<std::uint8_t>(Http2::FType::PING));
    ping_frame.fFlags(Http2::Flags::END_STREAM); // ACK flag
    ping_frame.fStream(0); // Ping frames use stream 0
    ping_frame.fPayload(ping.serialize());
    
    return ping_frame.serialize();
}

std::string Http2Server::handleWindowUpdateFrame(const Http2::FrameFormat& frame) {
    // Parse window update
    Http2::WindowUpdate window_update;
    window_update.deserialize(frame.fPayload());
    
    // Update flow control
    m_flow_control->updateWindow(frame.fStream(), window_update.windowSizeIncrement());
    
    return ""; // No response needed for window updates
}

std::string Http2Server::createGoawayFrame(Http2::ErrorCodes error_code) {
    Http2::Goaway goaway;
    goaway.errorCode(error_code);
    goaway.lastStreamId(0);
    goaway.additionalDebugData("Server shutting down");
    
    Http2::FrameFormat goaway_frame;
    goaway_frame.fType(static_cast<std::uint8_t>(Http2::FType::GOAWAY));
    goaway_frame.fFlags(Http2::Flags::INVALID);
    goaway_frame.fStream(0);
    goaway_frame.fPayload(goaway.serialize());
    
    return goaway_frame.serialize();
}

void Http2Server::parseRequestHeaders(const std::string& payload, std::string& method, std::string& path) {
    // Simplified header parsing
    std::istringstream iss(payload);
    std::string line;
    
    while (std::getline(iss, line)) {
        if (line.empty()) break;
        
        if (line.find(":method:") == 0) {
            method = line.substr(8);
        } else if (line.find(":path:") == 0) {
            path = line.substr(6);
        }
    }
}

std::string Http2Server::createResponseHeaders() {
    std::stringstream ss;
    ss << ":status:200\n";
    ss << "content-type:text/plain\n";
    ss << "server:Http2Server\n";
    return ss.str();
}

std::string Http2Server::generateResponseBody(const std::string& method, const std::string& path) {
    // Simple response generation
    std::stringstream ss;
    ss << "HTTP/2 Response\n";
    ss << "Method: " << method << "\n";
    ss << "Path: " << path << "\n";
    ss << "Timestamp: " << std::time(nullptr) << "\n";
    return ss.str();
}

// HTTP/2 Utility Functions
std::string Http2Utils::createConnectionPreface() {
    return Http2::CONNECTION_PREFACE;
}

bool Http2Utils::validateFrame(const std::string& frame_data) {
    if (frame_data.length() < 9) {
        return false; // Frame too short
    }
    
    Http2::FrameFormat frame = Http2::parseFrame(frame_data);
    
    // Validate frame type
    if (!Http2::isValidFrameType(frame.fType())) {
        return false;
    }
    
    // Validate frame length
    if (frame.fLength() > Http2::SETTINGS_MAX_FRAME_SIZE) {
        return false;
    }
    
    return true;
}

std::string Http2Utils::createSettingsFrame(const Http2::Settings& settings) {
    Http2::FrameFormat frame;
    frame.fType(static_cast<std::uint8_t>(Http2::FType::SETTINGS));
    frame.fFlags(Http2::Flags::INVALID);
    frame.fStream(0); // Settings frames use stream 0
    frame.fPayload(settings.serialize());
    
    return frame.serialize();
}

std::string Http2Utils::createWindowUpdateFrame(std::uint32_t stream_id, std::uint32_t increment) {
    Http2::WindowUpdate window_update;
    window_update.windowSizeIncrement(increment);
    
    Http2::FrameFormat frame;
    frame.fType(static_cast<std::uint8_t>(Http2::FType::WINDOW_UPDATE));
    frame.fFlags(Http2::Flags::INVALID);
    frame.fStream(stream_id);
    frame.fPayload(window_update.serialize());
    
    return frame.serialize();
}

std::string Http2Utils::createPingFrame(std::uint64_t data) {
    Http2::Ping ping;
    ping.opaqueData(data);
    
    Http2::FrameFormat frame;
    frame.fType(static_cast<std::uint8_t>(Http2::FType::PING));
    frame.fFlags(Http2::Flags::INVALID);
    frame.fStream(0);
    frame.fPayload(ping.serialize());
    
    return frame.serialize();
}

std::string Http2Utils::createGoawayFrame(std::uint32_t last_stream_id, Http2::ErrorCodes error_code) {
    Http2::Goaway goaway;
    goaway.lastStreamId(last_stream_id);
    goaway.errorCode(error_code);
    goaway.additionalDebugData("Connection terminated");
    
    Http2::FrameFormat frame;
    frame.fType(static_cast<std::uint8_t>(Http2::FType::GOAWAY));
    frame.fFlags(Http2::Flags::INVALID);
    frame.fStream(0);
    frame.fPayload(goaway.serialize());
    
    return frame.serialize();
}

// HTTP/2 Enhanced HTTPClient
HTTP2Client::HTTP2Client(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                        const std::string& _peerHost, const std::uint16_t& _peerPort, 
                        const std::string& _localHost, const std::uint16_t& _localPort)
    : HTTPClient(_protocol, _blocking, _ipv4, _peerHost, _peerPort, _localHost, _localPort),
      m_use_http2(false) {
    
    // Initialize HTTP/2 client if protocol supports it
    if (_protocol == 2) { // Assuming 2 represents HTTP/2
        m_http2_client = std::make_unique<Http2Client>(_peerHost, _peerPort);
        m_use_http2 = true;
    }
}

std::string HTTP2Client::sendHttp2Request(const std::string& method, const std::string& path, 
                                         const std::string& body) {
    if (!m_use_http2 || !m_http2_client) {
        return "";
    }

    // Prepare headers
    std::unordered_map<std::string, std::string> headers;
    if (!token().empty()) {
        headers["authorization"] = "Bearer " + token();
    }
    if (!cookie().empty()) {
        headers["cookie"] = cookie();
    }

    // Send HTTP/2 request
    return m_http2_client->sendRequest(method, path, body, headers);
}

std::string HTTP2Client::receiveHttp2Response() {
    if (!m_use_http2 || !m_http2_client) {
        return "";
    }

    return m_http2_client->receiveResponse();
}

bool HTTP2Client::connectHttp2() {
    if (!m_use_http2 || !m_http2_client) {
        return false;
    }

    return m_http2_client->connect();
}

// HTTP/2 Enhanced HTTPServer
HTTP2Server::HTTP2Server(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, 
                        const bool& _ipv4, const std::string& _localHost, const std::uint16_t& _localPort)
    : HTTPServer(_qsize, _protocol, _blocking, _ipv4, _localHost, _localPort) {
    
    m_http2_server = std::make_unique<Http2Server>();
}

std::int32_t HTTP2Server::onReceiveHttp2(const std::string& request_data) {
    if (!m_http2_server) {
        return -1;
    }

    // Validate HTTP/2 frame
    if (!Http2Utils::validateFrame(request_data)) {
        return -1;
    }

    // Handle HTTP/2 request
    std::string response = m_http2_server->handleRequest(request_data);
    
    // Send response (implementation depends on your networking layer)
    // For now, just return success
    return 0;
}

// Original HTTP/1.1 implementation continues below...

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