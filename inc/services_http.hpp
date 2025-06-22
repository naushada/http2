#ifndef __services_http_hpp__
#define __services_http_hpp__

#include <iostream>
#include <vector>
#include <sstream>
#include <memory>
#include <algorithm>
#include <unordered_map>
#include <variant>

#include "services.hpp"
#include "json.hpp"

extern "C" {
    #include <openssl/bio.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/ossl_typ.h>
    #include <openssl/pem.h>
    #include <openssl/x509.h>
    #include <openssl/x509_vfy.h>
}

using json = nlohmann::json;
class Http {
    public:
        Http() {
            m_uri.clear();
            m_params.clear();
        }

        Http(const std::string& in) {
            m_uri.clear();
            m_params.clear();
            m_header.clear();
            m_body.clear();

            m_header = get_header(in);

            do {
                if(m_header.length()) {
                    
                    if(!m_header.compare(0, 8, "HTTP/1.1")) {
                        //this is a response.
                        m_status_code = m_header.substr(9, 3);
                        parse_header(in);
                        m_body = get_body(in);
                        break;
                    }

                    parse_uri(m_header);
                    parse_header(in);
                }

                m_body = get_body(in);
                auto idx = m_header.find(' ');
                if(idx != std::string::npos) {
                    method(m_header.substr(0, idx));
                }
                
            }while(0);
        }

        ~Http() {
            m_params.clear();
        }

        std::string method() {
            return(m_method);
        }

        void method(std::string _method) {
            m_method = _method;
        }

        std::string uri() const {
            return(m_uri);
        }

        void uri(std::string _uri) {
            m_uri = _uri;
        }

        void add_element(std::string key, std::string value) {
            m_params.insert(std::make_pair(key, value));
        }

        std::string value(const std::string& key) {
            auto it = m_params.find(key);
            if(it != m_params.end()) {
                return(it->second);
            }
            return std::string();
        }

        std::string body() {
            return m_body;
        }

        void body(std::string in) {
            m_body = in;
        }

        std::string header() {
            return m_header;
        }

        void header(std::string in) {
            m_header = in;
        }

        std::string status_code() const {return m_status_code;}
        void status_code(std::string code) {m_status_code = code;}

        void format_value(const std::string& param) {
            auto offset = param.find_first_of("=", 0);
            auto name = param.substr(0, offset);
            auto value = param.substr((offset + 1));
            std::stringstream input(value);
            std::int32_t c;
            value.clear();

            while((c = input.get()) != EOF) {
                switch(c) {
                case '+':
                    value.push_back(' ');
                break;

                case '%':
                {
                    std::int8_t octalCode[3];
                    octalCode[0] = (std::int8_t)input.get();
                    octalCode[1] = (std::int8_t)input.get();
                    octalCode[2] = 0;
                    std::string octStr((const char *)octalCode, 3);
                    std::int32_t ch = std::stoi(octStr, nullptr, 16);
                    value.push_back(ch);
                }
                break;

                default:
                    value.push_back(c);
                }
            }

            if(!value.empty() && !name.empty()) {
                add_element(name, value);
            }
        }

        void parse_uri(const std::string& in) {
            std::string delim("\r\n");
            size_t offset = in.find(delim);

            if(std::string::npos != offset) {
                /* Qstring */
                std::string req = in.substr(0, offset);
                std::stringstream input(req);
                std::string parsed_string;
                std::string param;
                std::string value;
                bool isQsPresent = false;

                parsed_string.clear();
                param.clear();
                value.clear();

                std::int32_t c;
                while((c = input.get()) != EOF) {
                    switch(c) {
                        case ' ':
                        {
                            std::int8_t endCode[4];
                            endCode[0] = (std::int8_t)input.get();
                            endCode[1] = (std::int8_t)input.get();
                            endCode[2] = (std::int8_t)input.get();
                            endCode[3] = (std::int8_t)input.get();

                            std::string p((const char *)endCode, 4);

                            if(!p.compare("HTTP")) {

                                if(!isQsPresent) {
                                    uri(parsed_string);
                                    parsed_string.clear();
                                } else {
                                    value = parsed_string;
                                    add_element(param, value);
                                }
                            } else {
                                /* make available to stream to be get again*/
                                input.unget();
                                input.unget();
                                input.unget();
                                input.unget();
                            }

                            parsed_string.clear();
                            param.clear();
                            value.clear();
                        }
                        break;

                        case '+':
                        {
                            parsed_string.push_back(' ');
                        }
                        break;

                        case '?':
                        {
                            isQsPresent = true;
                            uri(parsed_string);
                            parsed_string.clear();
                        }
                        break;

                        case '&':
                        {
                            value = parsed_string;
                            add_element(param, value);
                            parsed_string.clear();
                            param.clear();
                            value.clear();
                        }
                        break;

                        case '=':
                        {
                            param = parsed_string;
                            parsed_string.clear();
                        }
                        break;

                        case '%':
                        {
                            std::int8_t octalCode[3];
                            octalCode[0] = (std::int8_t)input.get();
                            octalCode[1] = (std::int8_t)input.get();
                            octalCode[2] = 0;
                            std::string octStr((const char *)octalCode, 3);
                            std::int32_t ch = std::stoi(octStr, nullptr, 16);
                            parsed_string.push_back(ch);
                        }
                        break;

                        default:
                        {
                            parsed_string.push_back(c);
                        }
                        break;  
                    }
                }
            }
        }

        void parse_header(const std::string& in) {
            std::stringstream input(in);
            std::string param;
            std::string value;
            std::string parsed_string;
            std::string line_str;
            line_str.clear();

            /* getridof first request line 
             * GET/POST/PUT/DELETE <uri>?uriName[&param=value]* HTTP/1.1\r\n
             */
            std::getline(input, line_str);

            param.clear();
            value.clear();
            parsed_string.clear();

            /* iterating through the MIME Header of the form
             * Param: Value\r\n
             */
            while(!input.eof()) {
                line_str.clear();
                std::getline(input, line_str);
                std::stringstream _line(line_str);

                std::int32_t c;
                while((c = _line.get()) != EOF ) {
                    switch(c) {
                        case ':':
                        {
                            param = parsed_string;
                            parsed_string.clear();
                            /* getridof of first white space */
                            c = _line.get();
                            while((c = _line.get()) != EOF) {
                                switch(c) {
                                    case '\r':
                                    case '\n':
                                        /* get rid of \r character */
                                        continue;

                                    default:
                                        parsed_string.push_back(c);
                                        break;
                                }
                            }
                            /* we hit the end of line */
                            value = parsed_string;
                            add_element(param, value);
                            parsed_string.clear();
                            param.clear();
                            value.clear();
                        }
                            break;

                        default:
                            parsed_string.push_back(c);
                            break;
                    }
                }
            }
        }
        std::string get_header(const std::string& in) {
            std::string delimeter("\r\n\r\n");
            std::string::size_type offset = in.rfind(delimeter);
  
            if(std::string::npos != offset) {
                std::string document = in.substr(0, offset + delimeter.length());
                return(document);
            }

            return(in);
        }

        std::string get_body(const std::string& in) {
            std::string ct = value("Content-Type");
            std::string contentLen = value("Content-Length");

            if(ct.length() && !ct.compare("application/vnd.api+json") && contentLen.length()) {
                auto offset = header().length() /* \r\n delimeter's length which seperator between header and body */;
                if(offset) {
                    std::string document(in.substr(offset, std::stoi(contentLen)));
                    return(document);
                }
            }
            return(std::string());
        }

    private:
        std::unordered_map<std::string, std::string> m_params;
        std::string m_uri;
        std::string m_header;
        std::string m_body;
        std::string m_method;
        std::string m_status_code;
        std::uint32_t m_eventId;
};

class Http2 final {
    public:
    enum class ErrorCodes : std::uint32_t {
        NO_ERROR = 0,
        PROTOCOL_ERROR = 1,
        INTERNAL_ERROR = 2,
        FLOW_CONTROL_ERROR = 3,
        SETTINGS_TIMEOUT = 4,
        STREAM_CLOSED = 5,
        FRAME_SIZE_ERROR = 6,
        REFUSED_STREAM = 7,
        CANCEL = 8,
        COMPRESSION_ERROR = 9,
        CONNECT_ERROR = 0xA,
        ENHANCE_YOUR_CALM = 0xB,
        INADEQUATE_SECURITY = 0xC,
        HTTP_1_1_REQUIRED = 0xD
    };

    // Frame Types
    enum class FType: std::uint8_t {
        DATA = 0x00,
        HEADERS = 0x01,
        PRIORITY = 0x02,
        RST_STREAM = 0x03,
        SETTINGS = 0x04,
        PUSH_PROMISE = 0x05,
        PING = 0x06,
        GOAWAY = 0x07,
        WINDOW_UPDATE = 0x08,
        CONTINUATION = 0x09,
        ALTSVC = 0x0A,
        UNASSIGNED = 0x0B,
        ORIGIN = 0x0C,
        // 0x0D - 0x0F is unassigned
        PRIORITY_UPDATE = 0x10,
        // 0x11-0x1F is Unassigned
    };

    enum class Flags: std::uint8_t {
        END_STREAM = 0x01,
        END_HEADERS = 0x04,
        PADDED=0x08,
        PRIORITY=0x20,
        INVALID
    };

    // 2^14
    static constexpr std::uint32_t SETTINGS_MAX_FRAME_SIZE = 16384;

    struct FrameFormat {
        std::uint32_t m_fLength;
        std::uint8_t m_fType;
        Flags m_fFlags;
        std::uint8_t m_fR;
        std::uint32_t m_fStream;
        std::string m_fPayload;

        FrameFormat(): m_fLength(0), m_fType(0), m_fFlags(Flags::INVALID), m_fR(0), m_fStream(0), m_fPayload("") {}
        ~FrameFormat() = default;
        // copy ctor.
        FrameFormat(const FrameFormat& ff) : m_fLength(ff.m_fLength), m_fType(ff.m_fType), m_fFlags(ff.m_fFlags),
                                             m_fR(ff.m_fR), m_fStream(ff.m_fStream), m_fPayload(ff.m_fPayload) {}
        // assignment
        FrameFormat& operator = (const FrameFormat& ff) {
            m_fLength = ff.m_fLength;
            m_fType = ff.m_fType;
            m_fFlags = ff.m_fFlags;
            m_fR = ff.m_fR;
            m_fStream = ff.m_fStream;
            m_fPayload = ff.m_fPayload;
            return(*this);
        }

        friend std::uint8_t operator& (const Http2::Flags& left, const Http2::Flags& right) {
          return(static_cast<std::uint8_t>(left) & static_cast<std::uint8_t>(right));
        }

        friend std::uint8_t operator& (const Http2::Flags& left, const std::uint8_t& right) {
          return(static_cast<std::uint8_t>(left) & right);
        }

        std::uint32_t fLength() const {
            return(m_fLength);
        }
        void fLength(std::uint32_t l) {
            m_fLength = l;
        }

        std::uint8_t fType() const {
            return(m_fType);
        }
        void fType(std::uint8_t ty) {
            m_fType = ty;
        }

        Flags fFlags() const {
            return(m_fFlags);
        }
        void fFlags(Flags f) {
            m_fFlags = f;
        }

        std::uint8_t fR() const {
            return(m_fR);
        }
        void fR(std::uint8_t f) {
            m_fR = f;
        }

        std::uint8_t fStream() const {
            return(m_fStream);
        }
        void fStream(std::uint32_t f) {
            m_fStream = f;
        }

        std::string fPayload() const {
            return(m_fPayload);
        }
        void fPayload(std::string p) {
            m_fPayload = p;
        }

        // Reference: https://datatracker.ietf.org/doc/html/rfc7540#section-4.1
        std::string serialize(const std::uint32_t& len, const std::string& in,
                              const std::uint8_t& type, const Http2::Flags& flag, const std::uint8_t& r,
                              const std::uint32_t& stream) {
            std::stringstream ss;
            std::uint8_t oneByte;

            // Length(24) Field
            oneByte = len & 0xFF;
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));
            oneByte = (len >> 8) & 0xFF;
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));
            oneByte = (len >> 16) & 0xFF;
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));

            // Type(8) Field --- Frame Type
            oneByte = type & 0xFF;
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));

            // Flags(8) Field
            oneByte = static_cast<std::uint8_t>(flag) & static_cast<std::uint8_t>(0xFF);
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));

            // R(1) + StreamId(31) Field
            std::uint32_t fourBytes;
            fourBytes = ((r & 0b1) << 31) | (stream & 0x7FFFFFFF);
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(fourBytes));

            // Frame Payload
            ss << in;

            return(ss.str());
        }

        std::string serialize(const std::string& in,
                                const std::uint8_t& type, const std::uint32_t& stream) {
            return(serialize(in.length(), in, type, fFlags(), fR(), stream));
        }

        std::string serialize(const std::string& in) {
            return(serialize(in.length(), in, fType(), fFlags(), fR(), fStream()));
        }

        std::string serialize() {
            return(serialize(fPayload().length(), fPayload(), fType(), fFlags(), fR(), fStream()));
        }
    };

    struct DataFrame {
        private:
          bool m_isPadding;
          std::uint8_t m_paddLength;
          std::string m_contents;
          std::string m_padding;
          std::vector<Http2::Flags> m_allowedFlags;
          std::string m_debug;

        public:
          DataFrame(): m_isPadding(false), m_paddLength(0), m_contents(""), m_padding(""), 
                       m_allowedFlags({Flags::END_STREAM, Flags::PADDED}), m_debug("ctor") {}
          ~DataFrame() = default;

          DataFrame(DataFrame& df) {
            isPadding(df.isPadding());
            paddLength(df.paddLength());
            contents(df.contents());
            padding(df.padding());
            allowedFlags(df.allowedFlags());
            debug("copy ctor");
          }

          DataFrame& operator=(DataFrame& df) {
            isPadding(df.isPadding());
            paddLength(df.paddLength());
            contents(df.contents());
            padding(df.padding());
            allowedFlags(df.allowedFlags());
            debug("copy assignment");
            return(*this);
          }

          // Move semantics copy ctor
          // e.g. DataFrame df = std::move(df);
          // DataFrame df1 = fn1(); ---> assigning temporary object
          DataFrame(DataFrame&& df) {
            isPadding(df.isPadding());
            paddLength(df.paddLength());
            contents(df.contents());
            padding(df.padding());
            allowedFlags(df.allowedFlags());
            df.isPadding(false);
            df.paddLength(0);
            df.contents("");
            df.padding("");
            df.allowedFlags({Flags::END_STREAM, Flags::PADDED});
            debug("move ctor");
          }

          // move assignment 
          // DataFrame df; df = std::move(objDataFrame); 
          // df = fn(); ---> assigning temporary object 
          DataFrame& operator=(DataFrame&& df) {
            isPadding(df.isPadding());
            paddLength(df.paddLength());
            contents(df.contents());
            padding(df.padding());
            allowedFlags(df.allowedFlags());
            df.isPadding(false);
            df.paddLength(0);
            df.contents("");
            df.padding("");
            df.allowedFlags({Flags::END_STREAM, Flags::PADDED});
            debug("move assignment");
            return(*this);
          }

          friend bool operator==(const Http2::Flags& left, const Http2::Flags& right) {
            return(static_cast<std::uint8_t>(left) == static_cast<std::uint8_t>(right));
          }

          friend bool operator==(const std::vector<Http2::Flags>& left, const Http2::Flags right) {
            auto it = std::find_if(left.begin(), left.end(), [&](auto const& ent) -> bool {return(ent == right);});
            return(it != left.end());
          }

          void allowedFlags(std::vector<Http2::Flags> af) {
            m_allowedFlags = af;
          }

          std::vector<Http2::Flags> allowedFlags() {
            return(m_allowedFlags);
          }

          void debug(std::string ds) {
            m_debug = ds;
          }
          std::string debug() {
            return(m_debug);
          }

          bool isPadding() const {
            return(m_isPadding);
          }

          std::uint8_t paddLength() const {
            return(m_paddLength);
          }

          std::string contents() const {
            return(m_contents);
          }

          std::string padding() const {
            return(m_padding);
          }

          void isPadding(bool pad) {
            m_isPadding = pad;
          }

          void paddLength(std::uint8_t len) {
            m_paddLength = len;
          }

          void contents(std::string content) {
            m_contents = content;
          }

          void padding(std::string paddValue) {
            m_padding = paddValue;
          }

          std::string serialize(const Http2::Flags& f, const std::string& data, const std::uint8_t& paddLength) {

            auto it = std::find_if(m_allowedFlags.begin(), m_allowedFlags.end(), [&](auto const& ent) -> bool {return(f== ent);});
            if(it == m_allowedFlags.end()) {
              return(std::string());
            }

            if(Flags::PADDED == f) {
              std::stringstream ss;
              std::uint8_t oneByte;

              // Padd Length(8) Field
              oneByte = paddLength & 0xFF;
              ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));
              ss << data;
              ss << std::string(paddLength, 0);
              return(ss.str());
            }

            return(data);
          }

          std::string serialize(const Http2::Flags& f) {
            return(serialize(f, contents(), paddLength()));
          }

          std::string serialize() {
            if(isPadding()) {
                return(serialize(Http2::Flags::PADDED, contents(), paddLength()));
            }

            return(serialize(Http2::Flags::END_STREAM, contents(), 0));
          }

          std::string deserialize(const Http2::Flags& f, const std::string& in) {
            if(Flags::PADDED == f && in.length() > 0) {
                isPadding(true);
                std::istringstream iss;
                iss.rdbuf()->pubsetbuf(const_cast<char *>(in.data()), in.length());
                std::uint8_t padd_len = iss.get();
                if(padd_len > 0) {
                    paddLength(padd_len);
                    contents(in.substr(in.length() - padd_len, padd_len));
                    return(contents());
                }
            }

            contents(in);
            return(contents());
          }
    };

    struct HeaderFrame {
        bool m_isPad;
        std::uint8_t m_paddLength;
        std::uint8_t m_e;
        std::uint32_t m_sd;
        std::uint8_t m_w;
        std::string m_data;
        std::vector<Http2::Flags> m_allowedFlags;

        HeaderFrame(): m_isPad(false), m_paddLength(0), m_data(""), m_allowedFlags({Flags::END_STREAM, Flags::END_HEADERS, Flags::PADDED, Flags::PRIORITY,  Flags::INVALID}) {}
        ~HeaderFrame() = default;

        std::string padded_header(const std::uint8_t& paddLength,
                                  const std::uint32_t& sd, const std::string& data) {
          std::uint8_t dont_care_w = 0;
          return(serialize(Http2::Flags::PADDED, paddLength, sd, dont_care_w, data));
        }

        std::string priority_header(const std::uint8_t& weight, const std::uint32_t& sd, const std::string& data) {
          std::uint8_t paddLength = 0;
          return(serialize(Http2::Flags::PRIORITY, paddLength, sd, weight, data));
        }

        private:
        std::string serialize(const Http2::Flags& f, const std::uint8_t& paddLength,
                              const std::uint32_t& sd, const std::uint8_t& weight, const std::string& data) {
          std::stringstream ss;
          std::uint8_t oneByte;
          std::uint32_t fourBytes;

          if(Http2::Flags::PADDED == f) {
            // Padd Length(8) Field
            oneByte = paddLength & 0xFF;
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));
          }

          if(Http2::Flags::PRIORITY == f) {
            // put exclusive bit.
            std::uint8_t exclusive = 1U;
            fourBytes = ((exclusive << 31) | (sd & 0x7FFFFFFF));
            ss.write(reinterpret_cast<char*>(&fourBytes), sizeof(fourBytes));
            oneByte = weight & 0xFF;
            ss.write(reinterpret_cast<char*>(&oneByte), sizeof(oneByte));
          } else {
            // no exclusive bit.
            fourBytes = sd & 0x7FFFFFFF;
            ss.write(reinterpret_cast<char*>(&fourBytes), sizeof(fourBytes));
          }

          
          

          
        }

    };

    struct Headers {

    };

    struct Priority {

    };

    struct RstStream {

    };

    struct Settings {

    };

    struct PushPromise {

    };

    struct Ping {

    };

    struct Goaway {

    };

    struct WindowUpdate {

    };

    struct Continuation {

    };

    struct ALTSVC {

    };

    struct Origin {

    };

    struct PriorityUpdate {

    };

    struct Frame : public std::variant< DataFrame, HeaderFrame, Priority, RstStream, Settings, PushPromise, 
                                        Ping, Goaway, WindowUpdate, Continuation, ALTSVC, Origin, PriorityUpdate > {
        // inherit ctor of std::variant
        using variant::variant;

    };

    Http2() = default;
    ~Http2() = default;
    private:
};

class Tls {
    public:
        Tls(): m_method(nullptr), m_ssl_ctx(nullptr, SSL_CTX_free), m_ssl(nullptr, SSL_free) {
        }
        ~Tls() {
        }

        std::int32_t init(std::int32_t fd) {
            m_method = TLS_client_method();
            m_ssl_ctx = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(SSL_CTX_new(m_method), SSL_CTX_free);
            m_ssl = std::unique_ptr<SSL, decltype(&SSL_free)>(nullptr, SSL_free);
            m_ssl.reset(SSL_new(m_ssl_ctx.get()));

            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();
            /* ---------------------------------------------------------- *
             * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
             * ---------------------------------------------------------- */
            SSL_CTX_set_options(m_ssl_ctx.get(), SSL_OP_NO_SSLv2);

            std::int32_t rc = SSL_set_fd(m_ssl.get(), fd);
            return(rc);
        }
        
        std::int32_t client() {
            std::int32_t rc = SSL_connect(m_ssl.get());
            return(rc);
        }

        std::int32_t read(std::string& out, const std::size_t& len) {
            if(len > 0) {
                std::vector<char> req(len);
                auto rc = SSL_read(m_ssl.get(), req.data(), len);
                if(rc <= 0) {
                    return(rc);
                }

                req.resize(rc);
                std::string tmp(req.begin(), req.end());
                out.assign(tmp);
                return(rc);
            }

            return(len);
        }
        
        std::int32_t write(const std::string& out, const std::size_t& len) {
            size_t offset = 0;

            while(len != offset) {
                auto rc = SSL_write(m_ssl.get(), out.data() + offset, len - offset);

                if(rc < 0) {
                    return(rc);
                }

                offset += rc;
            }

            return(offset);
        }

        auto& ssl_ctx() {
            return(*(m_ssl_ctx.get()));
        }

        auto& ssl() {
            return(*(m_ssl.get()));
        }

    private:
        const SSL_METHOD *m_method;
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> m_ssl_ctx;
        std::unique_ptr<SSL, decltype(&SSL_free)> m_ssl;
};

class HTTPServer : public Server {
    public:
        HTTPServer(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, 
                   const std::string& _localHost, const std::uint16_t& _localPort);
        virtual ~HTTPServer();
        virtual std::int32_t onReceive(const std::string& out) override;
        std::unordered_map<std::string, json>& entry() {
            return(m_entry);
        }
        void entry(std::string srNo, json ent) {
            m_entry[srNo] = ent;
        }
        std::string buildHeader(const std::string& path, const std::string& payload);
    private:
        std::unordered_map<std::string, json> m_entry;
};

class HTTPClient : public Client {
    public:
        using Key = std::string;
        using Value = std::string;

        enum HTTPUriName: std::uint32_t {
            RegisterDataPoints = 1,
            GetDataPoints,
            SetDataPoints,
            GetTokenForSession,
            GetChangeEventsNotification,
            RegisterLocation,
            NotifySOS,
            NotifyLocation,
            NotifyTelemetry,
            NotifySOSClear,
            ErrorUnknown
        };
        HTTPClient(const std::int32_t& _protocol, const bool& blocking, const bool& _ipv4, 
                   const std::string& _peerHost, const std::uint16_t& _peerPort, const std::string& _localHost, const std::uint16_t& _localPort);
        virtual ~HTTPClient();
        virtual std::int32_t onReceive(const std::string& out) override;
        std::unique_ptr<Tls>& tls();
        std::string endPoint();
        void endPoint(std::string ep);
        bool handleGetDatapointResponse(const std::string& in);
        bool handleSetDatapointResponse(const std::string& in);
        void processKeyValue(std::string const& key, json value);
        bool handleEventsNotificationResponse(const std::string& in);
        bool handleRegisterDatapointsResponse(const std::string& in);
        bool handleGetTokenResponse(const std::string& in);
        std::string processRequestAndBuildResponse(const std::string& in);
        std::string buildGetEventsNotificationRequest();
        std::string buildResponse(const std::string& payload);

        std::string uri(HTTPUriName name) const {
            auto it = std::find_if(m_uri.begin(), m_uri.end(), [&](const auto& ent) -> bool {return(name == ent.first);});
            if(it != m_uri.end()) {
                return(it->second);
            }

            return(std::string());
        }

        std::string token() const {
            return(m_token);
        }
        void token(std::string tk) {
            m_token = tk;
        }

        std::string cookie() const {
            return(m_cookie);
        }
        void cookie(std::string coo) {
            m_cookie = coo;
        }
        std::string buildHeader(HTTPUriName path, const std::string& payload);
        std::string buildGetTokenRequest(const std::string& userid, const std::string& pwd);
        std::string buildRegisterDatapointsRequest();
        HTTPUriName sentURI() {
            return(m_sentURI);
        }
        void sentURI(HTTPUriName uri) {
            m_sentURI = uri;
        }
        std::string userid() const {
            return(m_userid);
        }
        void userid(std::string id) {
            m_userid = id;
        }

        std::string password() const {
            return(m_password);
        }
        void password(std::string pwd) {
            m_password = pwd;
        }

        std::string serialNumber() {
            return(m_serialNumber);
        }
        std::string latitude() {
            return(m_latitude);
        }
        std::string longitude() {
            return(m_longitude);
        }

        std::uint32_t speed() {
            return(m_speed);
        }
        void speed(std::uint32_t sp) {
            m_speed = sp;
        }

        std::uint32_t rpm() {
            return(m_rpm);
        }

        void rpm(std::uint32_t rp) {
            m_rpm = rp;
        }

        void model(std::string m) {
            m_model = m;
        }
        std::string model() {
            return(m_model);
        }

        void sosEntry(std::string ent) {
            m_sosEntry = ent;
        }

        std::string sosEntry() {
            return(m_sosEntry);
        }

    private:
        std::unique_ptr<Tls> m_tls;
        std::string m_endPoint;
        std::string m_token;
        std::string m_cookie;
        /// @brief This is the user ID for Rest Interface
        std::string m_userid;
        /// @brief This is the password for REST interface
        std::string m_password;
        std::unordered_map<HTTPUriName, std::string> m_uri;
        std::vector<std::string> m_datapoints;
        HTTPUriName m_sentURI;
        std::string m_serialNumber;
        std::string m_model;
        std::string m_latitude;
        std::string m_longitude;
        std::int32_t m_speed;
        std::int32_t m_rpm;
        /// @brief  @brief An array of sos contents.
        std::string m_sosEntry;
};


#endif /*__services_http_hpp__*/