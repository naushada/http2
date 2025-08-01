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

    // HTTP/2 Settings Identifiers (RFC 7540 Section 6.5.2)
    enum class SettingsIdentifier : std::uint16_t {
        HEADER_TABLE_SIZE = 0x1,
        ENABLE_PUSH = 0x2,
        MAX_CONCURRENT_STREAMS = 0x3,
        INITIAL_WINDOW_SIZE = 0x4,
        MAX_FRAME_SIZE = 0x5,
        MAX_HEADER_LIST_SIZE = 0x6
    };

    // HTTP/2 Default Settings Values
    static constexpr std::uint32_t DEFAULT_HEADER_TABLE_SIZE = 4096;
    static constexpr std::uint32_t DEFAULT_ENABLE_PUSH = 1;
    static constexpr std::uint32_t DEFAULT_MAX_CONCURRENT_STREAMS = 100;
    static constexpr std::uint32_t DEFAULT_INITIAL_WINDOW_SIZE = 65535;
    static constexpr std::uint32_t DEFAULT_MAX_FRAME_SIZE = 16384;
    static constexpr std::uint32_t DEFAULT_MAX_HEADER_LIST_SIZE = 262144;

    // HTTP/2 Connection Preface
    static constexpr const char* CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

        // Add deserialization method
        bool deserialize(const std::string& data, const Http2::Flags& flags) {
            if(data.empty()) return false;
            
            if(flags == Flags::PADDED) {
                if(data.length() < 1) return false;
                
                std::istringstream iss(data);
                std::uint8_t pad_len = iss.get();
                
                if(pad_len > 0 && data.length() > pad_len) {
                    m_paddLength = pad_len;
                    m_contents = data.substr(1, data.length() - 1 - pad_len);
                    m_padding = data.substr(data.length() - pad_len);
                    m_isPadding = true;
                } else {
                    m_contents = data.substr(1);
                    m_isPadding = false;
                }
            } else {
                m_contents = data;
                m_isPadding = false;
            }
            
            return true;
        }
    };

    struct HeaderFrame {
        private:
            bool m_isPad;
            std::uint8_t m_paddLength;
            std::uint8_t m_e;
            std::uint32_t m_sd;
            std::uint8_t m_w;
            std::string m_data;
            std::vector<Http2::Flags> m_allowedFlags;
            
        public:
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

              // Add the header block fragment data
              ss << data;
              
              return ss.str();
            }

            public:
            std::string serialize(const Http2::Flags& f, const std::string& data) {
                return serialize(f, m_paddLength, m_sd, m_w, data);
            }

            std::string serialize() {
                return serialize(m_allowedFlags[0], m_data);
            }

            void data(const std::string& d) { m_data = d; }
            std::string data() const { return m_data; }
            
            void sd(std::uint32_t stream_dep) { m_sd = stream_dep; }
            std::uint32_t sd() const { return m_sd; }
            
            void w(std::uint8_t weight) { m_w = weight; }
            std::uint8_t w() const { return m_w; }
            
            void e(std::uint8_t exclusive) { m_e = exclusive; }
            std::uint8_t e() const { return m_e; }
            
            void paddLength(std::uint8_t len) { m_paddLength = len; }
            std::uint8_t paddLength() const { return m_paddLength; }
            
            void isPad(bool pad) { m_isPad = pad; }
            bool isPad() const { return m_isPad; }
    };

    struct Headers {
        private:
            std::string m_header_block_fragment;
            std::vector<Http2::Flags> m_allowedFlags;
            
        public:
            Headers(): m_header_block_fragment(""), 
                      m_allowedFlags({Flags::END_STREAM, Flags::END_HEADERS, Flags::PADDED, Flags::PRIORITY}) {}
            ~Headers() = default;
            
            std::string serialize(const Http2::Flags& f, const std::string& header_block) {
                auto it = std::find_if(m_allowedFlags.begin(), m_allowedFlags.end(), 
                                      [&](auto const& ent) -> bool {return(f == ent);});
                if(it == m_allowedFlags.end()) {
                    return std::string();
                }
                
                m_header_block_fragment = header_block;
                return m_header_block_fragment;
            }
            
            std::string serialize() {
                return serialize(Flags::END_HEADERS, m_header_block_fragment);
            }
            
            void headerBlockFragment(const std::string& fragment) { m_header_block_fragment = fragment; }
            std::string headerBlockFragment() const { return m_header_block_fragment; }
    };

    struct Priority {
        private:
            std::uint8_t m_exclusive;
            std::uint32_t m_stream_dependency;
            std::uint8_t m_weight;
            
        public:
            Priority(): m_exclusive(0), m_stream_dependency(0), m_weight(16) {}
            ~Priority() = default;
            
            std::string serialize() {
                std::stringstream ss;
                std::uint32_t fourBytes;
                
                // E(1) + Stream Dependency(31)
                fourBytes = ((m_exclusive & 0b1) << 31) | (m_stream_dependency & 0x7FFFFFFF);
                ss.write(reinterpret_cast<char*>(&fourBytes), sizeof(fourBytes));
                
                // Weight(8)
                std::uint8_t weight = m_weight & 0xFF;
                ss.write(reinterpret_cast<char*>(&weight), sizeof(weight));
                
                return ss.str();
            }
            
            void exclusive(std::uint8_t e) { m_exclusive = e; }
            std::uint8_t exclusive() const { return m_exclusive; }
            
            void streamDependency(std::uint32_t sd) { m_stream_dependency = sd; }
            std::uint32_t streamDependency() const { return m_stream_dependency; }
            
            void weight(std::uint8_t w) { m_weight = w; }
            std::uint8_t weight() const { return m_weight; }
    };

    struct RstStream {
        private:
            std::uint32_t m_error_code;
            
        public:
            RstStream(): m_error_code(static_cast<std::uint32_t>(ErrorCodes::NO_ERROR)) {}
            ~RstStream() = default;
            
            std::string serialize() {
                std::stringstream ss;
                std::uint32_t error_code = m_error_code;
                ss.write(reinterpret_cast<char*>(&error_code), sizeof(error_code));
                return ss.str();
            }
            
            void errorCode(std::uint32_t code) { m_error_code = code; }
            std::uint32_t errorCode() const { return m_error_code; }
            
            void errorCode(ErrorCodes code) { m_error_code = static_cast<std::uint32_t>(code); }
            
            // Add deserialization method
            bool deserialize(const std::string& data) {
                if(data.length() != 4) return false;
                
                std::istringstream iss(data);
                std::uint32_t error_code;
                iss.read(reinterpret_cast<char*>(&error_code), sizeof(error_code));
                
                if(isValidErrorCode(error_code)) {
                    m_error_code = error_code;
                    return true;
                }
                
                return false;
            }
    };

    struct Settings {
        private:
            std::vector<std::pair<std::uint16_t, std::uint32_t>> m_settings;
            
        public:
            Settings(): m_settings() {}
            ~Settings() = default;
            
            std::string serialize() {
                std::stringstream ss;
                for(const auto& setting : m_settings) {
                    std::uint16_t identifier = setting.first;
                    std::uint32_t value = setting.second;
                    ss.write(reinterpret_cast<char*>(&identifier), sizeof(identifier));
                    ss.write(reinterpret_cast<char*>(&value), sizeof(value));
                }
                return ss.str();
            }
            
            void addSetting(std::uint16_t identifier, std::uint32_t value) {
                m_settings.emplace_back(identifier, value);
            }
            
            void clearSettings() { m_settings.clear(); }
            
            const std::vector<std::pair<std::uint16_t, std::uint32_t>>& getSettings() const {
                return m_settings;
            }
            
            // Add deserialization method
            bool deserialize(const std::string& data) {
                if(data.length() % 6 != 0) return false; // Each setting is 6 bytes
                
                m_settings.clear();
                std::istringstream iss(data);
                
                while(iss.tellg() < static_cast<std::streampos>(data.length())) {
                    std::uint16_t identifier;
                    std::uint32_t value;
                    
                    iss.read(reinterpret_cast<char*>(&identifier), sizeof(identifier));
                    iss.read(reinterpret_cast<char*>(&value), sizeof(value));
                    
                    m_settings.emplace_back(identifier, value);
                }
                
                return true;
            }
    };

    struct PushPromise {
        private:
            std::uint8_t m_padd_length;
            std::uint32_t m_promised_stream_id;
            std::string m_header_block_fragment;
            
        public:
            PushPromise(): m_padd_length(0), m_promised_stream_id(0), m_header_block_fragment("") {}
            ~PushPromise() = default;
            
            std::string serialize(const Http2::Flags& f) {
                std::stringstream ss;
                
                if(f == Flags::PADDED) {
                    std::uint8_t pad_len = m_padd_length;
                    ss.write(reinterpret_cast<char*>(&pad_len), sizeof(pad_len));
                }
                
                // Promised Stream ID (31 bits)
                std::uint32_t stream_id = m_promised_stream_id & 0x7FFFFFFF;
                ss.write(reinterpret_cast<char*>(&stream_id), sizeof(stream_id));
                
                // Header Block Fragment
                ss << m_header_block_fragment;
                
                return ss.str();
            }
            
            void paddLength(std::uint8_t len) { m_padd_length = len; }
            std::uint8_t paddLength() const { return m_padd_length; }
            
            void promisedStreamId(std::uint32_t id) { m_promised_stream_id = id; }
            std::uint32_t promisedStreamId() const { return m_promised_stream_id; }
            
            void headerBlockFragment(const std::string& fragment) { m_header_block_fragment = fragment; }
            std::string headerBlockFragment() const { return m_header_block_fragment; }
    };

    struct Ping {
        private:
            std::uint64_t m_opaque_data;
            
        public:
            Ping(): m_opaque_data(0) {}
            ~Ping() = default;
            
            std::string serialize() {
                std::stringstream ss;
                std::uint64_t data = m_opaque_data;
                ss.write(reinterpret_cast<char*>(&data), sizeof(data));
                return ss.str();
            }
            
            void opaqueData(std::uint64_t data) { m_opaque_data = data; }
            std::uint64_t opaqueData() const { return m_opaque_data; }
            
            // Add deserialization method
            bool deserialize(const std::string& data) {
                if(data.length() != 8) return false; // Ping is exactly 8 bytes
                
                std::istringstream iss(data);
                std::uint64_t ping_data;
                iss.read(reinterpret_cast<char*>(&ping_data), sizeof(ping_data));
                
                m_opaque_data = ping_data;
                return true;
            }
    };

    struct Goaway {
        private:
            std::uint32_t m_last_stream_id;
            std::uint32_t m_error_code;
            std::string m_additional_debug_data;
            
        public:
            Goaway(): m_last_stream_id(0), m_error_code(static_cast<std::uint32_t>(ErrorCodes::NO_ERROR)), 
                     m_additional_debug_data("") {}
            ~Goaway() = default;
            
            std::string serialize() {
                std::stringstream ss;
                
                // Last Stream ID (31 bits)
                std::uint32_t stream_id = m_last_stream_id & 0x7FFFFFFF;
                ss.write(reinterpret_cast<char*>(&stream_id), sizeof(stream_id));
                
                // Error Code
                std::uint32_t error_code = m_error_code;
                ss.write(reinterpret_cast<char*>(&error_code), sizeof(error_code));
                
                // Additional Debug Data
                ss << m_additional_debug_data;
                
                return ss.str();
            }
            
            void lastStreamId(std::uint32_t id) { m_last_stream_id = id; }
            std::uint32_t lastStreamId() const { return m_last_stream_id; }
            
            void errorCode(std::uint32_t code) { m_error_code = code; }
            std::uint32_t errorCode() const { return m_error_code; }
            
            void errorCode(ErrorCodes code) { m_error_code = static_cast<std::uint32_t>(code); }
            
            void additionalDebugData(const std::string& data) { m_additional_debug_data = data; }
            std::string additionalDebugData() const { return m_additional_debug_data; }
            
            // Add deserialization method
            bool deserialize(const std::string& data) {
                if(data.length() < 8) return false;
                
                std::istringstream iss(data);
                
                // Read Last Stream ID
                std::uint32_t stream_id;
                iss.read(reinterpret_cast<char*>(&stream_id), sizeof(stream_id));
                m_last_stream_id = stream_id & 0x7FFFFFFF;
                
                // Read Error Code
                std::uint32_t error_code;
                iss.read(reinterpret_cast<char*>(&error_code), sizeof(error_code));
                
                if(isValidErrorCode(error_code)) {
                    m_error_code = error_code;
                } else {
                    return false;
                }
                
                // Read Additional Debug Data
                if(data.length() > 8) {
                    m_additional_debug_data = data.substr(8);
                }
                
                return true;
            }
    };

    struct WindowUpdate {
        private:
            std::uint32_t m_window_size_increment;
            
        public:
            WindowUpdate(): m_window_size_increment(0) {}
            ~WindowUpdate() = default;
            
            std::string serialize() {
                std::stringstream ss;
                std::uint32_t increment = m_window_size_increment;
                ss.write(reinterpret_cast<char*>(&increment), sizeof(increment));
                return ss.str();
            }
            
            void windowSizeIncrement(std::uint32_t increment) { m_window_size_increment = increment; }
            std::uint32_t windowSizeIncrement() const { return m_window_size_increment; }
            
            // Add deserialization method
            bool deserialize(const std::string& data) {
                if(data.length() != 4) return false; // Window update is exactly 4 bytes
                
                std::istringstream iss(data);
                std::uint32_t increment;
                iss.read(reinterpret_cast<char*>(&increment), sizeof(increment));
                
                m_window_size_increment = increment;
                return true;
            }
    };

    struct Continuation {
        private:
            std::string m_header_block_fragment;
            
        public:
            Continuation(): m_header_block_fragment("") {}
            ~Continuation() = default;
            
            std::string serialize() {
                return m_header_block_fragment;
            }
            
            void headerBlockFragment(const std::string& fragment) { m_header_block_fragment = fragment; }
            std::string headerBlockFragment() const { return m_header_block_fragment; }
    };

    struct ALTSVC {
        private:
            std::uint16_t m_origin_len;
            std::string m_origin;
            std::string m_alt_svc_field_value;
            
        public:
            ALTSVC(): m_origin_len(0), m_origin(""), m_alt_svc_field_value("") {}
            ~ALTSVC() = default;
            
            std::string serialize() {
                std::stringstream ss;
                
                // Origin Length
                std::uint16_t origin_len = m_origin_len;
                ss.write(reinterpret_cast<char*>(&origin_len), sizeof(origin_len));
                
                // Origin
                ss << m_origin;
                
                // Alt-Svc Field Value
                ss << m_alt_svc_field_value;
                
                return ss.str();
            }
            
            void originLength(std::uint16_t len) { m_origin_len = len; }
            std::uint16_t originLength() const { return m_origin_len; }
            
            void origin(const std::string& o) { m_origin = o; }
            std::string origin() const { return m_origin; }
            
            void altSvcFieldValue(const std::string& value) { m_alt_svc_field_value = value; }
            std::string altSvcFieldValue() const { return m_alt_svc_field_value; }
    };

    struct Origin {
        private:
            std::vector<std::string> m_origins;
            
        public:
            Origin(): m_origins() {}
            ~Origin() = default;
            
            std::string serialize() {
                std::stringstream ss;
                for(const auto& origin : m_origins) {
                    std::uint16_t len = static_cast<std::uint16_t>(origin.length());
                    ss.write(reinterpret_cast<char*>(&len), sizeof(len));
                    ss << origin;
                }
                return ss.str();
            }
            
            void addOrigin(const std::string& origin) { m_origins.push_back(origin); }
            void clearOrigins() { m_origins.clear(); }
            
            const std::vector<std::string>& getOrigins() const { return m_origins; }
    };

    struct PriorityUpdate {
        private:
            std::uint32_t m_stream_id;
            std::string m_priority_field_value;
            
        public:
            PriorityUpdate(): m_stream_id(0), m_priority_field_value("") {}
            ~PriorityUpdate() = default;
            
            std::string serialize() {
                std::stringstream ss;
                
                // Stream ID
                std::uint32_t stream_id = m_stream_id;
                ss.write(reinterpret_cast<char*>(&stream_id), sizeof(stream_id));
                
                // Priority Field Value
                ss << m_priority_field_value;
                
                return ss.str();
            }
            
            void streamId(std::uint32_t id) { m_stream_id = id; }
            std::uint32_t streamId() const { return m_stream_id; }
            
            void priorityFieldValue(const std::string& value) { m_priority_field_value = value; }
            std::string priorityFieldValue() const { return m_priority_field_value; }
    };

    struct Frame : public std::variant< DataFrame, HeaderFrame, Priority, RstStream, Settings, PushPromise, 
                                        Ping, Goaway, WindowUpdate, Continuation, ALTSVC, Origin, PriorityUpdate > {
        // inherit ctor of std::variant
        using variant::variant;

    };

    Http2() = default;
    ~Http2() = default;

    // Utility methods for HTTP/2 operations
    static bool isValidFrameType(std::uint8_t type) {
        return type <= static_cast<std::uint8_t>(FType::PRIORITY_UPDATE);
    }

    static bool isValidErrorCode(std::uint32_t code) {
        return code <= static_cast<std::uint32_t>(ErrorCodes::HTTP_1_1_REQUIRED);
    }

    static std::string getErrorCodeString(ErrorCodes code) {
        switch(code) {
            case ErrorCodes::NO_ERROR: return "NO_ERROR";
            case ErrorCodes::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
            case ErrorCodes::INTERNAL_ERROR: return "INTERNAL_ERROR";
            case ErrorCodes::FLOW_CONTROL_ERROR: return "FLOW_CONTROL_ERROR";
            case ErrorCodes::SETTINGS_TIMEOUT: return "SETTINGS_TIMEOUT";
            case ErrorCodes::STREAM_CLOSED: return "STREAM_CLOSED";
            case ErrorCodes::FRAME_SIZE_ERROR: return "FRAME_SIZE_ERROR";
            case ErrorCodes::REFUSED_STREAM: return "REFUSED_STREAM";
            case ErrorCodes::CANCEL: return "CANCEL";
            case ErrorCodes::COMPRESSION_ERROR: return "COMPRESSION_ERROR";
            case ErrorCodes::CONNECT_ERROR: return "CONNECT_ERROR";
            case ErrorCodes::ENHANCE_YOUR_CALM: return "ENHANCE_YOUR_CALM";
            case ErrorCodes::INADEQUATE_SECURITY: return "INADEQUATE_SECURITY";
            case ErrorCodes::HTTP_1_1_REQUIRED: return "HTTP_1_1_REQUIRED";
            default: return "UNKNOWN_ERROR";
        }
    }

    static std::string getFrameTypeString(FType type) {
        switch(type) {
            case FType::DATA: return "DATA";
            case FType::HEADERS: return "HEADERS";
            case FType::PRIORITY: return "PRIORITY";
            case FType::RST_STREAM: return "RST_STREAM";
            case FType::SETTINGS: return "SETTINGS";
            case FType::PUSH_PROMISE: return "PUSH_PROMISE";
            case FType::PING: return "PING";
            case FType::GOAWAY: return "GOAWAY";
            case FType::WINDOW_UPDATE: return "WINDOW_UPDATE";
            case FType::CONTINUATION: return "CONTINUATION";
            case FType::ALTSVC: return "ALTSVC";
            case FType::UNASSIGNED: return "UNASSIGNED";
            case FType::ORIGIN: return "ORIGIN";
            case FType::PRIORITY_UPDATE: return "PRIORITY_UPDATE";
            default: return "UNKNOWN_FRAME_TYPE";
        }
    }

    // Frame parsing utility
    static FrameFormat parseFrame(const std::string& frame_data) {
        FrameFormat frame;
        if(frame_data.length() < 9) { // Minimum frame header size
            return frame;
        }

        std::istringstream iss(frame_data);
        
        // Parse Length (24 bits)
        std::uint8_t len_bytes[3];
        iss.read(reinterpret_cast<char*>(len_bytes), 3);
        frame.fLength((len_bytes[0] << 16) | (len_bytes[1] << 8) | len_bytes[2]);

        // Parse Type (8 bits)
        std::uint8_t type;
        iss.read(reinterpret_cast<char*>(&type), 1);
        frame.fType(type);

        // Parse Flags (8 bits)
        std::uint8_t flags;
        iss.read(reinterpret_cast<char*>(&flags), 1);
        frame.fFlags(static_cast<Flags>(flags));

        // Parse R (1 bit) + Stream ID (31 bits)
        std::uint32_t stream_data;
        iss.read(reinterpret_cast<char*>(&stream_data), 4);
        frame.fR((stream_data >> 31) & 0x1);
        frame.fStream(stream_data & 0x7FFFFFFF);

        // Parse Payload
        if(frame.fLength() > 0) {
            std::string payload(frame_data.substr(9, frame.fLength()));
            frame.fPayload(payload);
        }

        return frame;
    }

    // Create default settings frame
    static Settings createDefaultSettings() {
        Settings settings;
        settings.addSetting(static_cast<std::uint16_t>(SettingsIdentifier::HEADER_TABLE_SIZE), 
                           DEFAULT_HEADER_TABLE_SIZE);
        settings.addSetting(static_cast<std::uint16_t>(SettingsIdentifier::ENABLE_PUSH), 
                           DEFAULT_ENABLE_PUSH);
        settings.addSetting(static_cast<std::uint16_t>(SettingsIdentifier::MAX_CONCURRENT_STREAMS), 
                           DEFAULT_MAX_CONCURRENT_STREAMS);
        settings.addSetting(static_cast<std::uint16_t>(SettingsIdentifier::INITIAL_WINDOW_SIZE), 
                           DEFAULT_INITIAL_WINDOW_SIZE);
        settings.addSetting(static_cast<std::uint16_t>(SettingsIdentifier::MAX_FRAME_SIZE), 
                           DEFAULT_MAX_FRAME_SIZE);
        settings.addSetting(static_cast<std::uint16_t>(SettingsIdentifier::MAX_HEADER_LIST_SIZE), 
                           DEFAULT_MAX_HEADER_LIST_SIZE);
        return settings;
    }

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

// HTTP/2 HPACK Compression Support (Simplified Implementation)
namespace HPACK {
    struct HeaderField {
        std::string name;
        std::string value;
        bool indexed;
        
        HeaderField(const std::string& n, const std::string& v, bool idx = false) 
            : name(n), value(v), indexed(idx) {}
    };
    
    class Encoder {
    private:
        std::vector<HeaderField> m_dynamic_table;
        std::uint32_t m_max_table_size;
        
    public:
        Encoder();
        std::string encode(const std::vector<HeaderField>& headers);
    };
    
    class Decoder {
    private:
        std::vector<HeaderField> m_dynamic_table;
        std::string readString(std::istringstream& input);
        
    public:
        Decoder();
        std::vector<HeaderField> decode(const std::string& encoded_data);
    };
}

// HTTP/2 Flow Control Implementation
class FlowControl {
private:
    std::uint32_t m_initial_window_size;
    std::uint32_t m_current_window_size;
    std::unordered_map<std::uint32_t, std::uint32_t> m_stream_windows;
    
public:
    FlowControl(std::uint32_t initial_size = 65535);
    bool canSendData(std::uint32_t stream_id, std::uint32_t data_size);
    void consumeWindow(std::uint32_t stream_id, std::uint32_t data_size);
    void updateWindow(std::uint32_t stream_id, std::uint32_t increment);
    std::uint32_t getWindowSize(std::uint32_t stream_id) const;
};

// HTTP/2 Stream Management
class StreamManager {
private:
    std::unordered_map<std::uint32_t, std::string> m_streams;
    std::uint32_t m_next_client_stream_id;
    std::uint32_t m_next_server_stream_id;
    
public:
    StreamManager();
    std::uint32_t createClientStream();
    std::uint32_t createServerStream();
    void closeStream(std::uint32_t stream_id);
    bool isStreamOpen(std::uint32_t stream_id) const;
    void addStreamData(std::uint32_t stream_id, const std::string& data);
    std::string getStreamData(std::uint32_t stream_id) const;
    void clearStreamData(std::uint32_t stream_id);
};

// HTTP/2 Client Implementation
class Http2Client {
private:
    std::unique_ptr<Tls> m_tls;
    std::string m_host;
    std::uint16_t m_port;
    std::unique_ptr<FlowControl> m_flow_control;
    std::unique_ptr<StreamManager> m_stream_manager;
    std::unique_ptr<HPACK::Encoder> m_hpack_encoder;
    Http2::Settings m_settings;
    bool m_connection_established;

    std::string createHeadersBlock(const std::string& method, const std::string& path,
                                  const std::unordered_map<std::string, std::string>& headers);
    std::string parseHttp2Response(const std::string& frame_data);
    std::string parseHeadersPayload(const std::string& payload);

public:
    Http2Client(const std::string& host, std::uint16_t port);
    ~Http2Client() = default;

    bool connect();
    std::string sendRequest(const std::string& method, const std::string& path, 
                           const std::string& body = "", 
                           const std::unordered_map<std::string, std::string>& headers = {});
    std::string receiveResponse();
    void sendWindowUpdate(std::uint32_t stream_id, std::uint32_t increment);
    void sendPing();
};

// HTTP/2 Server Implementation
class Http2Server {
private:
    std::unique_ptr<FlowControl> m_flow_control;
    std::unique_ptr<StreamManager> m_stream_manager;
    std::unique_ptr<HPACK::Decoder> m_hpack_decoder;
    std::unique_ptr<HPACK::Encoder> m_hpack_encoder;
    Http2::Settings m_settings;
    std::uint32_t m_next_stream_id;

    std::string handleHeadersFrame(const Http2::FrameFormat& frame);
    std::string handleDataFrame(const Http2::FrameFormat& frame);
    std::string handleSettingsFrame(const Http2::FrameFormat& frame);
    std::string handlePingFrame(const Http2::FrameFormat& frame);
    std::string handleWindowUpdateFrame(const Http2::FrameFormat& frame);
    std::string createGoawayFrame(Http2::ErrorCodes error_code);
    void parseRequestHeaders(const std::string& payload, std::string& method, std::string& path);
    std::string createResponseHeaders();
    std::string generateResponseBody(const std::string& method, const std::string& path);

public:
    Http2Server();
    ~Http2Server() = default;

    std::string handleRequest(const std::string& frame_data);
};

// HTTP/2 Utility Functions
namespace Http2Utils {
    std::string createConnectionPreface();
    bool validateFrame(const std::string& frame_data);
    std::string createSettingsFrame(const Http2::Settings& settings);
    std::string createWindowUpdateFrame(std::uint32_t stream_id, std::uint32_t increment);
    std::string createPingFrame(std::uint64_t data = 0);
    std::string createGoawayFrame(std::uint32_t last_stream_id, Http2::ErrorCodes error_code);
}

// HTTP/2 Enhanced HTTPClient
class HTTP2Client : public HTTPClient {
private:
    std::unique_ptr<Http2Client> m_http2_client;
    bool m_use_http2;

public:
    HTTP2Client(const std::int32_t& _protocol, const bool& _blocking, const bool& _ipv4, 
                const std::string& _peerHost, const std::uint16_t& _peerPort, 
                const std::string& _localHost, const std::uint16_t& _localPort);

    std::string sendHttp2Request(const std::string& method, const std::string& path, 
                                const std::string& body = "");
    std::string receiveHttp2Response();
    bool connectHttp2();
};

// HTTP/2 Enhanced HTTPServer
class HTTP2Server : public HTTPServer {
private:
    std::unique_ptr<Http2Server> m_http2_server;

public:
    HTTP2Server(const std::int32_t& _qsize, const std::int32_t& _protocol, const bool& _blocking, 
                const bool& _ipv4, const std::string& _localHost, const std::uint16_t& _localPort);

    std::int32_t onReceiveHttp2(const std::string& request_data);
};


#endif /*__services_http_hpp__*/