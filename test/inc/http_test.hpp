#ifndef __http_test_hpp__
#define __http_test_hpp__

#include <iostream>
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include <fstream>

#include "services_http.hpp"

class Http2Test : public ::testing::Test
{
    public:
        Http2Test();
        virtual ~Http2Test();
     
        virtual void SetUp() override;
        virtual void TearDown() override;
        virtual void TestBody() override;
        std::shared_ptr<Http2> http2() const;
    private:
        std::shared_ptr<Http2> m_http2;
        

};

#endif /* __services_test_hpp__ */