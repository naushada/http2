#ifndef __services_test_hpp__
#define __services_test_hpp__

#include <iostream>
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include <fstream>

#include "services.hpp"
#include  "gnmi.pb.h"

class ServicesTest : public ::testing::Test
{
    public:
        ServicesTest();
        virtual ~ServicesTest();
     
        virtual void SetUp() override;
        virtual void TearDown() override;
        virtual void TestBody() override;
        std::shared_ptr<Server> tcpServer() const;
    private:
        std::shared_ptr<Server> m_tcpServer;
        

};

#endif /* __services_test_hpp__ */