#ifndef __gnmi_test_hpp__
#define __gnmi_test_hpp__

#include "gnmi.pb.h"
#include <iostream>
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>


class GnmiTest : public ::testing::Test
{
    public:
        GnmiTest();
        virtual ~GnmiTest();
     
        virtual void SetUp() override;
        virtual void TearDown() override;
        virtual void TestBody() override;
        using GetRequest = gnmi::GetRequest;
        using GetResponse = gnmi::GetResponse;
        using CapabilityRequest = gnmi::CapabilityRequest;
        using CapabilityResponse = gnmi::CapabilityResponse;
        using Notification = gnmi::Notification;
        using SubscribeRequest = gnmi::SubscribeRequest;
        using SubscribeResponse = gnmi::SubscribeResponse;
        using SetRequest = gnmi::SetRequest;
        using SetResponse = gnmi::SetResponse;
        using Path = gnmi::Path;
        Path buildGnmiPath(const std::string& xpath);
        GetRequest buildGetRequest(const Path& path);
        std::string gnmi2Xpath(const Path& path);
    private:
        
        

};


#endif