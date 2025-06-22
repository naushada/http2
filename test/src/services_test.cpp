#ifndef __services_test_cpp__
#define __services_test_cpp__

#include "services_test.hpp"

ServicesTest::ServicesTest() {
    m_tcpServer = std::make_shared<Server>(10, IPPROTO_TCP, true, true);
}

ServicesTest::~ServicesTest() {

}


void ServicesTest::SetUp() {
    
}

void ServicesTest::TearDown() {

}

void ServicesTest::TestBody() {

}

std::shared_ptr<Server> ServicesTest::tcpServer() const {
    return(m_tcpServer);
}

TEST_F(ServicesTest, TCPServerIPv4) {
    
    #if 0
    std::cout << "Handle: " << tcpServer()->handle() << std::endl;
    std::cout << "Protocol: " << tcpServer()->protocol() << std::endl;
    std::cout << "ipv4: " << tcpServer()->ipv4() << std::endl;
    std::cout << "Blocking: " << tcpServer()->blocking() << std::endl;
    #endif

    EXPECT_TRUE(tcpServer()->handle()> 0);
    EXPECT_EQ(tcpServer()->protocol(), IPPROTO_TCP);
    EXPECT_EQ(tcpServer()->ipv4(), true);
    EXPECT_EQ(tcpServer()->blocking(), true);
}









#endif /* __services_test_cpp__ */