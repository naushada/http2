#ifndef __command_line_argument_test_cpp__
#define __command_line_argument_test_cpp__

#include "command_line_argument_test.hpp"

CommandLineArgumentTest::CommandLineArgumentTest() {
    std::int32_t argc;
    char *const argv[] = {
        "intifada_test",
        /// @brief Command Arguments...
        "--role", "client",
        "--peer-host",  "192.168.1.1",
        "--peer-port",  "58989"
    };
    argc = 7;
    #if 0
    std::vector<std::string> arguments = {
        {"intifada_test"},
        /// @brief Command Arguments...
        {"--role"},       {"client"},
        {"--peer-host"},  {"192.168.1.1"},
        {"--peer-port"},  {"58989"},
        {"--local-host"}, {"192.168.2.1"},
        {"--local-port"}, {"58980"},
        {"--protocol"},   {"tcp"},
        {"--userid"},     {"abcd"},
        {"--password"},   {"abcd1234"},
        {"--timeout"},    {"10"},
        {"--long-poll"},  {"20"}
    };
    #endif
    m_commandArgument = std::make_shared<CommandLineArgument>(argc, argv);
}

CommandLineArgumentTest::~CommandLineArgumentTest() {

}

     
void CommandLineArgumentTest::SetUp() {

}

void CommandLineArgumentTest::TearDown() {
    std::cout << "TearDown & releasing Memory" << std::endl;
    m_commandArgument.reset();
}

void CommandLineArgumentTest::TestBody() {

}

std::shared_ptr<CommandLineArgument> CommandLineArgumentTest::commandInst() const {
    return(m_commandArgument);
}

TEST_F(CommandLineArgumentTest, Only3CommandLineArgument) {
    std::cout << "ent:" << commandInst()->arguments().size() << std::endl;
    commandInst()->dumpKey();
    Value value;
    auto result = commandInst()->getValue("role", value);
    EXPECT_TRUE(result);
    std::string out;
    value.getString(out);
    EXPECT_EQ("client", out);
    result = commandInst()->getValue("peer-host", value);
    EXPECT_TRUE(result);
    value.getString(out);
    EXPECT_EQ("192.168.1.1", out);
    result = commandInst()->getValue("peer-port", value);
    EXPECT_TRUE(result);
    std::uint16_t port = 0;
    value.getUint16(port);
    EXPECT_EQ(58989, port);
}

TEST_F(CommandLineArgumentTest, Only5CommandLineArgument) {
    std::int32_t argc;
    char *const argv[] = {
        "intifada_test",
        /// @brief Command Arguments...
        "--role",       "server",
        "--peer-host",  "192.168.1.1",
        "--peer-port",  "58989",
        "--local-host", "192.168.2.1",
        "--local-port", "58980",
        "--protocol",   "tcp",
        "--userid",     "abcd",
        "--password",   "abcd1234",
        "--timeout",    "10",
        "--long-poll",  "20"
    };
    argc = 21;
    Value value;
    commandInst()->parseOptions(argc, argv);
    std::cout << "ent:" << commandInst()->arguments().size() << std::endl;
    commandInst()->dumpKey();
    auto result = commandInst()->getValue("role", value);
    EXPECT_TRUE(result);
    std::string out;
    value.getString(out);
    EXPECT_EQ("server", out);
    result = commandInst()->getValue("peer-host", value);
    EXPECT_TRUE(result);
    value.getString(out);
    EXPECT_EQ("192.168.2.4", out);
    result = commandInst()->getValue("peer-port", value);
    EXPECT_TRUE(result);
    std::uint16_t port = 0;
    value.getUint16(port);
    EXPECT_EQ(58989, port);
    result = commandInst()->getValue("local-host", value);
    EXPECT_TRUE(result);
    value.getString(out);
    EXPECT_EQ("192.168.2.1", out);
    result = commandInst()->getValue("local-port", value);
    EXPECT_TRUE(result);
    port = 0;
    value.getUint16(port);
    EXPECT_EQ(58980, port);
}

#endif /*__command_line_argument_test_cpp__*/
