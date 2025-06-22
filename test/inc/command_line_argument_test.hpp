#ifndef __command_line_argument_test_hpp__
#define __command_line_argument_test_hpp__

#include <iostream>
#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include <fstream>

#include "command_line_argument.hpp"

class CommandLineArgumentTest : public ::testing::Test
{
    public:
        CommandLineArgumentTest();
        virtual ~CommandLineArgumentTest();
     
        virtual void SetUp() override;
        virtual void TearDown() override;
        virtual void TestBody() override;
        std::shared_ptr<CommandLineArgument> commandInst() const;
    private:
        std::shared_ptr<CommandLineArgument> m_commandArgument;
        

};

#endif /* __command_line_argument_test_hpp__ */