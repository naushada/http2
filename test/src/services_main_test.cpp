#ifndef __services_main_test_cpp__
#define __services_main_test_cpp__

#include <gtest/gtest.h>

int main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}



#endif /* __services_main_test_cpp__*/