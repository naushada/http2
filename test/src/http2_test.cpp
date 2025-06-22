#ifndef __http2_test__
#define __http2_test__


#include "http_test.hpp"

Http2Test::Http2Test() {
    m_http2 = std::make_shared<Http2>();
}

Http2Test::~Http2Test() {

}


void Http2Test::SetUp() {
    
}

void Http2Test::TearDown() {

}

void Http2Test::TestBody() {

}

std::shared_ptr<Http2> Http2Test::http2() const {
    return(m_http2);
}

Http2::DataFrame Function() {
    Http2::DataFrame df;
    return(df);
}

TEST_F(Http2Test, ValueSemantics) {
    Http2::DataFrame dataFrame;
    EXPECT_EQ(dataFrame.debug(), "ctor");

    /* @brief df is not constructed and it will be constructed by copy constructor */
    Http2::DataFrame df = dataFrame;
    EXPECT_EQ(df.debug(), "copy ctor");

    auto Fn = [&]() -> Http2::DataFrame {
        Http2::DataFrame df;
        return(df);
    }();

    Http2::DataFrame df_second = Fn;
    EXPECT_EQ(df_second.debug(), "copy ctor");

    /* @brief df_second is already constructed hence compiler will invoke assignment operator */
    df_second = Fn;
    EXPECT_EQ(df_second.debug(), "copy assignment");
}

TEST_F(Http2Test, MoveSemantics) {
    Http2::DataFrame dataFrame;
    EXPECT_EQ(dataFrame.debug(), "ctor");
    
    /* @brief df_second is not constructed yet and Function returns a temporary object hence compiler will invoke move ctor */
    Http2::DataFrame df_second = Function();
    EXPECT_EQ(df_second.debug(), "move ctor");

    /* @brief df_second is already constructed and Function returns a temporary object hence compiler will invoke move assignment */
    df_second = Function();
    EXPECT_EQ(df_second.debug(), "move assignment");
}

TEST_F(Http2Test, MoveSemanticsExplicit) {
    Http2::DataFrame dataFrame;
    EXPECT_EQ(dataFrame.debug(), "ctor");
    

    auto Fn = [&]() -> Http2::DataFrame {
        Http2::DataFrame df;
        return(df);
    }();

    /* @brief df_second is not constructed yet and Function returns a temporary object we are enforcing compiler to invoke move ctor */
    Http2::DataFrame df_second = std::move(Fn);
    EXPECT_EQ(df_second.debug(), "move ctor");

    /* @brief df_second is already constructed and Function returns a temporary object and we are enforcing compiler to invoke move assignment */
    df_second = std::move(Fn);
    EXPECT_EQ(df_second.debug(), "move assignment");
}

#endif /*__http2_test__*/