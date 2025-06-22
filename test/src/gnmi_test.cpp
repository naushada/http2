#ifndef __gnmi_test_cpp__
#define __gnmi_test_cpp__

#include "gnmi_test.hpp"


GnmiTest::GnmiTest() {
    
}

GnmiTest::~GnmiTest() {

}


void GnmiTest::SetUp() {
    
}

void GnmiTest::TearDown() {

}

void GnmiTest::TestBody() {

}

GnmiTest::Path GnmiTest::buildGnmiPath(const std::string& xpath) {
  Path path;
  auto *ent = path.add_elem();
  ent->set_name("interfaces");
  ent = path.add_elem();
  ent->set_name("interface");
  auto *keyMap = ent->mutable_key();
  keyMap->insert({"name", "eth0"});
  std::cout << path.DebugString() << std::endl;
  return(path);
}

GnmiTest::GetRequest GnmiTest::buildGetRequest(const Path& path) {
  GetRequest getReq;

  return(getReq);
}

std::string GnmiTest::gnmi2Xpath(const Path& path) {
    std::string xpath;
    if(path.elem_size()) {
        for(auto const& pathEnt: path.elem()) {
          xpath += "/";
          xpath +=pathEnt.name();
          if(pathEnt.key_size()) {
            for(auto const& [k, v] : pathEnt.key()) {
              xpath +="[";
              xpath += k;
              xpath += "=";
              xpath += v;
              xpath +="]";
            }
          }
        }
    }
    return(xpath);
}

TEST_F(GnmiTest, GnmiGet_Path) {
    GnmiTest::Path path = buildGnmiPath("test");
    std::string xpath = gnmi2Xpath(path);
    std::cout << xpath << std::endl;    
}








#endif