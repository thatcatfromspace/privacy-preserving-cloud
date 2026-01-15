#include "src/crypto/GroupSig.hpp"
#include <cassert>
#include <iostream>
#include <memory>
#include <vector>

// We need to link against the implementation instance
// For simplicity in test, we can just instantiate the class if header is
// exposed or include the cpp Or verify the factory. Here we will define the
// class locally or include a header that exposes it. Since RSAGroupSig is in a
// named namespace and defined in .cpp, we might need a factory. To satisfy the
// linker, we included RSAGroupSig.cpp in the library. But we need the
// declaration.

// Let's modify RSAGroupSig to be exposed in a header or just include the source
// for the test for simplicity or add a Factory function in GroupSig.hpp.

// Ideally, we'd add "std::unique_ptr<GroupSig> CreateGroupSig();" in
// GroupSig.hpp For now, let's just cheat and assume we can instantiate it if we
// include the class decl. But the class decl is in the .cpp file. Fix: I will
// add a Factory function to GroupSig.hpp and implement it in RSAGroupSig.cpp

#include "src/crypto/GroupSig.hpp"

namespace CloudPrivacy {
std::unique_ptr<GroupSig> CreateGroupSig();
}

int main() {
  auto groupSig = CloudPrivacy::CreateGroupSig();
  CloudPrivacy::GroupPublicKey gpk;
  CloudPrivacy::ManagerSecretKey msk;

  std::cout << "1. Setup..." << std::endl;
  groupSig->Setup(gpk, msk);
  std::cout << "   GPK Size: " << gpk.n.size() << std::endl;

  std::cout << "2. Join..." << std::endl;
  std::string userId = "user_123";
  auto memberKey = groupSig->Join(gpk, msk, userId);
  std::cout << "   Member Token: " << memberKey.certificate << std::endl;

  std::cout << "3. Sign..." << std::endl;
  std::string msg = "Hello World";
  auto sig = groupSig->Sign(msg, gpk, memberKey);
  std::cout << "   Signature: " << sig.data << std::endl;

  std::cout << "4. Verify..." << std::endl;
  bool valid = groupSig->Verify(msg, sig, gpk);
  if (valid)
    std::cout << "   [PASS] Signature Verified" << std::endl;
  else
    std::cout << "   [FAIL] Signature Invalid" << std::endl;
  assert(valid);

  std::cout << "5. Revocation Check..." << std::endl;
  std::vector<std::string> revoked = {"user_999"};
  assert(!groupSig->IsRevoked(sig, revoked));

  revoked.push_back("user_123");
  bool isRevoked = groupSig->IsRevoked(sig, revoked);
  if (isRevoked)
    std::cout << "   [PASS] User correctly identified as revoked" << std::endl;
  else
    std::cout << "   [FAIL] User should be revoked" << std::endl;
  assert(isRevoked);

  return 0;
}
