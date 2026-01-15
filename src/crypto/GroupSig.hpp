#pragma once

#include <memory>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <string>
#include <vector>

namespace CloudPrivacy {

struct GroupPublicKey {
  std::string n; // modulo
  std::string e; // exponent
};

struct ManagerSecretKey {
  std::string p;
  std::string q;
  std::string d;
};

struct MemberKey {
  std::string id;
  std::string secret;
  std::string certificate; // membership token
};

struct Signature {
  std::string data; // actual signature data
};

class GroupSig {
public:
  virtual ~GroupSig() = default;

  // manager sets up the group
  virtual void Setup(GroupPublicKey &gpk, ManagerSecretKey &msk) = 0;

  // user joins the group 
  // returns the member key
  virtual MemberKey Join(const GroupPublicKey &gpk, const ManagerSecretKey &msk,
                         const std::string &userId) = 0;

  // member signs a message
  virtual Signature Sign(const std::string &message, const GroupPublicKey &gpk,
                         const MemberKey &memberKey) = 0;

  // verifier checks the signature
  virtual bool Verify(const std::string &message, const Signature &sig,
                      const GroupPublicKey &gpk) = 0;

  // check if a user is revoked (using the signature to identify/link)
  virtual bool IsRevoked(const Signature &sig,
                         const std::vector<std::string> &revokedIds) = 0;

  // extract ID from signature (open) - for the RM/Manager
  virtual std::string Open(const Signature &sig,
                           const ManagerSecretKey &msk) = 0;
};

std::unique_ptr<GroupSig> CreateGroupSig();

} 
