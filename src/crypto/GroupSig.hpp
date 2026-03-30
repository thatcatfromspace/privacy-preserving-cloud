#pragma once

#include <memory>
#include <string>
#include <vector>

namespace CloudPrivacy {

// Public parameters (GPK)
struct GroupPublicKey {
  std::string n; // modulo n = r^2 s
  std::string g1;
  std::string g2;
  std::string g3;
  std::string A_proof;
  std::string p; // Schnorr group mod p
  std::string q; // Schnorr group order q
  std::string h1;
  std::string h2;

  std::string Serialize() const;
  static GroupPublicKey Deserialize(const std::string& str);
};

// Manager secret parameters (MSK)
struct ManagerSecretKey {
  std::string r;
  std::string s;
  std::string S1;
  std::string S2;
  std::string S3;
};

struct MemberKey {
  std::string id;    // pseudo id (or user id)
  std::string omega1;
  std::string omega2;
  std::string omega_RM;
  
  std::string Serialize() const;
  static MemberKey Deserialize(const std::string& str);
};

// The signature tuple
struct Signature {
  std::string Enc;
  std::string A;
  std::string C1;
  std::string C2;
  std::string c;
  std::string z1;
  std::string z2;
  std::string z3;
  std::string zs;

  std::string Serialize() const;
  static Signature Deserialize(const std::string& str);
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

  // check if a user is revoked
  virtual bool IsRevoked(const Signature &sig,
                         const std::vector<std::string> &revokedIds) = 0;

  // extract omega_RM from signature (open) - for the RM/Manager
  // returns the omega_RM of the signer
  virtual std::string Open(const Signature &sig,
                           const ManagerSecretKey &msk) = 0;
};

std::unique_ptr<GroupSig> CreateGroupSig();

} 
