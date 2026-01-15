#include "GroupSig.hpp"
#include <cstring>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <vector>

namespace CloudPrivacy {
namespace Utils {
std::string Base64Encode(const std::string &input);
std::string Base64Decode(const std::string &input);
} 
} 

namespace CloudPrivacy {

class RSAGroupSig : public GroupSig {
public:
  void Setup(GroupPublicKey &gpk, ManagerSecretKey &msk) override {
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);

    BIO *bioConf = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bioConf, pkey);
    char *pubData;
    long pubLen = BIO_get_mem_data(bioConf, &pubData);
    gpk.n = std::string(pubData, pubLen);

    BIO_reset(bioConf);
    PEM_write_bio_PrivateKey(bioConf, pkey, NULL, NULL, 0, NULL, NULL);
    char *privData;
    long privLen = BIO_get_mem_data(bioConf, &privData);
    msk.d = std::string(privData, privLen);

    BIO_free(bioConf);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
  }

  MemberKey Join(const GroupPublicKey &gpk, const ManagerSecretKey &msk,
                 const std::string &userId) override {
    BIO *bio = BIO_new_mem_buf(msk.d.c_str(), -1);
    EVP_PKEY *privKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    EVP_MD_CTX *signCtx = EVP_MD_CTX_new();
    EVP_DigestSignInit(signCtx, NULL, EVP_sha256(), NULL, privKey);
    EVP_DigestSignUpdate(signCtx, userId.data(), userId.length());

    size_t sigLen;
    EVP_DigestSignFinal(signCtx, NULL, &sigLen);
    std::vector<unsigned char> signature(sigLen);
    EVP_DigestSignFinal(signCtx, signature.data(), &sigLen);

    EVP_MD_CTX_free(signCtx);
    EVP_PKEY_free(privKey);

    MemberKey k;
    k.id = userId;
    k.certificate =
        Utils::Base64Encode(std::string(signature.begin(), signature.end()));
    return k;
  }

  Signature Sign(const std::string &message, const GroupPublicKey &gpk,
                 const MemberKey &memberKey) override {
    std::string sigData = memberKey.id + ":" + memberKey.certificate;
    return {sigData};
  }

  bool Verify(const std::string &message, const Signature &sig,
              const GroupPublicKey &gpk) override {
    size_t delim = sig.data.find(':');
    if (delim == std::string::npos)
      return false;

    std::string id = sig.data.substr(0, delim);
    std::string b64Cert = sig.data.substr(delim + 1);
    std::string rawCert = Utils::Base64Decode(b64Cert);

    BIO *bio = BIO_new_mem_buf(gpk.n.c_str(), -1);
    EVP_PKEY *pubKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pubKey)
      return false;

    EVP_MD_CTX *verCtx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(verCtx, NULL, EVP_sha256(), NULL, pubKey);
    EVP_DigestVerifyUpdate(verCtx, id.data(), id.length());

    int res = EVP_DigestVerifyFinal(verCtx, (unsigned char *)rawCert.data(),
                                    rawCert.length());

    EVP_MD_CTX_free(verCtx);
    EVP_PKEY_free(pubKey);

    return (res == 1);
  }

  bool IsRevoked(const Signature &sig,
                 const std::vector<std::string> &revokedIds) override {
    size_t delim = sig.data.find(':');
    if (delim == std::string::npos)
      return true;
    std::string id = sig.data.substr(0, delim);

    for (const auto &r_id : revokedIds) {
      if (r_id == id)
        return true;
    }
    return false;
  }

  std::string Open(const Signature &sig, const ManagerSecretKey &msk) override {
    size_t delim = sig.data.find(':');
    if (delim == std::string::npos)
      return "";
    return sig.data.substr(0, delim);
  }
};

std::unique_ptr<GroupSig> CreateGroupSig() {
  return std::make_unique<RSAGroupSig>();
}

} // namespace CloudPrivacy
