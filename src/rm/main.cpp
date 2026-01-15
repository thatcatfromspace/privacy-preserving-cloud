#include "httplib.h"
#include "src/crypto/GroupSig.hpp"
#include <fstream>
#include <iostream>
#include <mutex>
#include <vector>

CloudPrivacy::GroupPublicKey gpk;
CloudPrivacy::ManagerSecretKey msk;
std::unique_ptr<CloudPrivacy::GroupSig> groupSig;
std::vector<std::string> revocationList;
std::mutex rlMutex;

void SaveGPK() {
  std::ofstream out("gpk.dat");
  out << gpk.n; // PEM
  out.close();
}

int main() {
  groupSig = CloudPrivacy::CreateGroupSig();

  // setup
  groupSig->Setup(gpk, msk);
  SaveGPK();

  httplib::Server svr;

  svr.Post("/join", [](const httplib::Request &req, httplib::Response &res) {
    std::string userId = req.body; 
    if (userId.empty()) {
      res.status = 400;
      return;
    }
    auto key = groupSig->Join(gpk, msk, userId);
    res.set_content(key.id + "\n" + key.certificate, "text/plain");
  });

  svr.Post("/revoke", [](const httplib::Request &req, httplib::Response &res) {
    std::string userId = req.body;
    std::lock_guard<std::mutex> lock(rlMutex);
    revocationList.push_back(userId);
    res.set_content("OK", "text/plain");
  });

  svr.Get("/revocation_list",
          [](const httplib::Request &req, httplib::Response &res) {
            std::lock_guard<std::mutex> lock(rlMutex);
            std::string list;
            for (const auto &id : revocationList) {
              list += id + "\n";
            }
            res.set_content(list, "text/plain");
          });

  std::cout << "[RM] Listening on port 8081..." << std::endl;
  svr.listen("0.0.0.0", 8081);

  return 0;
}
