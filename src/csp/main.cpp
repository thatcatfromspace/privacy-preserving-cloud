#include "httplib.h"
#include "src/crypto/GroupSig.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

// Global State
CloudPrivacy::GroupPublicKey gpk;
std::unique_ptr<CloudPrivacy::GroupSig> groupSig;
std::string rmUrl = "http://localhost:8081";

void LoadGPK() {
  std::ifstream in("gpk.dat");
  if (!in) {
    std::cerr << "[CSP] Failed to load GPK. Make sure RM is running and has "
                 "generated keys."
              << std::endl;
    exit(1);
  }
  std::stringstream buffer;
  buffer << in.rdbuf();
  gpk.n = buffer.str();
  in.close();
}

std::vector<std::string> GetRevocationList() {
  httplib::Client cli(rmUrl);
  auto res = cli.Get("/revocation_list");
  std::vector<std::string> list;
  if (res && res->status == 200) {
    std::stringstream ss(res->body);
    std::string id;
    while (std::getline(ss, id, '\n')) {
      if (!id.empty())
        list.push_back(id);
    }
  }
  return list;
}

int main() {
  groupSig = CloudPrivacy::CreateGroupSig();
  LoadGPK();
  std::cout << "[CSP] GPK Loaded." << std::endl;

  httplib::Server svr;

  // Upload Endpoint
  svr.Post("/upload", [](const httplib::Request &req, httplib::Response &res) {
    // Headers: X-Group-Sig
    if (!req.has_header("X-Group-Sig")) {
      res.status = 401;
      res.set_content("Missing Signature", "text/plain");
      return;
    }

    std::string sigData = req.get_header_value("X-Group-Sig");
    CloudPrivacy::Signature sig{sigData};

    // verify signature
    if (!groupSig->Verify(req.body, sig, gpk)) {
      res.status = 403;
      res.set_content("Invalid Signature", "text/plain");
      return;
    }

    // check revocation
    auto revoked = GetRevocationList();
    if (groupSig->IsRevoked(sig, revoked)) {
      res.status = 403;
      res.set_content("User Revoked", "text/plain");
      return;
    }

    size_t delim = sigData.find(':');
    std::string pseudoId = sigData.substr(0, delim);

    std::string dir = "storage/" + pseudoId;
    fs::create_directories(dir);

    std::string filename = "uploaded_file.txt"; 
    if (req.has_param("filename"))
      filename = req.get_param_value("filename");

    std::ofstream out(dir + "/" + filename);
    out << req.body;
    out.close();

    res.set_content("File saved to " + dir + "/" + filename, "text/plain");
  });

  std::cout << "[CSP] Listening on port 8080..." << std::endl;
  svr.listen("0.0.0.0", 8080);

  return 0;
}
