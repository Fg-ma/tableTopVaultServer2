#include <sodium.h>

#include <boost/asio.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>
#include <unordered_map>

using json = nlohmann::json;
namespace asio = boost::asio;
using asio::local::stream_protocol;
namespace fs = std::filesystem;

static const std::string SOCKET_PATH = "/run/tabletop-vault.sock";
static const std::string VAULT_MASTER_HASH_FILE = "/etc/tabletop-vault/master.hash";
static const std::string VAULT_CA_FILE = "/etc/tabletop-vault/ca.pem";

// In-memory
std::string masterHash;
std::unordered_map<std::string, json> pendingRequests;
std::unordered_map<std::string, std::string> completedRequests;

// Load Argon2 hash from disk
void loadMasterHash() {
  std::ifstream in(VAULT_MASTER_HASH_FILE);
  if (!in || !std::getline(in, masterHash)) {
    std::cerr << "Failed to load master hash\n";
    std::exit(1);
  }
}

// Verify token against Argon2 hash
bool verifyMasterToken(const std::string& token) {
  return sodium_init() >= 0 &&
         crypto_pwhash_str_verify(masterHash.c_str(), token.c_str(), token.size()) == 0;
}

// Forward declaration: integrate your Vault client logic here
std::string generateOneTimeVaultToken(const std::string& reqId, int uses,
                                      const std::vector<std::string>& policies) {
  // TEMP DUMMY IMPLEMENTATION
  return "mock-token-" + reqId;
}

// Handle a single client connection
void handle_client(stream_protocol::socket sock) {
  bool isAuthenticated = false;
  std::string buffer;
  asio::streambuf readbuf;

  try {
    // Step: read length-prefixed JSON messages
    while (true) {
      // Read header (4 bytes length)
      uint32_t netlen;
      asio::read(sock, asio::buffer(&netlen, sizeof(netlen)));
      uint32_t msgLen = ntohl(netlen);
      buffer.resize(msgLen);
      asio::read(sock, asio::buffer(buffer.data(), msgLen));

      auto msg = json::parse(buffer);
      buffer.clear();

      std::string cmd = msg.value("cmd", "");
      json resp;

      if (cmd == "login") {
        std::string token = msg.value("token", "");
        if (verifyMasterToken(token)) {
          isAuthenticated = true;
          resp["status"] = "ok";
        } else {
          resp["status"] = "unauthorized";
        }

      } else if (cmd == "request") {
        std::string id = msg.value("id", "");
        pendingRequests[id] = msg;
        resp = {{"status", "pending"}, {"request_id", id}};

      } else if (cmd == "approve" && isAuthenticated) {
        std::string id = msg.value("request_id", "");
        auto it = pendingRequests.find(id);
        if (it == pendingRequests.end()) {
          resp["status"] = "not_found";
        } else {
          auto jr = it->second;
          auto policies = jr["policies"].get<std::vector<std::string>>();
          int uses = jr.value("num_uses", 1);
          std::string token = generateOneTimeVaultToken(id, uses, policies);
          completedRequests[id] = token;
          pendingRequests.erase(it);
          resp = {{"status", "approved"}, {"vault_token", token}};
        }

      } else if (cmd == "decline" && isAuthenticated) {
        std::string id = msg.value("request_id", "");
        pendingRequests.erase(id);
        resp["status"] = "declined";

      } else if (cmd == "list" && isAuthenticated) {
        resp["pending"] = json::array();
        for (auto& kv : pendingRequests) resp["pending"].push_back(kv.second);

      } else {
        resp["status"] = "error";
        resp["message"] = "invalid command or unauthorized";
      }

      // Send response
      auto outStr = resp.dump();
      uint32_t outLen = htonl(outStr.size());
      asio::write(sock, asio::buffer(&outLen, sizeof(outLen)));
      asio::write(sock, asio::buffer(outStr));
    }

  } catch (const std::exception& e) {
    // client disconnected or error
  }
}

int main() {
  // Ensure sodium
  if (sodium_init() < 0) return 1;
  loadMasterHash();

  // Remove old socket
  fs::remove(SOCKET_PATH);
  asio::io_context ctx;
  stream_protocol::endpoint endpoint(SOCKET_PATH);
  stream_protocol::acceptor acceptor(ctx, endpoint);
  fs::permissions(SOCKET_PATH, fs::perms::owner_read | fs::perms::owner_write);

  std::cout << "Vault daemon listening on " << SOCKET_PATH << "\n";
  while (true) {
    stream_protocol::socket sock(ctx);
    acceptor.accept(sock);
    std::thread(handle_client, std::move(sock)).detach();
  }
  return 0;
}
