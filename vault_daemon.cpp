#include <curl/curl.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sodium.h>
#include <yaml-cpp/yaml.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>
#include <thread>
#include <unordered_map>

using nlohmann::json_schema::json_validator;
using json = nlohmann::json;
namespace asio = boost::asio;
namespace fs = std::filesystem;
using tcp = asio::ip::tcp;

// In-memory
std::string vaultMasterToken;

struct RequestContext {
  json requestData;
  std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> requesterSocket;
};
std::unordered_map<std::string, RequestContext> pendingRequests;

struct Config {
  std::string server_ip;
  int server_port;
  std::string vault_ca;
  std::string vault_cert;
  std::string vault_key;
  std::string vault_dhparam;
  std::string vault_token_url;
  std::string vault_lookup_url;
};

Config config;

json get_request_schema() {
  return {
      {"type", "object"},
      {"required", {"cmd", "id", "ip", "purpose", "policies", "num_uses"}},
      {"properties",
       {
           {"cmd", {{"type", "string"}, {"const", "request"}}},
           {"id", {{"type", "string"}, {"minLength", 1}}},
           {"ip", {{"type", "string"}, {"pattern", "^(\\d{1,3}\\.){3}\\d{1,3}$"}}},
           {"purpose", {{"type", "string"}}},
           {"num_uses", {{"type", "integer"}, {"minimum", 1}, {"maximum", 10}}},
           {"policies",
            {
                {"type", "array"},
                {"items", {{"type", "string"}}},
                {"minItems", 0},
            }},
       }},
  };
}

json get_login_schema() {
  return {{"type", "object"},
          {"required", {"cmd", "token"}},
          {"properties",
           {{"cmd", {{"type", "string"}, {"const", "login"}}},
            {"token", {{"type", "string"}, {"minLength", 10}}}}}};
}

json get_approve_schema() {
  return {{"type", "object"},
          {"required", {"cmd", "request_id"}},
          {"properties",
           {{"cmd", {{"type", "string"}, {"const", "approve"}}},
            {"request_id", {{"type", "string"}, {"minLength", 1}}}}}};
}

json get_decline_schema() {
  return {{"type", "object"},
          {"required", {"cmd", "request_id"}},
          {"properties",
           {{"cmd", {{"type", "string"}, {"const", "decline"}}},
            {"request_id", {{"type", "string"}, {"minLength", 1}}}}}};
}

json get_list_schema() {
  return {{"type", "object"},
          {"required", {"cmd"}},
          {"properties", {{"cmd", {{"type", "string"}, {"const", "list"}}}}}};
}

std::unordered_map<std::string, json_validator> schema_map;

void init_schemas() {
  schema_map["login"].set_root_schema(get_login_schema());
  schema_map["request"].set_root_schema(get_request_schema());
  schema_map["approve"].set_root_schema(get_approve_schema());
  schema_map["decline"].set_root_schema(get_decline_schema());
  schema_map["list"].set_root_schema(get_list_schema());
}

bool load_config(const std::string& path, Config& config) {
  try {
    YAML::Node cfg = YAML::LoadFile(path);

    // Check and load `server` config
    if (cfg["server"] && cfg["server"].IsMap()) {
      const auto& server = cfg["server"];
      if (server["ip"] && server["ip"].IsScalar()) {
        config.server_ip = server["ip"].as<std::string>();
      } else {
        std::cerr << "Missing or invalid server.ip\n";
        return false;
      }

      if (server["port"] && server["port"].IsScalar()) {
        config.server_port = server["port"].as<int>();
      } else {
        std::cerr << "Missing or invalid server.port\n";
        return false;
      }
    } else {
      std::cerr << "Missing or invalid 'server' section\n";
      return false;
    }

    // Check and load `tls` config
    if (cfg["tls"] && cfg["tls"].IsMap()) {
      const auto& tls = cfg["tls"];

      if (tls["ca"] && tls["ca"].IsScalar()) {
        config.vault_ca = tls["ca"].as<std::string>();
      } else {
        std::cerr << "Missing or invalid tls.ca\n";
        return false;
      }

      if (tls["cert"] && tls["cert"].IsScalar()) {
        config.vault_cert = tls["cert"].as<std::string>();
      } else {
        std::cerr << "Missing or invalid tls.cert\n";
        return false;
      }

      if (tls["key"] && tls["key"].IsScalar()) {
        config.vault_key = tls["key"].as<std::string>();
      } else {
        std::cerr << "Missing or invalid tls.key\n";
        return false;
      }

      if (tls["dhparam"] && tls["dhparam"].IsScalar()) {
        config.vault_dhparam = tls["dhparam"].as<std::string>();
      } else {
        std::cerr << "Missing or invalid tls.dhparam\n";
        return false;
      }
    } else {
      std::cerr << "Missing or invalid 'tls' section\n";
      return false;
    }

    // Check and load `vault` config
    if (cfg["vault"] && cfg["vault"].IsMap()) {
      const auto& vault = cfg["vault"];

      if (vault["vault_token_url"] && vault["vault_token_url"].IsScalar()) {
        config.vault_token_url = vault["vault_token_url"].as<std::string>();
      } else {
        std::cerr << "Missing or invalid vault.vault_token_url\n";
        return false;
      }

      if (vault["vault_lookup_url"] && vault["vault_lookup_url"].IsScalar()) {
        config.vault_lookup_url = vault["vault_lookup_url"].as<std::string>();
      } else {
        std::cerr << "Missing or invalid vault.vault_lookup_url\n";
        return false;
      }
    } else {
      std::cerr << "Missing or invalid 'vault' section\n";
      return false;
    }

    return true;
  } catch (const std::exception& e) {
    std::cerr << "Error loading YAML config: " << e.what() << "\n";
    return false;
  }
}

static size_t CurlWrite_CallbackFunc_StdString(void* contents, size_t size, size_t nmemb,
                                               void* userp) {
  ((std::string*)userp)->append((char*)contents, size * nmemb);
  return size * nmemb;
}

std::string generateOneTimeVaultToken(const std::string& request_id, int num_uses,
                                      const std::vector<std::string>& policies) {
  nlohmann::json payload = {{"policies", policies},
                            {"meta", {{"request_id", request_id}}},
                            {"ttl", "30m"},
                            {"num_uses", num_uses},
                            {"renewable", false}};
  std::string payloadStr = payload.dump();

  CURL* curl = curl_easy_init();
  std::string response;
  if (curl) {
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("X-Vault-Token: " + vaultMasterToken).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, config.vault_token_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadStr.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, config.vault_ca.c_str());

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }

  auto j = nlohmann::json::parse(response);

  if (!j.contains("auth") || !j["auth"].contains("client_token")) {
    std::cerr << "Error creating one-time token: " << response << "\n";
    return "";
  }

  return j["auth"]["client_token"].get<std::string>();
}

bool verifyMasterToken(const std::string& token) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    std::cerr << "curl init failed\n";
    return false;
  }

  std::string response;
  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, ("X-Vault-Token: " + token).c_str());

  curl_easy_setopt(curl, CURLOPT_URL, config.vault_lookup_url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl, CURLOPT_CAINFO, config.vault_ca.c_str());

  CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  if (res == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  } else {
    std::cerr << "curl error: " << curl_easy_strerror(res) << "\n";
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK || http_code != 200) {
    std::cerr << "lookup-self fail (HTTP " << http_code << "): " << response << "\n";
    return false;
  }
  vaultMasterToken = token;
  return true;
}

// Handle a single client connection
void handle_client(std::shared_ptr<asio::ssl::stream<tcp::socket>> sock) {
  bool isAuthenticated = false;
  std::string buffer;
  asio::streambuf readbuf;

  try {
    // Step: read length-prefixed JSON messages
    while (true) {
      // Read header (4 bytes length)
      uint32_t netlen;
      asio::read(*sock, asio::buffer(&netlen, sizeof(netlen)));
      uint32_t msgLen = ntohl(netlen);
      buffer.resize(msgLen);
      asio::read(*sock, asio::buffer(buffer.data(), msgLen));

      auto msg = json::parse(buffer);
      buffer.clear();

      std::string cmd = msg.value("cmd", "");
      json resp;

      if (schema_map.find(cmd) != schema_map.end()) {
        try {
          schema_map[cmd].validate(msg);
        } catch (const std::exception& e) {
          resp = {{"status", "error"},
                  {"message", std::string("Schema validation failed: ") + e.what()}};
          std::string outStr = resp.dump();
          uint32_t outLen = htonl(outStr.size());
          asio::write(*sock, asio::buffer(&outLen, sizeof(outLen)));
          asio::write(*sock, asio::buffer(outStr));
          continue;
        }
      }

      if (cmd == "login") {
        std::string token = msg.value("token", "");
        if (verifyMasterToken(token)) {
          isAuthenticated = true;
          resp["status"] = "ok";
        } else {
          resp["status"] = "unauthorized";
        }

      } else if (cmd == "request") {
        std::string request_id = "req-" + std::to_string(std::rand());

        pendingRequests[request_id] = RequestContext{.requestData = msg, .requesterSocket = sock};

        resp = {{"status", "pending"}, {"request_id", request_id}};

        std::string outStr = resp.dump();
        uint32_t outLen = htonl(outStr.size());
        asio::write(*sock, asio::buffer(&outLen, sizeof(outLen)));
        asio::write(*sock, asio::buffer(outStr));
        return;
      } else if (cmd == "approve" && isAuthenticated) {
        std::string request_id = msg.value("request_id", "");
        auto it = pendingRequests.find(request_id);
        if (it == pendingRequests.end()) {
          resp["status"] = "not_found";
        } else {
          auto& ctx = it->second;
          auto& jr = ctx.requestData;
          auto sockPtr = ctx.requesterSocket;

          auto policies = jr["policies"].get<std::vector<std::string>>();
          int uses = jr.value("num_uses", 1);
          std::string token = generateOneTimeVaultToken(request_id, uses, policies);

          // Send token back to the requester
          json tokenMsg = {
              {"status", "approved"}, {"vault_token", token}, {"request_id", request_id}};
          std::string out = tokenMsg.dump();
          uint32_t outLen = htonl(out.size());
          asio::write(*sockPtr, asio::buffer(&outLen, sizeof(outLen)));
          asio::write(*sockPtr, asio::buffer(out));

          // Clean up
          pendingRequests.erase(it);
          resp = {{"status", "approved"}, {"request_id", request_id}};
        }

      } else if (cmd == "decline" && isAuthenticated) {
        std::string id = msg.value("request_id", "");
        auto it = pendingRequests.find(id);
        if (it != pendingRequests.end()) {
          pendingRequests.erase(it);
          resp["status"] = "declined";
        } else {
          resp["status"] = "not_found";
        }

      } else if (cmd == "list" && isAuthenticated) {
        resp["pending"] = json::array();
        for (auto& [id, ctx] : pendingRequests) {
          json entry = ctx.requestData;
          entry["request_id"] = id;
          resp["pending"].push_back(entry);
        }

      } else {
        resp["status"] = "error";
        resp["message"] = "invalid command or unauthorized";
      }

      // Send response
      auto outStr = resp.dump();
      uint32_t outLen = htonl(outStr.size());
      asio::write(*sock, asio::buffer(&outLen, sizeof(outLen)));
      asio::write(*sock, asio::buffer(outStr));
    }

  } catch (const std::exception& e) {
    // client disconnected or error
  }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <config.yaml>\n";
    return 1;
  }

  if (!load_config(argv[1], config)) {
    return 1;
  }

  // Ensure sodium
  if (sodium_init() < 0) return 1;
  init_schemas();

  asio::ssl::context sslCtx(asio::ssl::context::tlsv12_server);
  sslCtx.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                     asio::ssl::context::single_dh_use);

  // Load server cert and key
  sslCtx.use_certificate_chain_file(config.vault_cert);
  sslCtx.use_private_key_file(config.vault_key, asio::ssl::context::pem);
  sslCtx.use_tmp_dh_file(config.vault_dhparam);
  sslCtx.load_verify_file(config.vault_ca);
  sslCtx.set_verify_mode(asio::ssl::verify_fail_if_no_peer_cert | asio::ssl::verify_peer);
  std::cout << "Worked" << "\n";
  sslCtx.set_verify_callback([](bool preverified, asio::ssl::verify_context& ctx) -> bool {
    std::cout << "=== Verify Callback ===\n";
    std::cout << "preverified: " << preverified << "\n";

    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    if (!cert) {
      std::cerr << "[TLS] No current cert\n";
      return false;
    }

    // Dump the current cert subject and issuer
    char subject[256], issuer[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));

    std::cout << "[TLS] Cert Subject: " << subject << "\n";
    std::cout << "[TLS] Cert Issuer:  " << issuer << "\n";

    // Print serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
    char* hex = BN_bn2hex(bn);
    std::cout << "[TLS] Serial:       " << hex << "\n";
    BN_free(bn);
    OPENSSL_free(hex);

    // Check if it's a CA cert
    if (X509_check_ca(cert)) {
      std::cerr << "[TLS] Rejecting cert because it's a CA cert.\n";
      return false;
    }

    // Accept only specific CN
    std::string subjectStr(subject);
    std::string allowed_cn = "/CN=table-top-vault-server-nginx-proxy";

    if (subjectStr != allowed_cn) {
      std::cerr << "[TLS] CN mismatch. Expected: " << allowed_cn << "\n";
      return false;
    }

    std::cout << "[TLS] Certificate accepted\n";
    return true;
  });

  asio::io_context ioCtx;
  using asio::ip::tcp;
  tcp::acceptor acceptor(
      ioCtx, tcp::endpoint(asio::ip::make_address(config.server_ip), config.server_port));

  std::cout << "Vault daemon listening on " << config.server_ip << "\n";
  while (true) {
    auto sslSock = std::make_shared<asio::ssl::stream<tcp::socket>>(ioCtx, sslCtx);
    acceptor.accept(sslSock->lowest_layer());  // Accept raw TCP connection

    // TLS handshake
    sslSock->handshake(asio::ssl::stream_base::server);

    std::thread([sslSock]() { handle_client(sslSock); }).detach();
  }
  return 0;
}
