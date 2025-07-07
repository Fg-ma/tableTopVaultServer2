#include <arpa/inet.h>
#include <yaml-cpp/yaml.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <filesystem>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using ssl_stream = asio::ssl::stream<tcp::socket>;
using json = nlohmann::json;

struct Config {
  std::string server_ip;
  int server_port;

  std::string ca_file;
  std::string cert_file;
  std::string key_file;

  std::string request_id;
  std::string request_ip;
  std::string request_purpose;
  std::vector<std::string> request_policies;
  int request_num_uses;
};

Config config;

bool checkNodeExists(const YAML::Node& node, const std::string& key) {
  if (!node[key]) {
    std::cerr << "Missing required config key: " << key << "\n";
    return false;
  }
  return true;
}

bool load_config(const std::string& path) {
  try {
    YAML::Node root = YAML::LoadFile(path);

    // Check top-level sections
    if (!checkNodeExists(root, "server") || !checkNodeExists(root, "tls") ||
        !checkNodeExists(root, "request"))
      return false;

    // Server
    YAML::Node server = root["server"];
    if (!checkNodeExists(server, "ip") || !checkNodeExists(server, "port")) return false;

    config.server_ip = server["ip"].as<std::string>();
    config.server_port = server["port"].as<int>();

    // TLS
    YAML::Node tls = root["tls"];
    if (!checkNodeExists(tls, "ca") || !checkNodeExists(tls, "cert") ||
        !checkNodeExists(tls, "key"))
      return false;

    config.ca_file = tls["ca"].as<std::string>();
    config.cert_file = tls["cert"].as<std::string>();
    config.key_file = tls["key"].as<std::string>();

    // Request
    YAML::Node request = root["request"];
    if (!checkNodeExists(request, "id") || !checkNodeExists(request, "ip") ||
        !checkNodeExists(request, "purpose") || !checkNodeExists(request, "policies") ||
        !checkNodeExists(request, "num_uses"))
      return false;

    config.request_id = request["id"].as<std::string>();
    config.request_ip = request["ip"].as<std::string>();
    config.request_purpose = request["purpose"].as<std::string>();
    config.request_policies = request["policies"].as<std::vector<std::string>>();
    config.request_num_uses = request["num_uses"].as<int>();

    // Additional sanity checks
    if (config.request_num_uses < 1) {
      std::cerr << "request.num_uses must be >= 1\n";
      return false;
    }

    return true;

  } catch (const YAML::BadFile& e) {
    std::cerr << "Could not open config file: " << e.what() << "\n";
  } catch (const YAML::ParserException& e) {
    std::cerr << "YAML parsing error: " << e.what() << "\n";
  } catch (const YAML::Exception& e) {
    std::cerr << "YAML error: " << e.what() << "\n";
  } catch (const std::exception& e) {
    std::cerr << "General error: " << e.what() << "\n";
  }

  return false;
}

void send_json(ssl_stream& sock, const json& obj) {
  std::string body = obj.dump();
  uint32_t len = htonl(body.size());
  asio::write(sock, asio::buffer(&len, sizeof(len)));
  asio::write(sock, asio::buffer(body));
}

json recv_json(ssl_stream& sock) {
  uint32_t len_net;
  asio::read(sock, asio::buffer(&len_net, sizeof(len_net)));
  uint32_t len = ntohl(len_net);
  std::vector<char> buf(len);
  asio::read(sock, asio::buffer(buf.data(), len));
  return json::parse(buf);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <config.yaml>\n";
    return 1;
  }

  if (!load_config(argv[1])) {
    std::cerr << "Failed to load config\n";
    return 1;
  }

  asio::io_context ctx;
  asio::ssl::context ssl_ctx(asio::ssl::context::tlsv12_client);

  // Set CA cert to verify server
  ssl_ctx.use_certificate_chain_file(config.cert_file);
  ssl_ctx.use_private_key_file(config.key_file, asio::ssl::context::pem);
  ssl_ctx.load_verify_file(config.ca_file);
  ssl_ctx.set_verify_mode(asio::ssl::verify_peer);

  ssl_stream sock(ctx, ssl_ctx);

  tcp::resolver resolver(ctx);
  tcp::resolver::results_type endpoints =
      resolver.resolve(config.server_ip, std::to_string(config.server_port));
  asio::connect(sock.lowest_layer(), endpoints);
  sock.handshake(ssl_stream::client);

  // Send request
  json req = {
      {"cmd", "request"},
      {"id", config.request_id},
      {"ip", config.request_ip},
      {"purpose", config.request_purpose},
      {"policies", config.request_policies},
      {"num_uses", config.request_num_uses},
  };
  send_json(sock, req);

  // Read initial response
  json resp = recv_json(sock);
  if (!resp.contains("request_id")) {
    std::cerr << "Request failed or invalid response: " << resp.dump() << "\n";
    return 1;
  }

  std::string request_id = resp["request_id"];
  std::cerr << "[INFO] Request submitted. Waiting for approval of ID: " << request_id << "\n";

  // Wait for vault_token
  while (true) {
    try {
      json msg = recv_json(sock);
      if (msg.contains("request_id") && msg["request_id"] == request_id &&
          msg.contains("vault_token")) {
        std::cout << msg["vault_token"].get<std::string>() << "\n";
        return 0;
      }
    } catch (...) {
      std::cerr << "Socket closed or error during receive\n";
      break;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
  }

  std::cerr << "[ERROR] Never received approval\n";
  return 1;
}
