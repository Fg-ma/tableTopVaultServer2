#include <arpa/inet.h>
#include <yaml-cpp/yaml.h>

#include <QApplication>
#include <QDialog>
#include <QFile>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QVBoxLayout>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

QSslSocket sock;

struct Config {
  std::string server_ip;
  int server_port;
  QString ca_file;
  QString cert_file;
  QString key_file;
};

Config config;

bool hasKey(const YAML::Node& node, const std::string& key) {
  return node && node[key] && node[key].IsScalar();
}

Config loadConfig(const std::string& path) {
  YAML::Node cfg = YAML::LoadFile(path);
  Config config;

  if (!cfg["server"] || !cfg["server"].IsMap()) {
    throw std::runtime_error("Missing or invalid 'server' section in config");
  }

  if (!hasKey(cfg["server"], "ip") || !hasKey(cfg["server"], "port")) {
    throw std::runtime_error("Missing 'ip' or 'port' in 'server' section");
  }

  if (!cfg["tls"] || !cfg["tls"].IsMap()) {
    throw std::runtime_error("Missing or invalid 'tls' section in config");
  }

  if (!hasKey(cfg["tls"], "ca") || !hasKey(cfg["tls"], "cert") || !hasKey(cfg["tls"], "key")) {
    throw std::runtime_error("Missing one of 'ca', 'cert', or 'key' in 'tls' section");
  }

  // All good, extract values
  config.server_ip = cfg["server"]["ip"].as<std::string>();
  config.server_port = cfg["server"]["port"].as<int>();
  config.ca_file = QString::fromStdString(cfg["tls"]["ca"].as<std::string>());
  config.cert_file = QString::fromStdString(cfg["tls"]["cert"].as<std::string>());
  config.key_file = QString::fromStdString(cfg["tls"]["key"].as<std::string>());

  return config;
}

json rpc(const json& msg) {
  if (sock.state() != QAbstractSocket::ConnectedState) {
    // Load CA cert
    QSslConfiguration sslConfig = sock.sslConfiguration();
    QList<QSslCertificate> caCerts = QSslCertificate::fromPath(config.ca_file);
    if (caCerts.isEmpty()) throw std::runtime_error("Failed to load CA certificate.");
    sslConfig.setCaCertificates(caCerts);

    // Load client certificate
    QFile certFile(config.cert_file);
    if (!certFile.open(QIODevice::ReadOnly)) {
      throw std::runtime_error("Failed to open client certificate file.");
    }
    QSslCertificate clientCert(&certFile, QSsl::Pem);
    certFile.close();
    if (clientCert.isNull()) {
      throw std::runtime_error("Failed to load client certificate.");
    }
    sslConfig.setLocalCertificate(clientCert);

    // Load client private key
    QFile keyFile(config.key_file);
    if (!keyFile.open(QIODevice::ReadOnly)) {
      throw std::runtime_error("Failed to open client private key.");
    }
    QSslKey clientKey(&keyFile, QSsl::Rsa);
    keyFile.close();
    if (clientKey.isNull()) throw std::runtime_error("Failed to load client key.");
    sslConfig.setPrivateKey(clientKey);

    sslConfig.setPeerVerifyMode(QSslSocket::VerifyPeer);
    sock.setSslConfiguration(sslConfig);

    // Connect and perform TLS handshake
    sock.connectToHostEncrypted(QString::fromStdString(config.server_ip),
                                static_cast<quint16>(config.server_port));
    if (!sock.waitForEncrypted(3000)) {
      throw std::runtime_error("TLS handshake failed: " + sock.errorString().toStdString());
    }
  }

  QByteArray ba = QString::fromStdString(msg.dump()).toUtf8();
  uint32_t len = htonl(static_cast<uint32_t>(ba.size()));
  sock.write(reinterpret_cast<char*>(&len), sizeof(len));
  sock.write(ba);
  if (!sock.waitForBytesWritten(1000)) {
    throw std::runtime_error("Failed to write to vault daemon");
  }

  if (!sock.waitForReadyRead(2000)) {
    throw std::runtime_error("No response from vault daemon");
  }

  uint32_t netlen = 0;
  sock.read(reinterpret_cast<char*>(&netlen), sizeof(netlen));
  uint32_t rlen = ntohl(netlen);

  QByteArray out = sock.read(rlen);
  while (static_cast<uint32_t>(out.size()) < rlen) {
    if (!sock.waitForReadyRead(1000)) break;
    out += sock.read(rlen - out.size());
  }

  return json::parse(out.constData());
}

int main(int argc, char** argv) {
  QApplication app(argc, argv);

  // Ensure config path is passed
  if (argc < 2) {
    return 1;
  }

  try {
    config = loadConfig(argv[1]);
  } catch (const std::exception& e) {
    std::cerr << "Failed to load config: " << e.what() << "\n";
    return 1;
  }

  QString token;
  {
    bool ok;
    token = QInputDialog::getText(nullptr, "Login", "Master token:", QLineEdit::Password, "", &ok);
    if (!ok) return 0;
  }

  try {
    auto resp = rpc({{"cmd", "login"}, {"token", token.toStdString()}});
    if (resp.value("status", "error") != "ok") {
      QMessageBox::critical(nullptr, "Error", "Invalid token");
      return 1;
    }
  } catch (const std::exception& e) {
    QMessageBox::critical(nullptr, "Error", e.what());
    return 1;
  }

  QDialog dlg;
  dlg.setWindowTitle("TableTop Vault Approvals");
  QVBoxLayout* mainL = new QVBoxLayout(&dlg);
  QListWidget* list = new QListWidget;
  mainL->addWidget(list);

  auto refresh = [&]() {
    list->clear();
    try {
      auto result = rpc({{"cmd", "list"}});
      std::cerr << "list response: " << result.dump(2) << "\n";
      for (auto& it : result["pending"]) {
        QString request_id = QString::fromStdString(it["request_id"].get<std::string>());
        QString vm_id = QString::fromStdString(it.value("id", "N/A"));
        QString vm_ip = QString::fromStdString(it.value("ip", "N/A"));
        QString purpose = QString::fromStdString(it.value("purpose", "N/A"));
        int uses = it.value("num_uses", 1);

        QString policies_str = "[]";
        if (it.contains("policies") && it["policies"].is_array()) {
          QStringList polList;
          for (const auto& p : it["policies"]) {
            polList << QString::fromStdString(p.get<std::string>());
          }
          policies_str = "[" + polList.join(", ") + "]";
        }

        QString text = QString("ID: %1 | IP: %2 | Purpose: %3 | Uses: %4 | Policies: %5")
                           .arg(vm_id)
                           .arg(vm_ip)
                           .arg(purpose)
                           .arg(uses)
                           .arg(policies_str);

        auto item = new QListWidgetItem(text, list);
        item->setData(Qt::UserRole, request_id);
        item->setData(Qt::UserRole + 1, QString::fromStdString(it.dump()));
      }
    } catch (const std::exception& e) {
      QMessageBox::critical(nullptr, "Error", e.what());
    }
  };
  refresh();

  QHBoxLayout* btnRow = new QHBoxLayout;
  auto *approveBtn = new QPushButton("Approve"), *declineBtn = new QPushButton("Decline"),
       *refreshBtn = new QPushButton("Refresh");
  btnRow->addWidget(approveBtn);
  btnRow->addWidget(declineBtn);
  btnRow->addWidget(refreshBtn);
  mainL->addLayout(btnRow);

  QObject::connect(refreshBtn, &QPushButton::clicked, [&] { refresh(); });
  QObject::connect(approveBtn, &QPushButton::clicked, [&] {
    if (auto* item = list->currentItem()) {
      QString id = item->data(Qt::UserRole).toString();
      try {
        auto r2 = rpc({{"cmd", "approve"}, {"request_id", id.toStdString()}});
        if (r2.value("status", "") == "approved") {
          refresh();
        } else {
          QMessageBox::warning(nullptr, "Error", "Approval failed.");
        }
      } catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "Error", e.what());
      }
    }
  });

  QObject::connect(declineBtn, &QPushButton::clicked, [&] {
    if (auto* item = list->currentItem()) {
      QString id = item->data(Qt::UserRole).toString();
      try {
        rpc({{"cmd", "decline"}, {"request_id", id.toStdString()}});
        refresh();
      } catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "Error", e.what());
      }
    }
  });

  dlg.exec();
  return 0;
}
