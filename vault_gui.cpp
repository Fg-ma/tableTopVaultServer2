#include <arpa/inet.h>

#include <QApplication>
#include <QDialog>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QTcpSocket>
#include <QVBoxLayout>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
static const QString SOCKET_PATH = "/run/tabletop-vault.sock";

// Helper: send JSON and receive response over local socket
json rpc(const json& msg) {
  // use QLocalSocket in real code; placeholder using QTcpSocket + AF_UNIX
  QTcpSocket sock;
  sock.connectToHost("localhost", 0);  // stub
  // ... implement AF_UNIX connection
  QByteArray ba = QString::fromStdString(msg.dump()).toUtf8();
  uint32_t len = htonl(ba.size());
  sock.write((char*)&len, sizeof(len));
  sock.write(ba);
  sock.waitForBytesWritten();
  // read 4-byte length then payload
  sock.waitForReadyRead();
  uint32_t rlen;
  sock.read((char*)&rlen, sizeof(rlen));
  rlen = ntohl(rlen);
  QByteArray out = sock.read(rlen);
  return json::parse(out.constData());
}

int main(int argc, char** argv) {
  QApplication app(argc, argv);

  // 1) Prompt for master token
  bool ok;
  QString token =
      QInputDialog::getText(nullptr, "Login", "Master token:", QLineEdit::Password, "", &ok);
  if (!ok) return 0;
  auto resp = rpc({{"cmd", "login"}, {"token", token.toStdString()}});
  if (resp.value("status", "fail") != "ok") {
    QMessageBox::critical(nullptr, "Error", "Invalid token");
    return 1;
  }

  // 2) Main window
  QDialog dlg;
  dlg.setWindowTitle("TableTop Vault Approvals");
  QVBoxLayout* mainL = new QVBoxLayout(&dlg);
  QListWidget* list = new QListWidget;
  mainL->addWidget(list);

  auto refresh = [&]() {
    list->clear();
    auto jr = rpc({{"cmd", "list"}})["pending"];
    for (auto& it : jr) {
      QString id = QString::fromStdString(it["id"].get<std::string>());
      QString text = id + ": uses=" + QString::number(it.value("num_uses", 1));
      auto item = new QListWidgetItem(text, list);
      item->setData(Qt::UserRole, id);
    }
  };
  refresh();

  QHBoxLayout* btnRow = new QHBoxLayout;
  QPushButton* approveBtn = new QPushButton("Approve");
  QPushButton* declineBtn = new QPushButton("Decline");
  QPushButton* refreshBtn = new QPushButton("Refresh");
  btnRow->addWidget(approveBtn);
  btnRow->addWidget(declineBtn);
  btnRow->addWidget(refreshBtn);
  mainL->addLayout(btnRow);

  QObject::connect(refreshBtn, &QPushButton::clicked, [&]() { refresh(); });
  QObject::connect(approveBtn, &QPushButton::clicked, [&]() {
    auto item = list->currentItem();
    if (!item) return;
    QString id = item->data(Qt::UserRole).toString();
    auto r2 = rpc({{"cmd", "approve"}, {"request_id", id.toStdString()}});
    if (r2.value("status", "fail") == "approved") {
      QMessageBox::information(
          nullptr, "Approved",
          "Token: " + QString::fromStdString(r2["vault_token"].get<std::string>()));
      refresh();
    }
  });
  QObject::connect(declineBtn, &QPushButton::clicked, [&]() {
    auto item = list->currentItem();
    if (!item) return;
    QString id = item->data(Qt::UserRole).toString();
    rpc({{"cmd", "decline"}, {"request_id", id.toStdString()}});
    refresh();
  });

  dlg.exec();
  return 0;
}
