#include <iostream>
#include <thread>
#include <string>
#include <vector>

// --- Crow & JWT ---
#include "crow.h"
#include "crow/middlewares/cors.h"
#include "jwt-cpp/jwt.h"

// --- Bcrypt ---
#include "bcrypt/BCrypt.hpp"

// --- Qt Includes ---
#include <QCoreApplication>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QSqlRecord>
#include <QVariant>
#include <QString>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QThread>
#include <QDebug>

// Konfiguration
const std::string JWT_SECRET = "mein_sehr_geheimes_secret_key_12345";
const std::string JWT_ISSUER = "crow_qt_server";
const QString DB_FILENAME    = "app_database.sqlite";

// -------------------------------------------------------------------------
// DATABASE MANAGER
// -------------------------------------------------------------------------
class DbManager {
public:
    static void initMainDatabase() {
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "main_setup_conn");
        db.setDatabaseName(DB_FILENAME);

        if (!db.open()) {
            qCritical() << "FATAL: Could not open database:" << db.lastError().text();
            return;
        }

        QSqlQuery query(db);
        bool ok = query.exec(
            "CREATE TABLE IF NOT EXISTS users ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "  username TEXT UNIQUE NOT NULL, "
            "  password_hash TEXT NOT NULL"
            ")"
        );

        if (!ok) qDebug() << "Table creation failed:" << query.lastError().text();

        query.exec("SELECT count(*) FROM users WHERE username = 'admin'");
        if (query.next() && query.value(0).toInt() == 0) {
            std::string hash = BCrypt::generateHash("secret");
            
            QSqlQuery insert(db);
            insert.prepare("INSERT INTO users (username, password_hash) VALUES (:u, :p)");
            insert.bindValue(":u", "admin");
            insert.bindValue(":p", QString::fromStdString(hash));
            insert.exec();
            qDebug() << "Initial Admin user created (User: admin, Pass: secret)";
        }
        db.close();
    }

    static bool verifyUser(const std::string& username, const std::string& password) {
        QString connName = QString("worker_conn_%1").arg((quint64)QThread::currentThreadId());

        {
            QSqlDatabase db;
            if (QSqlDatabase::contains(connName)) {
                db = QSqlDatabase::database(connName);
            } else {
                db = QSqlDatabase::addDatabase("QSQLITE", connName);
                db.setDatabaseName(DB_FILENAME);
            }

            if (!db.isOpen() && !db.open()) {
                qCritical() << "Worker DB Open Error:" << db.lastError().text();
                return false;
            }

            QSqlQuery query(db);
            query.prepare("SELECT password_hash FROM users WHERE username = :u");
            query.bindValue(":u", QString::fromStdString(username));

            if (query.exec() && query.next()) {
                std::string storedHash = query.value(0).toString().toStdString();
                return BCrypt::validatePassword(password, storedHash);
            }
        }
        return false;
    }
};

// -------------------------------------------------------------------------
// AUTH MIDDLEWARE
// -------------------------------------------------------------------------
struct AuthMiddleware : crow::ILocalMiddleware {
    struct context {
        std::string current_user;
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx) {
        std::string authHeader = req.get_header_value("Authorization");
        
        if (authHeader.empty()) {
            res.code = 401;
            res.end(R"({"error": "Missing Authorization Header"})");
            return;
        }

        if (authHeader.substr(0, 7) != "Bearer ") {
            res.code = 401;
            res.end(R"({"error": "Invalid Authorization Header format"})");
            return;
        }

        std::string token = authHeader.substr(7);

        try {
            auto decoded = jwt::decode(token);
            auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{JWT_SECRET})
                .with_issuer(JWT_ISSUER);

            verifier.verify(decoded);

            if (decoded.has_payload_claim("username")) {
                ctx.current_user = decoded.get_payload_claim("username").as_string();
            }

        } catch (const std::exception& e) {
            res.code = 401;
            res.end("Token verification failed: " + std::string(e.what()));
        }
    }

    void after_handle(crow::request& /*req*/, crow::response& /*res*/, context& /*ctx*/) {
    }
};

// -------------------------------------------------------------------------
// SERVER THREAD
// -------------------------------------------------------------------------
void runCrowServer() {
    crow::App<AuthMiddleware> app;

    // --- LOGIN ---
    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req){
        auto json = crow::json::load(req.body);
        if (!json) return crow::response(400, "Invalid JSON");

        if (!json.has("username") || !json.has("password")) {
            return crow::response(400, "Missing username or password");
        }

        std::string user = json["username"].s();
        std::string pass = json["password"].s();

        if (DbManager::verifyUser(user, pass)) {
            auto token = jwt::create()
                .set_issuer(JWT_ISSUER)
                .set_type("JWS")
                .set_payload_claim("username", jwt::claim(user))
                .set_issued_at(std::chrono::system_clock::now())
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{2})
                .sign(jwt::algorithm::hs256{JWT_SECRET});

            crow::json::wvalue resp;
            resp["token"] = token;
            return crow::response(resp);
        }

        return crow::response(401, "Invalid credentials");
    });

    // --- UPLOAD ---
    CROW_ROUTE(app, "/upload")
        .methods(crow::HTTPMethod::POST)
        .CROW_MIDDLEWARES(app, AuthMiddleware) 
    ([](const crow::request& req, crow::response& res){
        
        crow::multipart::message msg(req);
        const crow::multipart::part* photoPart = nullptr;
        
        // --- FIX: Suche den Part über den Header-Parameter "name" ---
        for (const auto& part : msg.parts) {
            auto contentDisp = part.get_header_object("Content-Disposition");
            auto it = contentDisp.params.find("name");
            if (it != contentDisp.params.end() && it->second == "photo") {
                photoPart = &part;
                break;
            }
        }
        // ------------------------------------------------------------

        if (!photoPart) {
            res.code = 400;
            res.end("Part 'photo' missing");
            return;
        }

        // Dateiname aus Header extrahieren
        auto contentDisp = photoPart->get_header_object("Content-Disposition");
        std::string rawFilename = "unknown.jpg";
        if (contentDisp.params.find("filename") != contentDisp.params.end()) {
            rawFilename = contentDisp.params["filename"];
        }

        QString qFilename = QString::fromStdString(rawFilename);
        QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss_zzz");
        
        QDir dir;
        if (!dir.exists("uploads")) dir.mkdir("uploads");

        QString finalPath = QString("uploads/%1_%2").arg(timestamp, qFilename);

        QFile file(finalPath);
        if (file.open(QIODevice::WriteOnly)) {
            file.write(photoPart->body.data(), photoPart->body.size());
            file.close();
            
            crow::json::wvalue json;
            json["status"] = "success";
            json["path"] = finalPath.toStdString();
            
            res.code = 201;
            res.write(json.dump());
            res.end();
        } else {
            res.code = 500;
            res.end("Server Error: Could not save file.");
        }
    });

    qDebug() << "Crow Server is starting on port 8080 (Thread:" << QThread::currentThreadId() << ")";
    app.port(8080).multithreaded().run();
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    qDebug() << "Main Thread ID:" << QThread::currentThreadId();

    DbManager::initMainDatabase();

    std::jthread serverThread(runCrowServer);

    return app.exec();
}