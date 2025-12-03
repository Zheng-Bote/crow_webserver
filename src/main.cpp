/**
0.2.1
*/
#include <iostream>
#include <thread>
#include <string>
#include <vector>
#include <format>
#include <set>
#include <algorithm> 

#include <openssl/rand.h>
#include <stdexcept>

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

#include "includes/rz_dbmanager.hpp"
#include "includes/rz_middleware.hpp"
#include "includes/rz_helpers.hpp"

#include "includes/rz_config.hpp"

// -------------------------------------------------------------------------
// SERVER THREAD
// -------------------------------------------------------------------------
void runCrowServer() {
    crow::App<crow::CORSHandler, AuthMiddleware> app;

    // CORS for webclients
    auto& cors = app.get_middleware<crow::CORSHandler>();
cors
      .global()
        .headers("Content-Type", "Authorization") // Wichtig für JWT
        .methods("POST"_method, "GET"_method, "OPTIONS"_method)
        .origin("*"); // for development OK, in Prod better specific Domain
    

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
            // 1. Access Token (Kurz: 15 Min)
            auto accessToken = jwt::create()
                .set_issuer(JWT_ISSUER)
                .set_type("JWS")
                .set_payload_claim("username", jwt::claim(user))
                .set_issued_at(std::chrono::system_clock::now())
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{15}) // <-- KURZ
                .sign(jwt::algorithm::hs256{JWT_SECRET});

            // 2. Refresh Token (Lang: Random String)
            std::string refreshToken = generateRandomString(64);
            DbManager::storeRefreshToken(user, refreshToken);

            crow::json::wvalue resp;
            resp["token"] = accessToken;
            resp["refreshToken"] = refreshToken; // <-- Senden
            return crow::response(resp);
        }
        return crow::response(401, "Invalid credentials");
    });

    // --- LOGOUT ROUTE ---
    CROW_ROUTE(app, "/logout").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req){
        auto json = crow::json::load(req.body);
        
        // Wir erwarten den Refresh Token, um ihn zu löschen
        if (json && json.has("refreshToken")) {
            std::string rToken = json["refreshToken"].s();
            DbManager::revokeRefreshToken(rToken);
        }
        
        // Wir antworten immer mit Erfolg, damit der Client aufräumt
        return crow::response(200, "Logged out successfully");
    });

    // --- REFRESH ROUTE ---
    CROW_ROUTE(app, "/refresh").methods(crow::HTTPMethod::POST)
    ([](const crow::request& req){
        auto json = crow::json::load(req.body);
        if (!json || !json.has("refreshToken")) return crow::response(400);

        std::string rToken = json["refreshToken"].s();
        
        // Prüfen ob Refresh Token in DB existiert und gültig ist
        std::string user = DbManager::validateRefreshToken(rToken);

        if (!user.empty()) {
            // Neuen Access Token ausstellen
            auto newAccessToken = jwt::create()
                .set_issuer(JWT_ISSUER)
                .set_type("JWS")
                .set_payload_claim("username", jwt::claim(user))
                .set_issued_at(std::chrono::system_clock::now())
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::minutes{15})
                .sign(jwt::algorithm::hs256{JWT_SECRET});

            crow::json::wvalue resp;
            resp["token"] = newAccessToken;
            // Optional: Auch den Refresh Token rotieren (neuen ausstellen) für max. Sicherheit
            return crow::response(resp);
        }

        return crow::response(401, "Invalid credentials");
    });

// --- UPLOAD ROUTE (Mit Pfad-Parameter) ---
    CROW_ROUTE(app, "/upload")
        .methods(crow::HTTPMethod::POST)
        .CROW_MIDDLEWARES(app, AuthMiddleware) 
    ([](const crow::request& req, crow::response& res){
        
        crow::multipart::message msg(req);
        const crow::multipart::part* photoPart = nullptr;
        QString userSubDir = "";
        
        // 1. Alle Parts durchgehen und "photo" sowie "path" suchen
        for (const auto& part : msg.parts) {
            auto contentDisp = part.get_header_object("Content-Disposition");
            auto it = contentDisp.params.find("name");
            
            if (it != contentDisp.params.end()) {
                if (it->second == "photo") {
                    photoPart = &part;
                } else if (it->second == "path") {
                    // Body enthält den Pfad-String
                    userSubDir = QString::fromStdString(part.body).trimmed();
                }
            }
        }

        if (!photoPart) {
            res.code = 400;
            res.end("Part 'photo' missing");
            return;
        }

        // 2. SICHERHEITS-CHECK: Directory Traversal verhindern!
        // Wir erlauben keine ".." und keine absoluten Pfade.
        if (userSubDir.contains("..") || userSubDir.contains("\\")) {
            res.code = 403; 
            res.end("Security Violation: Invalid path characters detected.");
            return;
        }
        
        // Führende Slashes entfernen, um relative Pfade zu erzwingen
        while (userSubDir.startsWith("/")) {
            userSubDir.remove(0, 1);
        }

        // 3. Dateinamen ermitteln
        auto contentDisp = photoPart->get_header_object("Content-Disposition");
        std::string rawFilename = "unknown.jpg";
        if (contentDisp.params.find("filename") != contentDisp.params.end()) {
            rawFilename = contentDisp.params["filename"];
        }

        QString qFilename = QString::fromStdString(rawFilename);

        // --- FIX START: Anführungszeichen entfernen ---
        // Entferne führende Anführungszeichen (" oder ')
        if (qFilename.startsWith('"') || qFilename.startsWith('\'')) {
            qFilename.remove(0, 1);
        }
        // Entferne abschließende Anführungszeichen
        if (qFilename.endsWith('"') || qFilename.endsWith('\'')) {
            qFilename.chop(1);
        }
        
        // --- Dateityp Validierung ---
        if (!isAllowedImage(qFilename.toStdString())) {
            res.code = 400;
            crow::json::wvalue json;
            json["error"] = "Invalid file type. Only png, jpg, jpeg, bmp, tiff, gif allowed.";
            res.write(json.dump());
            res.end();
            return;
        }
        // ----------------------------------

        //QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss_zzz");
        
        // 4. Zielverzeichnis bauen
        // Basis ist "uploads". Wenn userSubDir leer ist, bleibt es "uploads/"
        QString targetDir = "uploads";
        if (!userSubDir.isEmpty()) {
            targetDir += "/" + userSubDir;
        }

        // 5. Verzeichnis rekursiv anlegen (mkpath statt mkdir)
        QDir dir;
        if (!dir.mkpath(targetDir)) {
            res.code = 500;
            res.end("Server Error: Could not create directory path.");
            return;
        }

        // 6. Datei speichern
        // QString finalPath = targetDir + "/" + QString("%1_%2").arg(timestamp, qFilename);
        QString finalPath = targetDir + "/" + QString("%1").arg(qFilename);

        QFile file(finalPath);
        if (file.open(QIODevice::WriteOnly)) {
            file.write(photoPart->body.data(), photoPart->body.size());
            file.close();
            
            crow::json::wvalue json;
            json["status"] = "success";
            json["path"]   = finalPath.toStdString();
            
            res.code = 201;
            res.write(json.dump());
            res.end();
        } else {
            res.code = 500;
            res.end("Server Error: Could not save file to disk.");
        }
    });

    // --- UPLOAD ---
    CROW_ROUTE(app, "/upload_base")
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
        qDebug() << "qFilename: " << qFilename;
        //QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss_zzz");
        
        QDir dir;
        if (!dir.exists("uploads")) dir.mkdir("uploads");

        //QString finalPath = QString("uploads/%1_%2").arg(timestamp, qFilename);
        QString finalPath = QString("uploads/%1").arg(qFilename);
        qDebug() << "finalPath: " << finalPath;

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



// --- SYSTEM ROUTE ---
CROW_ROUTE(app, "/system/json")
  ([]
   {
    crow::json::wvalue x({{"PROJECT_NAME", PROJECT_NAME}, 
                            {"PROJECT_VERSION", PROJECT_VERSION}, 
                            {"PROJECT_DESCRIPTION", PROJECT_DESCRIPTION},
                            {"PROJECT_HOMEPAGE_URL", PROJECT_HOMEPAGE_URL},
                            {"PROG_CREATED", PROG_CREATED},
                            {"PROG_AUTHOR", PROG_AUTHOR},
                            {"PROG_ORGANIZATION_NAME", PROG_ORGANIZATION_NAME},
                            {"PROG_ORGANIZATION_DOMAIN", PROG_ORGANIZATION_DOMAIN},
                            {"PROG_LONGNAME", PROG_LONGNAME},
                            {"PROJECT_EXECUTABLE", PROJECT_EXECUTABLE},
                            {"CMAKE_CXX_STANDARD", CMAKE_CXX_STANDARD},
                            {"CMAKE_CXX_COMPILER", CMAKE_CXX_COMPILER},
                            {"CMAKE_QT_VERSION", CMAKE_QT_VERSION},
                            
                        });
    return x; });

    // --- STATIC ROUTE ---
CROW_ROUTE(app, "/")
  ([](const crow::request &, crow::response &res)
   {
        //replace cat.jpg with your file path
        res.set_static_file_info("static/index.html");
        res.end(); });


  CROW_ROUTE(app, "/static")
  ([](const crow::request &, crow::response &res)
   {
        //replace cat.jpg with your file path
        res.set_static_file_info("static/test.txt");
        res.end(); });

  CROW_ROUTE(app, "/static/<string>")
  ([](const crow::request &, crow::response &res, std::string para)
   {
        //replace cat.jpg with your file path
        res.set_static_file_info("static/" + para);
        res.end(); });

        // --- TEMPLATE ROUTE ---
  CROW_ROUTE(app, "/template")
  ([]()
   {
            auto page = crow::mustache::load("template.html");
            crow::mustache::context ctx;
            ctx["doof"] = "doofie";
            ctx["Morgens"] = false;
            ctx["Mittags"] = true;
            ctx["morgen_gruss"] = "Guten Morgen";
            ctx["mahlzeit"] = "Maahlzeit";

            return page.render(ctx); });


    /* --- END ROUTES --- */

    qDebug() << std::format("{} v{} is starting on port 8080 (Thread: {})", PROJECT_EXECUTABLE, PROJECT_VERSION, QThread::currentThreadId());
    app.port(8080).multithreaded().run();
}



int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    qDebug() << "Main Thread ID:" << QThread::currentThreadId();

    DbManager::initMainDatabase();

    std::jthread serverThread(runCrowServer);

    return app.exec();
}