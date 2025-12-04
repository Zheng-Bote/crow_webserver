#include "rz_dbmanager.hpp"


QSqlDatabase DbManager::getNewConnection(const QString& connectionName) {
    // Falls eine Verbindung mit diesem Namen schon existiert (z.B. durch Fehler nicht aufgeräumt),
    // holen wir sie uns, anstatt addDatabase zu rufen (was warnen würde).
    if (QSqlDatabase::contains(connectionName)) {
        QSqlDatabase db = QSqlDatabase::database(connectionName);
        if (!db.isOpen()) {
            // Versuchen erneut zu öffnen, falls geschlossen
            if (!db.open()) {
                qCritical() << "Failed to reopen existing connection:" << connectionName;
            }
        }
        return db;
    }

    // Neue Verbindung anlegen
    QSqlDatabase db = QSqlDatabase::addDatabase("QPSQL", connectionName);

    // Config aus Environment lesen
    QString host = qEnvironmentVariable("PG_HOST", "localhost");
    QString portStr = qEnvironmentVariable("PG_PORT", "5432");
    QString dbName = qEnvironmentVariable("PG_DB", "Photos");
    QString user = qEnvironmentVariable("PG_USER", "postgres");
    QString pass = qEnvironmentVariable("PG_PASS");

    db.setHostName(host);
    db.setPort(portStr.toInt());
    db.setDatabaseName(dbName);
    db.setUserName(user);
    db.setPassword(pass);

    if (!db.open()) {
        qCritical() << "API DB Connection Error (" << connectionName << "):" << db.lastError().text();
    }

    return db;
}