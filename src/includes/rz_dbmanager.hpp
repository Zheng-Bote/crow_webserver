// -------------------------------------------------------------------------
// DATABASE MANAGER
// -------------------------------------------------------------------------

const QString DB_FILENAME    = "app_database.sqlite";

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

        if (!ok) qDebug() << "User table creation failed:" << query.lastError().text();

        ok = query.exec("CREATE TABLE IF NOT EXISTS refresh_tokens ("
                   "token TEXT PRIMARY KEY, "
                   "username TEXT, "
                   "expires_at INTEGER)" // Unix Timestamp
        );
        if (!ok) qDebug() << "Refresh token table creation failed:" << query.lastError().text();


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

    static void storeRefreshToken(const std::string& username, const std::string& token) {
        QString connName = QString("worker_conn_%1").arg((quint64)QThread::currentThreadId());
        {
            QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connName);
            db.setDatabaseName(DB_FILENAME);
            if(db.open()) {
                QSqlQuery q(db);
                // Alte Tokens des Users löschen (optional, erlaubt nur 1 Session)
                q.prepare("DELETE FROM refresh_tokens WHERE username = :u");
                q.bindValue(":u", QString::fromStdString(username));
                q.exec();

                // Neuen Token speichern (Gültig z.B. 7 Tage)
                qint64 expiry = QDateTime::currentSecsSinceEpoch() + (7 * 24 * 60 * 60);
                
                q.prepare("INSERT INTO refresh_tokens (token, username, expires_at) VALUES (:t, :u, :e)");
                q.bindValue(":t", QString::fromStdString(token));
                q.bindValue(":u", QString::fromStdString(username));
                q.bindValue(":e", expiry);
                q.exec();
            }
        }
        QSqlDatabase::removeDatabase(connName);
    }

    // NEU: Refresh Token validieren und Username zurückgeben
    static std::string validateRefreshToken(const std::string& token) {
        QString connName = QString("refresh_conn_%1").arg((quint64)QThread::currentThreadId());
        std::string username = "";
        {
            QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connName);
            db.setDatabaseName(DB_FILENAME);
            if(db.open()) {
                QSqlQuery q(db);
                q.prepare("SELECT username, expires_at FROM refresh_tokens WHERE token = :t");
                q.bindValue(":t", QString::fromStdString(token));
                
                if (q.exec() && q.next()) {
                    qint64 exp = q.value(1).toLongLong();
                    qint64 now = QDateTime::currentSecsSinceEpoch();
                    
                    if (now < exp) {
                        username = q.value(0).toString().toStdString();
                    } else {
                        // Abgelaufen -> Löschen
                        QSqlQuery del(db);
                        del.prepare("DELETE FROM refresh_tokens WHERE token = :t");
                        del.bindValue(":t", QString::fromStdString(token));
                        del.exec();
                    }
                }
            }
        }
        QSqlDatabase::removeDatabase(connName);
        return username;
    }

    // Entfernt einen spezifischen Refresh Token (Logout)
    static void revokeRefreshToken(const std::string& token) {
        QString connName = QString("logout_conn_%1").arg((quint64)QThread::currentThreadId());
        {
            QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", connName);
            db.setDatabaseName(DB_FILENAME);
            if (db.open()) {
                QSqlQuery q(db);
                q.prepare("DELETE FROM refresh_tokens WHERE token = :t");
                q.bindValue(":t", QString::fromStdString(token));
                q.exec();
            }
        }
        QSqlDatabase::removeDatabase(connName);
    }
};
