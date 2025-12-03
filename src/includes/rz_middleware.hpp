// -------------------------------------------------------------------------
// AUTH MIDDLEWARE
// -------------------------------------------------------------------------

const std::string JWT_SECRET = "mein_sehr_geheimes_secret_key_12345";
const std::string JWT_ISSUER = "crow_qt_server";

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

// Zufalls-Strings für Refresh Token
// TODO: replace with opnessl/rand.h
std::string _generateRandomString(size_t length) {
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.resize(length);
    for (size_t i = 0; i < length; i++) {
        result[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    return result;
}

std::string generateRandomString(size_t length) {
    // Unser Zeichenvorrat (62 Zeichen)
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t charsetSize = sizeof(charset) - 1;

    std::string result;
    result.resize(length);

    // Buffer für die Zufallsbytes erstellen
    std::vector<unsigned char> buffer(length);

    // RAND_bytes füllt den Buffer kryptographisch sicher.
    // Rückgabewert 1 bedeutet Erfolg, 0 oder -1 Fehler.
    // Der Cast auf (int) ist nötig, da die OpenSSL API int erwartet.
    if (RAND_bytes(buffer.data(), static_cast<int>(length)) != 1) {
        // Sollte eigentlich nie passieren, aber sicher ist sicher (z.B. Entropie-Pool leer)
        throw std::runtime_error("OpenSSL RAND_bytes failed to generate entropy");
    }

    // Bytes auf das Charset mappen
    for (size_t i = 0; i < length; i++) {
        // Wir nehmen das zufällige Byte modulo der Charset-Länge.
        // (Hinweis: Technisch gesehen gibt es hier einen minimalen Modulo-Bias, 
        // da 256 nicht glatt durch 62 teilbar ist. Für Refresh-Tokens ist das 
        // jedoch vernachlässigbar sicher genug.)
        result[i] = charset[buffer[i] % charsetSize];
    }

    return result;
}

