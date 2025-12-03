// helper functions
bool isAllowedImage(const std::string& filename) {
    // Erlaubte Endungen
    const std::set<std::string> allowed = { ".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".gif" };

    // Endung finden
    size_t pos = filename.rfind('.');
    if (pos == std::string::npos) return false; // Keine Endung

    std::string ext = filename.substr(pos);
    
    // In Kleinbuchstaben umwandeln (damit .JPG auch geht)
    std::transform(ext.begin(), ext.end(), ext.begin(), 
                   [](unsigned char c){ return std::tolower(c); });

    return allowed.find(ext) != allowed.end();
}
