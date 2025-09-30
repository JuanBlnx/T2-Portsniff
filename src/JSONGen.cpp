//---------------------------------------------------------//
//Integrante: Angel David Morales Palomo - Módulo JSONGen //
//-------------------------------------------------------//

#include "JSONGen.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>

bool JSONGen::generarJSON(const std::vector<ResultadoEscaneo>& resultados, 
                         const std::string& nombreArchivo) {
    std::ofstream archivo(nombreArchivo);
    if (!archivo.is_open()) {
        std::cerr << "Error al crear archivo JSON: " << nombreArchivo << std::endl;
        return false;
    }
    
    archivo << "[\n";
    for (size_t i = 0; i < resultados.size(); i++) {
        const auto& resultado = resultados[i];
        
        archivo << "  {\n";
        archivo << "    \"ip\": \"" << escapeJSON(resultado.ip) << "\",\n";
        archivo << "    \"port\": " << resultado.puerto << ",\n";
        archivo << "    \"protocol\": \"" << escapeJSON(resultado.protocolo) << "\",\n";
        archivo << "    \"service\": \"" << escapeJSON(resultado.servicio) << "\",\n";
        archivo << "    \"state\": \"" << escapeJSON(resultado.estado) << "\",\n";
        archivo << "    \"header_bytes\": \"" << escapeJSON(resultado.header_bytes) << "\"\n";
        archivo << "  }";
        
        if (i < resultados.size() - 1) {
            archivo << ",";
        }
        archivo << "\n";
    }
    archivo << "]\n";
    
    archivo.close();
    std::cout << "JSON guardado en: " << nombreArchivo << std::endl;
    return true;
}

std::string JSONGen::escapeJSON(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default: ss << c; break;
        }
    }
    return ss.str();
}
