//---------------------------------------------------------//
//Integrante: Angel David Morales Palomo - Módulo JSONGen //
//-------------------------------------------------------//

#ifndef JSONGEN_H
#define JSONGEN_H

#include <string>
#include <vector>
#include "Escaneo.h"

class JSONGen {
public:
    static bool generarJSON(const std::vector<ResultadoEscaneo>& resultados, 
                           const std::string& nombreArchivo);
    
private:
    static std::string escapeJSON(const std::string& input);
};

#endif
