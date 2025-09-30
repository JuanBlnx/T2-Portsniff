//
//  - Módulo principal - //
//Integrantes:
//    * Juan Angel Rodriguez Bulnes
//    * Angel David Morales Palomo
//    * Sofia Flores Martinez Cisneros
//

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include "Escaneo.h"
#include "Sniffer.h"
#include "JSONGen.h"

// Función para validar IP
bool validarIP(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

// Función para validar rango de puertos
bool validarPuertos(int inicio, int fin) {
    return (inicio >= 1 && inicio <= 65535 && fin >= 1 && fin <= 65535 && inicio <= fin);
}

// Función para solicitar entrada
void solicitarEntrada(std::string& ip, int& puerto_inicio, int& puerto_fin, int& timeout, std::string& archivo_salida) {
    std::cout << "=== CONFIGURACION DEL ESCANEO ===\n";
    
    // IP
    do {
        std::cout << "IP objetivo: ";
        std::getline(std::cin, ip);
        if (!validarIP(ip)) {
            std::cout << "IP invalida. Use formato: 192.168.1.100\n";
        }
    } while (!validarIP(ip));
    
    // Puertos
    do {
        std::cout << "Puerto inicial: ";
        std::cin >> puerto_inicio;
        std::cout << "Puerto final: ";
        std::cin >> puerto_fin;
        std::cin.ignore(); // Limpiar buffer
        
        if (!validarPuertos(puerto_inicio, puerto_fin)) {
            std::cout << "Rango de puertos invalido. Use: 1-65535\n";
        }
    } while (!validarPuertos(puerto_inicio, puerto_fin));
    
    // Timeout
    std::cout << "Timeout (ms) [predeterminado 1000]: ";
    std::string timeout_str;
    std::getline(std::cin, timeout_str);
    if (timeout_str.empty()) {
        timeout = 1000;
    } else {
        timeout = std::stoi(timeout_str);
    }
    
    // Archivo salida
    std::cout << "Archivo JSON de salida [predeterminado resultado.json]: ";
    std::getline(std::cin, archivo_salida);
    if (archivo_salida.empty()) {
        archivo_salida = "resultado.json";
    }
}

int main() {
    std::cout << "=== Escaner Hibrido de Puertos - CONCURRENTE ===\n";
    
    // Variables de configuración
    std::string ip_objetivo;
    int puerto_inicio, puerto_fin, timeout_ms;
    std::string archivo_salida;
    std::string interfaz = "enp0s3"; // Tu interfaz de red
    
    // Solicitar entrada al usuario
    solicitarEntrada(ip_objetivo, puerto_inicio, puerto_fin, timeout_ms, archivo_salida);
    
    // Crear objetos
    Escaneo escaner(ip_objetivo, timeout_ms);
    Sniffer sniffer(interfaz, ip_objetivo);
    
    // Inicializar sniffer
    if (!sniffer.inicializar()) {
        std::cerr << "No se pudo inicializar el sniffer" << std::endl;
        return 1;
    }
    
    std::cout << "\nINICIANDO ESCANEO CONCURRENTE...\n";
    
    auto inicio_total = std::chrono::steady_clock::now();
    
    // ESCANEO CONCURRENTE TCP y UDP
    std::vector<ResultadoEscaneo> todos_resultados = escaner.escanearTCPyUDPConcurrente(puerto_inicio, puerto_fin);
    
    auto fin_escaneo = std::chrono::steady_clock::now();
    auto duracion_escaneo = std::chrono::duration_cast<std::chrono::milliseconds>(fin_escaneo - inicio_total);
    std::cout << "Escaneco completado en " << duracion_escaneo.count() << "ms\n";
    
    // Identificar puertos abiertos para captura
    std::vector<std::pair<int, std::string>> puertos_abiertos;
    for (const auto& resultado : todos_resultados) {
        if (resultado.estado == "abierto") {
            puertos_abiertos.push_back({resultado.puerto, resultado.protocolo});
        }
    }
    
    std::cout << "\nIniciando captura concurrente para " << puertos_abiertos.size() << " puertos abiertos...\n";
    
    // CAPTURA CONCURRENTE
    if (!puertos_abiertos.empty()) {
        sniffer.iniciarCapturaConcurrente(puertos_abiertos, timeout_ms);
        
        // Esperar a que la captura termine
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms * 2));
        sniffer.detenerCaptura();
        
        // Asignar resultados de captura
        for (auto& resultado : todos_resultados) {
            if (resultado.estado == "abierto") {
                resultado.header_bytes = sniffer.obtenerResultadoCaptura(resultado.puerto, resultado.protocolo);
            }
        }
    }
    
    auto fin_total = std::chrono::steady_clock::now();
    auto duracion_total = std::chrono::duration_cast<std::chrono::milliseconds>(fin_total - inicio_total);
    
    // Generar JSON
    std::cout << "\nGenerando reporte JSON...\n";
    if (JSONGen::generarJSON(todos_resultados, archivo_salida)) {
        std::cout << "Reporte generado exitosamente!\n";
    } else {
        std::cerr << "Error generando reporte\n";
    }
    
    // Mostrar resumen final
    std::cout << "\nRESUMEN FINAL CONCURRENTE:\n";
    std::cout << "Tiempo total: " << duracion_total.count() << "ms\n";
    
    int abiertos_tcp = 0, abiertos_udp = 0;
    for (const auto& resultado : todos_resultados) {
        if (resultado.estado == "abierto") {
            if (resultado.protocolo == "TCP") abiertos_tcp++;
            else abiertos_udp++;
            
            std::cout << "Puerto " << resultado.puerto << "/" << resultado.protocolo 
                      << " - " << resultado.servicio 
                      << " - Bytes: " << resultado.header_bytes << std::endl;
        }
    }
    
    std::cout << "\nTotal: " << abiertos_tcp << " TCP abiertos, " 
              << abiertos_udp << " UDP abiertos de " 
              << (puerto_fin - puerto_inicio + 1) * 2 << " puertos escaneados" << std::endl;
    
    return 0;
}
