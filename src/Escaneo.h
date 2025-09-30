//----------------------------------------------------------//
//Integrante: Juan Angel Rodriguez Bulnes - Módulo Escaneo //
//--------------------------------------------------------//

#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <future>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <cstring>
#include <iostream>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

struct ResultadoEscaneo {
    std::string ip;
    int puerto;
    std::string protocolo;
    std::string estado;
    std::string servicio;
    std::string header_bytes;
};

class Escaneo {
public:
    Escaneo(const std::string& ip_objetivo, int timeout_ms);
    
    // Escaneo secuencial
    ResultadoEscaneo escanearPuertoTCP(int puerto);
    ResultadoEscaneo escanearPuertoUDP(int puerto);
    
    // Escaneo concurrente
    std::vector<ResultadoEscaneo> escanearRangoTCPConcurrente(int puerto_inicio, int puerto_fin, int max_hilos = 10);
    std::vector<ResultadoEscaneo> escanearRangoUDPConcurrente(int puerto_inicio, int puerto_fin, int max_hilos = 10);
    std::vector<ResultadoEscaneo> escanearTCPyUDPConcurrente(int puerto_inicio, int puerto_fin);
    
private:
    std::string ip_objetivo;
    int timeout_ms;
    std::mutex mutex_resultados;
    
    std::string determinarServicio(int puerto, const std::string& protocolo);
    bool recibirICMPPortUnreachable(int sockfd, const std::string& ip_objetivo, int puerto);
    
    // Funciones para hilos
    void escanearLoteTCP(const std::vector<int>& puertos, std::vector<ResultadoEscaneo>& resultados);
    void escanearLoteUDP(const std::vector<int>& puertos, std::vector<ResultadoEscaneo>& resultados);
};

#endif
