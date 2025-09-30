//--------------------------------------------------------------//
//Integrante: Sofia Flores Martinez Cisneros  - Módulo Sniffer //
//------------------------------------------------------------//

#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

struct TareaCaptura {
    int puerto;
    std::string protocolo;
    std::string header_bytes;
    bool completada;
};

class Sniffer {
public:
    Sniffer(const std::string& interfaz, const std::string& ip_objetivo);
    ~Sniffer();
    
    bool inicializar();
    void iniciarCapturaConcurrente(const std::vector<std::pair<int, std::string>>& puertos_abiertos, int timeout_ms);
    std::string obtenerResultadoCaptura(int puerto, const std::string& protocolo);
    void detenerCaptura();
    
    // Método simple (para uso no concurrente)
    std::string capturarRespuesta(int puerto, const std::string& protocolo, int timeout_ms);
    
private:
    std::string interfaz;
    std::string ip_objetivo;
    pcap_t* handle;
    std::atomic<bool> activo;
    std::mutex mutex_capturas;
    std::vector<TareaCaptura> tareas_captura;
    std::thread hilo_captura;
    
    std::string bytesToHex(const unsigned char* datos, size_t longitud);
    void ejecutarCaptura(int timeout_ms);
    static void manejarPaquete(unsigned char* usuario, const struct pcap_pkthdr* cabecera, const unsigned char* paquete);
};

#endif
