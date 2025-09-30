//-------------------------------------------------------------//
//Integrante: Sofia Flores Martinez Cisneros - Módulo Sniffer //
//-----------------------------------------------------------//

#include "Sniffer.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <chrono>

Sniffer::Sniffer(const std::string& interfaz, const std::string& ip_objetivo)
    : interfaz(interfaz), ip_objetivo(ip_objetivo), handle(nullptr), activo(false) {}

Sniffer::~Sniffer() {
    detenerCaptura();
}

bool Sniffer::inicializar() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    // Abrir interfaz en modo promiscuo
    handle = pcap_open_live(interfaz.c_str(), BUFSIZ, 1, 1000, error_buffer);
    if (handle == nullptr) {
        std::cerr << "Error al abrir interfaz " << interfaz << ": " << error_buffer << std::endl;
        return false;
    }
    
    // Compilar filtro para capturar solo tráfico del objetivo
    std::string filtro = "host " + ip_objetivo;
    struct bpf_program fp;
    
    if (pcap_compile(handle, &fp, filtro.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compilando filtro: " << pcap_geterr(handle) << std::endl;
        return false;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error aplicando filtro: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        return false;
    }
    
    pcap_freecode(&fp);
    activo = true;
    std::cout << "Sniffer inicializado en " << interfaz << " para " << ip_objetivo << std::endl;
    return true;
}

// CAPTURA SIMPLE
std::string Sniffer::capturarRespuesta(int puerto, const std::string& protocolo, int timeout_ms) {
    if (!activo || handle == nullptr) {
        return "sniffer_no_inicializado";
    }
    
    // Configurar filtro específico por puerto y protocolo
    std::string filtro_especifico = "host " + ip_objetivo + " and ";
    if (protocolo == "TCP") {
        filtro_especifico += "tcp port " + std::to_string(puerto);
    } else {
        filtro_especifico += "udp port " + std::to_string(puerto);
    }
    
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filtro_especifico.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compilando filtro específico: " << pcap_geterr(handle) << std::endl;
        return "error_filtro";
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error aplicando filtro específico: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        return "error_filtro";
    }
    
    pcap_freecode(&fp);
    
    // Capturar un paquete con timeout
    struct pcap_pkthdr* cabecera;
    const unsigned char* paquete;
    
    int resultado = pcap_next_ex(handle, &cabecera, &paquete);
    
    if (resultado == 1) {
        // Paquete capturado - extraer primeros bytes
        size_t bytes_a_capturar = (cabecera->caplen < 16) ? cabecera->caplen : 16;
        return bytesToHex(paquete, bytes_a_capturar);
    } else if (resultado == 0) {
        // Timeout
        return "timeout";
    } else {
        // Error
        return "error_captura";
    }
}

// CAPTURA CONCURRENTE
void Sniffer::iniciarCapturaConcurrente(const std::vector<std::pair<int, std::string>>& puertos_abiertos, int timeout_ms) {
    // Limpiar tareas anteriores
    {
        std::lock_guard<std::mutex> lock(mutex_capturas);
        tareas_captura.clear();
        
        // Crear nuevas tareas
        for (const auto& puerto_proto : puertos_abiertos) {
            tareas_captura.push_back({puerto_proto.first, puerto_proto.second, "", false});
        }
    }
    
    activo = true;
    
    // Iniciar hilo de captura
    hilo_captura = std::thread(&Sniffer::ejecutarCaptura, this, timeout_ms);
}

void Sniffer::ejecutarCaptura(int timeout_ms) {
    std::cout << "[Hilo Captura] Iniciando captura concurrente..." << std::endl;
    
    auto inicio = std::chrono::steady_clock::now();
    
    while (activo) {
        // Verificar timeout general
        auto ahora = std::chrono::steady_clock::now();
        auto duracion = std::chrono::duration_cast<std::chrono::milliseconds>(ahora - inicio).count();
        if (duracion > timeout_ms * 2) {
            std::cout << "[Hilo Captura] Timeout de captura alcanzado" << std::endl;
            break;
        }
        
        // Verificar si todas las tareas están completas
        bool todas_completadas = true;
        {
            std::lock_guard<std::mutex> lock(mutex_capturas);
            for (const auto& tarea : tareas_captura) {
                if (!tarea.completada) {
                    todas_completadas = false;
                    break;
                }
            }
        }
        
        if (todas_completadas) {
            std::cout << "[Hilo Captura] Todas las capturas completadas" << std::endl;
            break;
        }
        
        // Configurar filtro para todos los puertos abiertos
        std::string filtro = "host " + ip_objetivo + " and (";
        bool primer_filtro = true;
        
        {
            std::lock_guard<std::mutex> lock(mutex_capturas);
            for (const auto& tarea : tareas_captura) {
                if (!tarea.completada) {
                    if (!primer_filtro) filtro += " or ";
                    filtro += tarea.protocolo + " port " + std::to_string(tarea.puerto);
                    primer_filtro = false;
                }
            }
        }
        
        filtro += ")";
        
        // Aplicar filtro
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filtro.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            continue; // Reintentar
        }
        
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
        
        // Capturar un paquete
        struct pcap_pkthdr* cabecera;
        const unsigned char* paquete;
        
        int resultado = pcap_next_ex(handle, &cabecera, &paquete);
        
        if (resultado == 1) {
            // Analizar paquete capturado
            struct ip* ip_header = (struct ip*)paquete;
            std::string ip_origen = inet_ntoa(ip_header->ip_src);
            
            if (ip_origen == ip_objetivo) {
                uint16_t puerto_origen = 0;
                std::string protocolo;
                
                if (ip_header->ip_p == IPPROTO_TCP) {
                    struct tcphdr* tcp_header = (struct tcphdr*)(paquete + (ip_header->ip_hl * 4));
                    puerto_origen = ntohs(tcp_header->th_sport);
                    protocolo = "TCP";
                } else if (ip_header->ip_p == IPPROTO_UDP) {
                    struct udphdr* udp_header = (struct udphdr*)(paquete + (ip_header->ip_hl * 4));
                    puerto_origen = ntohs(udp_header->uh_sport);
                    protocolo = "UDP";
                }
                
                if (puerto_origen > 0) {
                    std::lock_guard<std::mutex> lock(mutex_capturas);
                    for (auto& tarea : tareas_captura) {
                        if (!tarea.completada && tarea.puerto == puerto_origen && tarea.protocolo == protocolo) {
                            // LÍNEA CORREGIDA:
                            tarea.header_bytes = bytesToHex(paquete, (cabecera->caplen < 16) ? cabecera->caplen : 16);
                            tarea.completada = true;
                            std::cout << "[Hilo Captura] Capturado puerto " << puerto_origen << "/" << protocolo << std::endl;
                            break;
                        }
                    }
                }
            }
        }
        
        // Pequeña pausa para no saturar la CPU
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    activo = false;
    std::cout << "[Hilo Captura] Captura concurrente finalizada" << std::endl;
}

std::string Sniffer::obtenerResultadoCaptura(int puerto, const std::string& protocolo) {
    std::lock_guard<std::mutex> lock(mutex_capturas);
    
    for (const auto& tarea : tareas_captura) {
        if (tarea.puerto == puerto && tarea.protocolo == protocolo) {
            return tarea.header_bytes.empty() ? "no_capturado" : tarea.header_bytes;
        }
    }
    
    return "no_encontrado";
}

void Sniffer::detenerCaptura() {
    activo = false;
    if (hilo_captura.joinable()) {
        hilo_captura.join();
    }
    
    if (handle != nullptr) {
        pcap_close(handle);
        handle = nullptr;
    }
}

std::string Sniffer::bytesToHex(const unsigned char* datos, size_t longitud) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < longitud; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(datos[i]);
        if (i < longitud - 1) {
            ss << " ";
        }
    }
    
    return ss.str();
}

void Sniffer::manejarPaquete(unsigned char* usuario, const struct pcap_pkthdr* cabecera, const unsigned char* paquete) {
    // Callback para procesamiento asíncrono
}
