//----------------------------------------------------------//
//Integrante: Juan Angel Rodriguez Bulnes - Módulo Escaneo //
//--------------------------------------------------------//

#include "Escaneo.h"

// Mapa de servicios comunes
std::map<int, std::string> servicios_tcp = {
    {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"},
    {53, "dns"}, {80, "http"}, {110, "pop3"}, {143, "imap"},
    {443, "https"}, {993, "imaps"}, {995, "pop3s"}, {3306, "mysql"},
    {3389, "rdp"}, {5432, "postgresql"}, {27017, "mongodb"}
};

std::map<int, std::string> servicios_udp = {
    {53, "dns"}, {67, "dhcp"}, {68, "dhcp"}, {69, "tftp"},
    {123, "ntp"}, {161, "snmp"}, {162, "snmptrap"}, {514, "syslog"}
};

Escaneo::Escaneo(const std::string& ip_objetivo, int timeout_ms) 
    : ip_objetivo(ip_objetivo), timeout_ms(timeout_ms) {}

std::string Escaneo::determinarServicio(int puerto, const std::string& protocolo) {
    if (protocolo == "TCP") {
        auto it = servicios_tcp.find(puerto);
        if (it != servicios_tcp.end()) return it->second;
    } else {
        auto it = servicios_udp.find(puerto);
        if (it != servicios_udp.end()) return it->second;
    }
    return "desconocido";
}

// ESCANEO TCP
ResultadoEscaneo Escaneo::escanearPuertoTCP(int puerto) {
    ResultadoEscaneo resultado;
    resultado.ip = ip_objetivo;
    resultado.puerto = puerto;
    resultado.protocolo = "TCP";
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        resultado.estado = "error";
        resultado.servicio = "desconocido";
        return resultado;
    }
    
    // Socket no bloqueante
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in direccion;
    std::memset(&direccion, 0, sizeof(direccion));
    direccion.sin_family = AF_INET;
    direccion.sin_port = htons(puerto);
    inet_pton(AF_INET, ip_objetivo.c_str(), &direccion.sin_addr);
    
    // Intentar conexión
    int connect_result = connect(sockfd, (struct sockaddr*)&direccion, sizeof(direccion));
    
    if (connect_result == 0) {
        resultado.estado = "abierto";
    } else if (errno == EINPROGRESS) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sockfd, &writefds);
        
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        
        int select_result = select(sockfd + 1, NULL, &writefds, NULL, &timeout);
        
        if (select_result > 0) {
            int error_code;
            socklen_t error_len = sizeof(error_code);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error_code, &error_len);
            
            if (error_code == 0) {
                resultado.estado = "abierto";
            } else if (error_code == ECONNREFUSED) {
                resultado.estado = "cerrado";
            } else {
                resultado.estado = "filtrado";
            }
        } else if (select_result == 0) {
            resultado.estado = "filtrado";
        } else {
            resultado.estado = "error";
        }
    } else if (errno == ECONNREFUSED) {
        resultado.estado = "cerrado";
    } else {
        resultado.estado = "filtrado";
    }
    
    resultado.servicio = determinarServicio(puerto, "TCP");
    close(sockfd);
    return resultado;
}

// DETECCIÓN ICMP PARA UDP
bool Escaneo::recibirICMPPortUnreachable(int sockfd, const std::string& ip_objetivo, int puerto) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    int select_result = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
    
    if (select_result > 0) {
        char buffer[1024];
        struct sockaddr_in remoto;
        socklen_t remoto_len = sizeof(remoto);
        
        ssize_t bytes_recibidos = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                                         (struct sockaddr*)&remoto, &remoto_len);
        
        if (bytes_recibidos > 0) {
            // Verificar si es mensaje ICMP "Port Unreachable"
            struct ip* ip_header = (struct ip*)buffer;
            if (ip_header->ip_p == IPPROTO_ICMP) {
                struct icmp* icmp_header = (struct icmp*)(buffer + (ip_header->ip_hl * 4));
                if (icmp_header->icmp_type == ICMP_UNREACH && 
                    icmp_header->icmp_code == ICMP_UNREACH_PORT) {
                    return true; // Puerto cerrado
                }
            }
        }
    }
    
    return false; // No se recibió ICMP Port Unreachable
}

// ESCANEO UDP
ResultadoEscaneo Escaneo::escanearPuertoUDP(int puerto) {
    ResultadoEscaneo resultado;
    resultado.ip = ip_objetivo;
    resultado.puerto = puerto;
    resultado.protocolo = "UDP";
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        resultado.estado = "error";
        resultado.servicio = "desconocido";
        return resultado;
    }
    
    // Configurar timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in direccion;
    std::memset(&direccion, 0, sizeof(direccion));
    direccion.sin_family = AF_INET;
    direccion.sin_port = htons(puerto);
    inet_pton(AF_INET, ip_objetivo.c_str(), &direccion.sin_addr);
    
    // Enviar datagrama vacío
    const char* datos = "";
    ssize_t bytes_enviados = sendto(sockfd, datos, 0, 0, 
                                   (struct sockaddr*)&direccion, sizeof(direccion));
    
    if (bytes_enviados < 0) {
        resultado.estado = "error";
        close(sockfd);
        resultado.servicio = determinarServicio(puerto, "UDP");
        return resultado;
    }
    
    // Esperar respuesta
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    
    int select_result = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
    
    if (select_result > 0) {
        // Hay datos para leer - verificar si es ICMP o respuesta UDP
        if (recibirICMPPortUnreachable(sockfd, ip_objetivo, puerto)) {
            resultado.estado = "cerrado";
        } else {
            // Posible respuesta del servicio - PUERTO ABIERTO
            resultado.estado = "abierto";
        }
    } else if (select_result == 0) {
        // Timeout - PUERTO FILTRADO (o abierto pero sin respuesta)
        resultado.estado = "filtrado";
    } else {
        // Error
        resultado.estado = "error";
    }
    
    close(sockfd);
    resultado.servicio = determinarServicio(puerto, "UDP");
    return resultado;
}

// CONCURRENCIA TCP
std::vector<ResultadoEscaneo> Escaneo::escanearRangoTCPConcurrente(int puerto_inicio, int puerto_fin, int max_hilos) {
    std::vector<ResultadoEscaneo> resultados;
    std::vector<std::thread> hilos;
    std::vector<std::vector<int>> lotes(max_hilos);
    
    // Dividir puertos en lotes para cada hilo
    int total_puertos = puerto_fin - puerto_inicio + 1;
    int puertos_por_hilo = total_puertos / max_hilos;
    int extra_puertos = total_puertos % max_hilos;
    
    int puerto_actual = puerto_inicio;
    for (int i = 0; i < max_hilos; i++) {
        int puertos_en_lote = puertos_por_hilo + (i < extra_puertos ? 1 : 0);
        for (int j = 0; j < puertos_en_lote; j++) {
            lotes[i].push_back(puerto_actual++);
        }
    }
    
    // Vector para resultados de cada hilo
    std::vector<std::vector<ResultadoEscaneo>> resultados_parciales(max_hilos);
    
    // Lanzar hilos
    for (int i = 0; i < max_hilos; i++) {
        if (!lotes[i].empty()) {
            hilos.emplace_back(&Escaneo::escanearLoteTCP, this, 
                             std::cref(lotes[i]), 
                             std::ref(resultados_parciales[i]));
        }
    }
    
    // Esperar a que todos los hilos terminen
    for (auto& hilo : hilos) {
        if (hilo.joinable()) {
            hilo.join();
        }
    }
    
    // Combinar resultados
    for (const auto& parcial : resultados_parciales) {
        resultados.insert(resultados.end(), parcial.begin(), parcial.end());
    }
    
    return resultados;
}

void Escaneo::escanearLoteTCP(const std::vector<int>& puertos, std::vector<ResultadoEscaneo>& resultados) {
    for (int puerto : puertos) {
        ResultadoEscaneo resultado = escanearPuertoTCP(puerto);
        
        // Bloquear mutex para output seguro
        std::lock_guard<std::mutex> lock(mutex_resultados);
        resultados.push_back(resultado);
        std::cout << "[Hilo " << std::this_thread::get_id() << "] ";
        std::cout << "Puerto " << puerto << "/TCP: " << resultado.estado;
        if (resultado.estado == "abierto") {
            std::cout << " (" << resultado.servicio << ")";
        }
        std::cout << std::endl;
    }
}

// CONCURRENCIA UDP
std::vector<ResultadoEscaneo> Escaneo::escanearRangoUDPConcurrente(int puerto_inicio, int puerto_fin, int max_hilos) {
    std::vector<ResultadoEscaneo> resultados;
    std::vector<std::thread> hilos;
    std::vector<std::vector<int>> lotes(max_hilos);
    
    // Dividir puertos en lotes (misma lógica que TCP)
    int total_puertos = puerto_fin - puerto_inicio + 1;
    int puertos_por_hilo = total_puertos / max_hilos;
    int extra_puertos = total_puertos % max_hilos;
    
    int puerto_actual = puerto_inicio;
    for (int i = 0; i < max_hilos; i++) {
        int puertos_en_lote = puertos_por_hilo + (i < extra_puertos ? 1 : 0);
        for (int j = 0; j < puertos_en_lote; j++) {
            lotes[i].push_back(puerto_actual++);
        }
    }
    
    std::vector<std::vector<ResultadoEscaneo>> resultados_parciales(max_hilos);
    
    for (int i = 0; i < max_hilos; i++) {
        if (!lotes[i].empty()) {
            hilos.emplace_back(&Escaneo::escanearLoteUDP, this, 
                             std::cref(lotes[i]), 
                             std::ref(resultados_parciales[i]));
        }
    }
    
    for (auto& hilo : hilos) {
        if (hilo.joinable()) {
            hilo.join();
        }
    }
    
    for (const auto& parcial : resultados_parciales) {
        resultados.insert(resultados.end(), parcial.begin(), parcial.end());
    }
    
    return resultados;
}

void Escaneo::escanearLoteUDP(const std::vector<int>& puertos, std::vector<ResultadoEscaneo>& resultados) {
    for (int puerto : puertos) {
        ResultadoEscaneo resultado = escanearPuertoUDP(puerto);
        
        std::lock_guard<std::mutex> lock(mutex_resultados);
        resultados.push_back(resultado);
        std::cout << "[Hilo " << std::this_thread::get_id() << "] ";
        std::cout << "Puerto " << puerto << "/UDP: " << resultado.estado;
        if (resultado.estado == "abierto") {
            std::cout << " (" << resultado.servicio << ")";
        }
        std::cout << std::endl;
    }
}

// ESCANEO TCP Y UDP CONCURRENTE
std::vector<ResultadoEscaneo> Escaneo::escanearTCPyUDPConcurrente(int puerto_inicio, int puerto_fin) {
    std::vector<ResultadoEscaneo> todos_resultados;
    std::vector<std::thread> hilos;
    std::vector<ResultadoEscaneo> resultados_tcp, resultados_udp;
    
    std::cout << "🚀 Iniciando escaneo CONCURRENTE TCP y UDP...\n";
    
    // Hilo para TCP
    hilos.emplace_back([&]() {
        std::cout << "[Hilo TCP] Iniciando escaneo TCP...\n";
        resultados_tcp = escanearRangoTCPConcurrente(puerto_inicio, puerto_fin, 5);
    });
    
    // Hilo para UDP
    hilos.emplace_back([&]() {
        std::cout << "[Hilo UDP] Iniciando escaneo UDP...\n";
        resultados_udp = escanearRangoUDPConcurrente(puerto_inicio, puerto_fin, 5);
    });
    
    // Esperar que ambos hilos terminen
    for (auto& hilo : hilos) {
        if (hilo.joinable()) {
            hilo.join();
        }
    }
    
    // Combinar resultados
    todos_resultados.insert(todos_resultados.end(), resultados_tcp.begin(), resultados_tcp.end());
    todos_resultados.insert(todos_resultados.end(), resultados_udp.begin(), resultados_udp.end());
    
    return todos_resultados;
}
