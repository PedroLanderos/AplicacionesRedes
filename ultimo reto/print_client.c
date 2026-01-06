// print_client.c
// Cliente TCP bloqueante para enviar "trabajos de impresión" a una impresora en red (puerto 9100 por defecto).
// Uso:
//   ./print_client -i <IP> [-p <puerto>] [-m "mensaje"] [-f ruta/al/archivo.txt]
//
// Ejemplos:
//   ./print_client -i 192.168.1.50 -m "Hola impresora\n"
//   ./print_client -i 127.0.0.1 -p 9100 -f texto.txt
//
// Compilar en Linux:
//   gcc -O2 -Wall -Wextra -pedantic -std=c11 print_client.c -o print_client

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
// (opcional) en algunas distros ayuda incluir:
#include <getopt.h>

#define DEFAULT_PORT 9100
#define BUFSZ 4096

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso:\n"
        "  %s -i <IP> [-p <puerto>] [-m \"mensaje\"] [-f archivo]\n\n"
        "Opciones:\n"
        "  -i <IP>         IP de la impresora/servidor (obligatoria)\n"
        "  -p <puerto>     Puerto TCP (por defecto 9100)\n"
        "  -m <mensaje>    Cadena a enviar (si no se usa -f)\n"
        "  -f <archivo>    Enviar contenido de archivo de texto\n"
        "\n"
        "Notas:\n"
        "  Si se especifican -m y -f, se prioriza -f.\n", prog);
}

static int send_all(int sockfd, const void *buf, size_t len) {
    const char *p = (const char*)buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(sockfd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue; // reintentar si fue interrumpido
            perror("send");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "send devolvió 0 (conexión cerrada inesperadamente)\n");
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

static int send_file(int sockfd, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    char buf[BUFSZ];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (send_all(sockfd, buf, n) < 0) {
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp)) {
        perror("fread");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *ip = NULL;
    int port = DEFAULT_PORT;
    const char *message = "Ejemplo de trabajo de impresión.\n";
    const char *filepath = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "i:p:m:f:h")) != -1) {
        switch (opt) {
            case 'i': ip = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'm': message = optarg; break;
            case 'f': filepath = optarg; break;
            case 'h':
            default: usage(argv[0]); return (opt=='h') ? 0 : 1;
        }
    }

    if (!ip) {
        usage(argv[0]);
        return 1;
    }

    // 1) Crear socket TCP bloqueante
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // 2) Establecer conexión con la "impresora"
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        perror("inet_pton (IP inválida)");
        close(sockfd);
        return 1;
    }

    printf("[INFO] Conectando a %s:%d ...\n", ip, port);
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }
    printf("[OK] Conexión establecida.\n");

    // 3) Enviar mensaje o archivo
    int rc = 0;
    if (filepath) {
        printf("[INFO] Enviando archivo: %s\n", filepath);
        rc = send_file(sockfd, filepath);
    } else {
        printf("[INFO] Enviando mensaje (%zu bytes)\n", strlen(message));
        rc = send_all(sockfd, message, strlen(message));
// print_client.c
// Cliente TCP bloqueante para enviar "trabajos de impresión" a una impresora en red (puerto 9100 por defecto).
// Uso:
//   ./print_client -i <IP> [-p <puerto>] [-m "mensaje"] [-f ruta/al/archivo.txt]
//
// Ejemplos:
//   ./print_client -i 192.168.1.50 -m "Hola impresora\n"
//   ./print_client -i 127.0.0.1 -p 9100 -f texto.txt
//
// Compilar en Linux:
//   gcc -O2 -Wall -Wextra -pedantic -std=c11 print_client.c -o print_client

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
// (opcional) en algunas distros ayuda incluir:
#include <getopt.h>

#define DEFAULT_PORT 9100
#define BUFSZ 4096

static void usage(const char *prog) {
    fprintf(stderr,
        "Uso:\n"
        "  %s -i <IP> [-p <puerto>] [-m \"mensaje\"] [-f archivo]\n\n"
        "Opciones:\n"
        "  -i <IP>         IP de la impresora/servidor (obligatoria)\n"
        "  -p <puerto>     Puerto TCP (por defecto 9100)\n"
        "  -m <mensaje>    Cadena a enviar (si no se usa -f)\n"
        "  -f <archivo>    Enviar contenido de archivo de texto\n"
        "\n"
        "Notas:\n"
        "  Si se especifican -m y -f, se prioriza -f.\n", prog);
}

static int send_all(int sockfd, const void *buf, size_t len) {
    const char *p = (const char*)buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(sockfd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue; // reintentar si fue interrumpido
            perror("send");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "send devolvió 0 (conexión cerrada inesperadamente)\n");
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

static int send_file(int sockfd, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    char buf[BUFSZ];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (send_all(sockfd, buf, n) < 0) {
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp)) {
        perror("fread");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *ip = NULL;
    int port = DEFAULT_PORT;
    const char *message = "Ejemplo de trabajo de impresión.\n";
    const char *filepath = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "i:p:m:f:h")) != -1) {
        switch (opt) {
            case 'i': ip = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'm': message = optarg; break;
            case 'f': filepath = optarg; break;
            case 'h':
            default: usage(argv[0]); return (opt=='h') ? 0 : 1;
        }
    }

    if (!ip) {
        usage(argv[0]);
        return 1;
    }

    // 1) Crear socket TCP bloqueante
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // 2) Establecer conexión con la "impresora"
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        perror("inet_pton (IP inválida)");
        close(sockfd);
        return 1;
    }

    printf("[INFO] Conectando a %s:%d ...\n", ip, port);
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }
    printf("[OK] Conexión establecida.\n");

    // 3) Enviar mensaje o archivo
    int rc = 0;
    if (filepath) {
        printf("[INFO] Enviando archivo: %s\n", filepath);
        rc = send_file(sockfd, filepath);
    } else {
        printf("[INFO] Enviando mensaje (%zu bytes)\n", strlen(message));
        rc = send_all(sockfd, message, strlen(message));
    }
    if (rc < 0) {
        fprintf(stderr, "[ERROR] Falló el envío de datos.\n");
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
        return 1;
    }
    printf("[OK] Datos enviados.\n");

    // 4) Cierre correcto
    if (shutdown(sockfd, SHUT_WR) < 0) {
        perror("shutdown");
    } else {
        printf("[INFO] Señalado fin de escritura (shutdown).\n");
    }
    close(sockfd);
    printf("[OK] Conexión cerrada.\n");
    return 0;
}
    }
    if (rc < 0) {
        fprintf(stderr, "[ERROR] Falló el envío de datos.\n");
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
        return 1;
    }
    printf("[OK] Datos enviados.\n");

    // 4) Cierre correcto
    if (shutdown(sockfd, SHUT_WR) < 0) {
        perror("shutdown");
    } else {
        printf("[INFO] Señalado fin de escritura (shutdown).\n");
    }
    close(sockfd);
    printf("[OK] Conexión cerrada.\n");
    return 0;
}

