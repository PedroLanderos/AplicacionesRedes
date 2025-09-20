#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#define DEFAULT_PRINTER_PORT 9100
#define BUF_SIZE 4096

static void mostrar_uso(const char *prog) {
    fprintf(stderr,
        "Uso:\n"
        "  %s -h <IP> [-p <puerto=9100>] (-m \"mensaje\" | -f <archivo>)\n"
        "\n"
        "Ejemplos:\n"
        "  %s -h 192.168.1.50 -m \"Prueba desde socket bloqueante\\n\"\n"
        "  %s -h 192.168.1.50 -f documento.txt -p 9100\n",
        prog, prog, prog
    );
}

// Envía exactamente 'len' bytes, reintentando si send() envía parcial.
// Devuelve 0 si OK; -1 si error.
static int send_todo(int sockfd, const void *data, size_t len) {
    const char *p = (const char *)data;
    size_t total = 0;

    while (total < len) {
        ssize_t n = send(sockfd, p + total, len - total, 0);
        if (n < 0) {
            // Si el peer cerró y genera SIGPIPE, lo ignoramos (signal(SIGPIPE, SIG_IGN) más abajo)
            perror("send");
            return -1;
        }
        if (n == 0) {
            // Muy raro en send(); tratar como error
            fprintf(stderr, "send devolvió 0 (conexión cerrada inesperadamente)\n");
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    const char *ip_str = NULL;
    const char *mensaje = NULL;
    const char *ruta_archivo = NULL;
    int puerto = DEFAULT_PRINTER_PORT;

    // Ignorar SIGPIPE para que send() falle con -1 en vez de matar el proceso
    signal(SIGPIPE, SIG_IGN);

    // Parseo simple de argumentos
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") && i + 1 < argc) {
            ip_str = argv[++i];
        } else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
            puerto = atoi(argv[++i]);
            if (puerto <= 0 || puerto > 65535) {
                fprintf(stderr, "Puerto inválido: %d\n", puerto);
                return EXIT_FAILURE;
            }
        } else if (!strcmp(argv[i], "-m") && i + 1 < argc) {
            mensaje = argv[++i];
        } else if (!strcmp(argv[i], "-f") && i + 1 < argc) {
            ruta_archivo = argv[++i];
        } else {
            mostrar_uso(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!ip_str || (!mensaje && !ruta_archivo)) {
        mostrar_uso(argv[0]);
        return EXIT_FAILURE;
    }

    // Crear socket TCP (bloqueante por defecto)
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error al crear socket");
        return EXIT_FAILURE;
    }

    // Configurar dirección de la impresora
    struct sockaddr_in printer_addr;
    memset(&printer_addr, 0, sizeof(printer_addr));
    printer_addr.sin_family = AF_INET;
    printer_addr.sin_port = htons((uint16_t)puerto);
    if (inet_pton(AF_INET, ip_str, &printer_addr.sin_addr) <= 0) {
        perror("Dirección IP inválida (usa IPv4 numérica, p. ej. 192.168.1.50)");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // Conectar
    fprintf(stdout, "Conectando a %s:%d ...\n", ip_str, puerto);
    if (connect(sockfd, (struct sockaddr*)&printer_addr, sizeof(printer_addr)) < 0) {
        perror("Error al conectar con la impresora/servidor");
        close(sockfd);
        return EXIT_FAILURE;
    }
    fprintf(stdout, "Conexión establecida.\n");

    int rc = 0;

    if (mensaje) {
        size_t len = strlen(mensaje);
        rc = send_todo(sockfd, mensaje, len);
        if (rc == 0) {
            fprintf(stdout, "Mensaje (%zu bytes) enviado correctamente.\n", len);
        }
    } else if (ruta_archivo) {
        FILE *f = fopen(ruta_archivo, "rb");
        if (!f) {
            perror("No se pudo abrir el archivo");
            close(sockfd);
            return EXIT_FAILURE;
        }
        fprintf(stdout, "Enviando archivo: %s\n", ruta_archivo);

        char buf[BUF_SIZE];
        size_t leidos;
        size_t total = 0;
        while ((leidos = fread(buf, 1, sizeof(buf), f)) > 0) {
            if (send_todo(sockfd, buf, leidos) != 0) {
                rc = -1;
                break;
            }
            total += leidos;
        }
        if (ferror(f)) {
            perror("Error al leer el archivo");
            rc = -1;
        } else if (rc == 0) {
            fprintf(stdout, "Archivo enviado (%zu bytes).\n", total);
        }
        fclose(f);
    }

    // Cerrar conexión
    if (close(sockfd) < 0) {
        perror("Error al cerrar el socket");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "Conexión cerrada.\n");

    return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
