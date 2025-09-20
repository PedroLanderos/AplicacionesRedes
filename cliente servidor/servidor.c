// servidor.c
// Servidor TCP con validación, comunicación bidireccional, soporte a múltiples clientes y envío de archivos.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Credenciales fijas para validación
#define USER_ID "usuario123"
#define PASSWORD "clave123"

// Función para atender cada cliente (se ejecuta en proceso hijo con fork)
void atender_cliente(int client_fd) {
    char buffer[BUFFER_SIZE];
    int bytes;
y
    // 1. Validación de acceso
    send(client_fd, "Ingrese ID de usuario: ", 24, 0);
    bytes = read(client_fd, buffer, BUFFER_SIZE - 1);
    buffer[bytes] = '\0';
    buffer[strcspn(buffer, "\n")] = '\0'; // quitar salto de línea
    if (strcmp(buffer, USER_ID) != 0) {
        send(client_fd, "ID incorrecto. Conexión cerrada.\n", 33, 0);
        close(client_fd);
        exit(0);
    }

    send(client_fd, "Ingrese contraseña: ", 21, 0);
    bytes = read(client_fd, buffer, BUFFER_SIZE - 1);
    buffer[bytes] = '\0';
    buffer[strcspn(buffer, "\n")] = '\0';
    if (strcmp(buffer, PASSWORD) != 0) {
        send(client_fd, "Contraseña incorrecta. Conexión cerrada.\n", 41, 0);
        close(client_fd);
        exit(0);
    }

    send(client_fd, "Acceso concedido.\n", 18, 0);

    // 2. Comunicación bidireccional
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (bytes <= 0) break;

        buffer[bytes] = '\0';
        printf("Cliente dice: %s\n", buffer);

        // Si el cliente pide un archivo
        if (strncmp(buffer, "GET ", 4) == 0) {
            char filename[BUFFER_SIZE];
            sscanf(buffer + 4, "%s", filename);
            FILE *f = fopen(filename, "rb");
            if (!f) {
                char *msg = "Archivo no encontrado.\n";
                send(client_fd, msg, strlen(msg), 0);
            } else {
                char filebuf[BUFFER_SIZE];
                size_t n;
                while ((n = fread(filebuf, 1, BUFFER_SIZE, f)) > 0) {
                    send(client_fd, filebuf, n, 0);
                }
                fclose(f);
                char *msg = "\n[Archivo enviado]\n";
                send(client_fd, msg, strlen(msg), 0);
            }
        } else {
            // El servidor escribe una respuesta (chat simple)
            char respuesta[BUFFER_SIZE];
            printf("Escribe respuesta para el cliente: ");
            fflush(stdout);
            fgets(respuesta, BUFFER_SIZE, stdin);
            send(client_fd, respuesta, strlen(respuesta), 0);
        }
    }

    close(client_fd);
    exit(0);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Crear socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Error al crear socket");
        exit(EXIT_FAILURE);
    }

    // Configuración del servidor
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Enlazar socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error en bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Escuchar conexiones
    if (listen(server_fd, 5) < 0) {
        perror("Error en listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Servidor esperando conexiones en el puerto %d...\n", PORT);

    // Aceptar múltiples clientes con fork()
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("Error al aceptar conexión");
            continue;
        }

        printf("Nuevo cliente conectado.\n");

        pid_t pid = fork();
        if (pid == 0) {
            // Proceso hijo atiende cliente
            close(server_fd);
            atender_cliente(client_fd);
        } else if (pid > 0) {
            // Proceso padre
            close(client_fd);
            waitpid(-1, NULL, WNOHANG); // evitar zombies
        } else {
            perror("Error en fork");
        }
    }

    close(server_fd);
    return 0;
}
