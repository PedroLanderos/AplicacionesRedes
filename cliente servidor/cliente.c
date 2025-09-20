// cliente.c
// Cliente TCP que permite autenticarse, enviar mensajes, recibir respuestas y pedir archivos al servidor.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // Crear socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error al crear socket");
        exit(EXIT_FAILURE);
    }

    // Configuración del servidor
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Conectar con el servidor
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error al conectar");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Conectado al servidor.\n");

    // Comunicación
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);

        // Recibir mensaje del servidor (ej. pedir ID/contraseña o respuesta)
        int bytes = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (bytes <= 0) {
            printf("Conexión cerrada por el servidor.\n");
            break;
        }
        buffer[bytes] = '\0';
        printf("Servidor dice: %s\n", buffer);

        // Leer input del usuario
        char mensaje[BUFFER_SIZE];
        printf("Escribe mensaje para el servidor: ");
        fflush(stdout);
        if (!fgets(mensaje, BUFFER_SIZE, stdin)) break;

        // Enviar al servidor
        send(sockfd, mensaje, strlen(mensaje), 0);
    }

    close(sockfd);
    return 0;
}
