#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "cJSON.h"

#define multicastGroup "239.128.1.1"
#define bufferSize 500 * 1024
#define maxLen 512
#define chunkDir "chunks"

// Function to compute the SHA-256 hash of given data
void computeSha256(const void *data, size_t length, char *output)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
    {
        perror("EVP_MD_CTX_new failed");
        return;
    }

    if (EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL) != 1)
    {
        perror("EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(mdCtx);
        return;
    }

    if (EVP_DigestUpdate(mdCtx, data, length) != 1)
    {
        perror("EVP_DigestUpdate failed");
        EVP_MD_CTX_free(mdCtx);
        return;
    }

    if (EVP_DigestFinal_ex(mdCtx, hash, NULL) != 1)
    {
        perror("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(mdCtx);
        return;
    }

    EVP_MD_CTX_free(mdCtx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

// Function to process a file and split it into chunks
void processFile(const char *filePath, int sock, struct sockaddr_in *addr)
{
    FILE *file = fopen(filePath, "rb");
    if (!file)
    {
        perror("Error opening file");
        return;
    }
    mkdir(chunkDir, 0777);
    char chunkHash[SHA256_DIGEST_LENGTH * 2 + 1];
    char fileHash[SHA256_DIGEST_LENGTH * 2 + 1];
    computeSha256(filePath, strlen(filePath), fileHash);
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "filename", filePath);
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);
    cJSON_AddNumberToObject(jsonObject, "fileSize", fileSize);
    cJSON *chunkArray = cJSON_CreateArray();
    unsigned char buffer[bufferSize];
    while (1)
    {
        size_t bytesRead = fread(buffer, 1, bufferSize, file);
        if (bytesRead == 0)
            break;
        computeSha256(buffer, bytesRead, chunkHash);
        char chunkFilename[maxLen];
        snprintf(chunkFilename, maxLen, "%s/%s", chunkDir, chunkHash);
        FILE *chunkFile = fopen(chunkFilename, "wb");
        fwrite(buffer, 1, bytesRead, chunkFile);
        fclose(chunkFile);
        cJSON_AddItemToArray(chunkArray, cJSON_CreateString(chunkHash));
    }
    fclose(file);
    cJSON_AddItemToObject(jsonObject, "chunkHashes", chunkArray);
    cJSON_AddStringToObject(jsonObject, "fullFileHash", fileHash);
    char *jsonString = cJSON_PrintUnformatted(jsonObject);
    sendto(sock, jsonString, strlen(jsonString), 0, (struct sockaddr *)addr, sizeof(*addr));
    printf("Sent metadata: %s\n", jsonString);
    cJSON_Delete(jsonObject);
    free(jsonString);
}

// Main function to read files from directory and process them
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <port number> <directory path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535)
    {
        fprintf(stderr, "Invalid port number: %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(multicastGroup);
    addr.sin_port = htons(port);
    DIR *dir = opendir(argv[2]);
    if (!dir)
    {
        perror("Error opening directory");
        close(sock);
        return EXIT_FAILURE;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_REG)
        {
            char filePath[maxLen];
            if (snprintf(filePath, maxLen, "%s/%s", argv[2], entry->d_name) >= maxLen)
            {
                fprintf(stderr, "Error: File path too long, skipping %s\n", entry->d_name);
                continue;
            }
            processFile(filePath, sock, &addr);
        }
    }
    closedir(dir);
    close(sock);
    return EXIT_SUCCESS;
}
