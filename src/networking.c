#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./networking.h"
#include "./sha256.h"

#define SALT_FILE "user_salts.txt"

char server_ip[IP_LEN];
char server_port[PORT_LEN];
char my_ip[IP_LEN];
char my_port[PORT_LEN];

int c;

/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    fread(buffer, casc_file_size, 1, fp);
    fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * Combine a password and salt together and hash the result to form the 
 * 'signature'. The result should be written to the 'hash' variable. Note that 
 * as handed out, this function is never called. You will need to decide where 
 * it is sensible to do so.
 */
void get_signature(const char* password, const char* salt, hashdata_t* hash) {
    size_t password_len = strlen(password);
    size_t salt_len = strlen(salt);
    size_t combined_len = password_len + salt_len;

    char* pass_and_salt = malloc(combined_len);
    if (!pass_and_salt) {
        fprintf(stderr, "[Client] Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    memcpy(pass_and_salt, password, password_len);
    memcpy(pass_and_salt + password_len, salt, salt_len);

    SHA256_CTX sha_ctx;
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, pass_and_salt, combined_len);
    sha256_final(&sha_ctx, *hash);

    free(pass_and_salt);
}

/*
 * Register a new user with a server by sending the username and signature to 
 * the server
 */
void register_user(char* username, char* password, char* salt)
{
    int clientfd = compsys_helper_open_clientfd(server_ip, server_port);
    if (clientfd < 0) {
        fprintf(stderr, "Error connecting to server at %s:%s\n", server_ip, server_port);
        return;
    }

    Request_t request = {0};
    strncpy(request.header.username, username, USERNAME_LEN);
    request.header.length = htobe32(0);
    get_signature(password, salt, &request.header.salted_and_hashed);

    ssize_t request_size = sizeof(request.header);
    if (compsys_helper_writen(clientfd, &request, request_size) < 0) {
        perror("Error sending request to server");
        close(clientfd);
        return;
    }

    char response[RESPONSE_HEADER_LEN];
    if (compsys_helper_readn(clientfd, &response, RESPONSE_HEADER_LEN) < 0) {
        fprintf(stderr, "Error reading the response\n");
        close(clientfd);
        return;
    }

    uint32_t status_code = ntohl(*(uint32_t*)&response[4]);

   switch (status_code)
    {
        case 1:
            fprintf(stdout, "Response processed successfully. Status code: %d\n", status_code);
            break;
        case 2:
            fprintf(stderr, "Error status code: %d, User already exists (could not register a user as they are already registered).\n", status_code);
            close(clientfd);
            return;
        case 3:
            fprintf(stderr, "Error status code: %d, User is not registered.\n", status_code);
            close(clientfd);
            return;
        case 4:
            fprintf(stderr, "Error status code: %d, Invalid login (username/signature mismatch).\n", status_code);
            close(clientfd);
            return;
        case 5:
            fprintf(stderr, "Error status code: %d, Bad request (file does not exist).\n", status_code);
            close(clientfd);
            return;
        case 6:
            fprintf(stderr, "Error status code: %d, An unspecified error occurred on the server.\n", status_code);
            close(clientfd);
            return;
        case 7:
            fprintf(stderr, "Error status code: %d, Malformed request (protocol mismatch).\n", status_code);
            close(clientfd);
            return;
    }  

}

/*
 * Get a file from the server by sending the username and signature, along with
 * a file path. Note that this function should be able to deal with both small 
 * and large files. 
 */
void get_file(char* username, char* password, char* salt, char* to_get)
{
    int clientfd = compsys_helper_open_clientfd(server_ip, server_port);

    if (clientfd < 0) {
        fprintf(stderr, "Error connecting to server at %s:%s\n", server_ip, server_port);
        return;
    }

    Request_t request = {0};
    strncpy(request.header.username, username, USERNAME_LEN);
    request.header.length = htobe32(strlen(to_get));
    get_signature(password, salt, &request.header.salted_and_hashed);
    strncpy(request.payload, to_get, PATH_LEN);

    if (compsys_helper_writen(clientfd, &request, (sizeof(request.header) + strlen(request.payload))) < 0) {
        fprintf(stderr, "Error sending request to server\n");
        close(clientfd);
        return;
    }
    

    FILE* pwrite = fopen(to_get, "wb");
    uint32_t block_progress = 0;
    uint32_t block_count = 2;
    Block_t* blocks = NULL;


    while (block_progress < block_count) {
        block_progress++;
        char response[RESPONSE_HEADER_LEN];
        if (compsys_helper_readn(clientfd, response, RESPONSE_HEADER_LEN) <= 0) {
            fprintf(stderr, "Error reading response header\n");
            break;
        }

        uint32_t response_length = ntohl(*(uint32_t*)&response[0]);
        uint32_t status_code = ntohl(*(uint32_t*)&response[4]);
        uint32_t block_number = ntohl(*(uint32_t*)&response[8]);
        block_count = ntohl(*(uint32_t*)&response[12]);
        uint8_t* block_hash = (uint8_t*)&response[16];
        // uint8_t* total_hash = (uint8_t*)&response[48];

        if (blocks == NULL) {
            blocks = calloc(block_count, sizeof(Block_t));
        }

        switch (status_code)
        {
            case 1:
                fprintf(stdout, "Response processed successfully. Status code: %d\n", status_code);
                break;
            case 2:
                fprintf(stderr, "Error status code: %d, User already exists (could not register a user as they are already registered).\n", status_code);
                close(clientfd);
                return;
            case 3:
                fprintf(stderr, "Error status code: %d, User is not registered.\n", status_code);
                close(clientfd);
                return;
            case 4:
                fprintf(stderr, "Error status code: %d, Invalid login (username/signature mismatch).\n", status_code);
                close(clientfd);
                return;
            case 5:
                fprintf(stderr, "Error status code: %d, Bad request (file does not exist).\n", status_code);
                close(clientfd);
                return;
            case 6:
                fprintf(stderr, "Error status code: %d, An unspecified error occurred on the server.\n", status_code);
                close(clientfd);
                return;
            case 7:
                fprintf(stderr, "Error status code: %d, Malformed request (protocol mismatch).\n", status_code);
                close(clientfd);
                return;
        }
        
        char *payload = malloc(response_length);
        if (compsys_helper_readn(clientfd, payload, response_length) <= 0) {
            fprintf(stderr, "Error reading the response\n");
            free(payload);
            return;
        }

        // Now we validate the payload with the the block hash.
        hashdata_t hashed_payload = {0};
        get_data_sha(payload, hashed_payload, response_length, SHA256_HASH_SIZE);

        if(memcmp(hashed_payload, block_hash, SHA256_HASH_SIZE) != 0) {
            fprintf(stderr, "Payload not valid.\n");
            close(clientfd);
            free(payload);
            return;
        }

        blocks[block_number].block_length = response_length;
        blocks[block_number].block_number = block_number;
        blocks[block_number].payload = payload;
    }

    for (uint32_t i = 0; i < block_count; i++) {
        printf("Processing block %u out of %u\n", blocks[i].block_number + 1, block_count);
        if (fwrite(blocks[i].payload, 1, blocks[i].block_length, pwrite) != blocks[i].block_length) {
            fprintf(stderr, "Error when writing block to file");
            free(blocks[i].payload);
            break;
        }
    }
    fclose(pwrite);
    close(clientfd);
    
}
int get_user_salt(char* username, char* salt) {
    FILE* file = fopen(SALT_FILE, "r"); 
    if (file == NULL) {
        printf("Error opening salt file: %s\n", SALT_FILE);
        return 1;
    }
    char line[USERNAME_LEN+SALT_LEN+1];
    while (fgets(line, sizeof(line), file)) {
        // Split the line by ':' to separate the username and salt
        char* file_username = strtok(line, ":");
        char* file_salt = strtok(NULL, "\n");

        if (file_username != NULL && file_salt != NULL && strcmp(file_username, username) == 0) {
            strncpy(salt, file_salt, SALT_LEN);
            salt[SALT_LEN] = '\0'; 
            fclose(file);
            return 0;
        }
    }
    return 1;
}

void save_user_salt(char* username, char* salt) {
    FILE* file = fopen(SALT_FILE, "a"); 
    if (file == NULL) {
        printf("Error opening salt file");
        return;
    }

    fprintf(file, "%s:%s\n", username, salt);
    fclose(file);
}

void generate_random_salt(char* user_salt) {
    srand(time(NULL));
    for (int i = 0; i < SALT_LEN; i++) {
        user_salt[i] = 'a' + (rand() % 26);
    }
    user_salt[SALT_LEN] = '\0'; 
}

void display_menu() {
    printf("-------------------\n");
    printf("1. Register a new user\n");
    printf("2. Retrieve a file \n");
    printf("3. Exit \n");
    printf("--------------------\n");
    printf("Enter your choice: ");
}

void handle_user_registration() {
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    char user_salt[SALT_LEN+1];
    fprintf(stdout, "Enter a username to proceed: ");
    scanf("%16s", username);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up username string as otherwise some extra chars can sneak in.
    for (int i=strlen(username); i<USERNAME_LEN; i++)
    {
        username[i] = '\0';
    }
    
    fprintf(stdout, "Enter your password to proceed: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }
    generate_random_salt(user_salt);
    save_user_salt(username, user_salt);
    fprintf(stdout, "Using salt: %s\n", user_salt);
    register_user(username, password, user_salt);
}


void handle_get_file() {
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    char user_salt[SALT_LEN+1];
    char filepath[PATH_LEN];
    fprintf(stdout, "Enter a username to proceed: ");
    scanf("%16s", username);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up username string as otherwise some extra chars can sneak in.
    for (int i=strlen(username); i<USERNAME_LEN; i++)
    {
        username[i] = '\0';
    }

    fprintf(stdout, "Enter your password to proceed: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    if (get_user_salt(username, user_salt) == 0) {
        printf("Found existing salt: %s\n", user_salt);
    } else {
        fprintf(stdout, "User must be registered to request files\n");
        return;
    }
    fprintf(stdout, "Enter a filepath to request: ");
    scanf("%128s", filepath);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up username string as otherwise some extra chars can sneak in.
    for (int i=strlen(filepath); i<PATH_LEN; i++)
    {
        filepath[i] = '\0';
    }
    get_file(username, password, user_salt, filepath);
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    // Read in configuration options. Should include a client_directory, 
    // client_ip, client_port, server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, CLIENT_IP)) {
            memcpy(my_ip, &buffer[strlen(CLIENT_IP)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_IP));
            if (!is_valid_ip(my_ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, CLIENT_PORT)) {
            memcpy(my_port, &buffer[strlen(CLIENT_PORT)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_PORT));
            if (!is_valid_port(my_port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", my_port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_IP)) {
            memcpy(server_ip, &buffer[strlen(SERVER_IP)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_IP));
            if (!is_valid_ip(server_ip)) {
                fprintf(stderr, ">> Invalid server IP: %s\n", server_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_PORT)) {
            memcpy(server_port, &buffer[strlen(SERVER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_PORT));
            if (!is_valid_port(server_port)) {
                fprintf(stderr, ">> Invalid server port: %s\n", server_port);
                exit(EXIT_FAILURE);
            }
        }        
    }
    fclose(fp);

    fprintf(stdout, "Client at: %s:%s\n", my_ip, my_port);
    fprintf(stdout, "Server at: %s:%s\n", server_ip, server_port);

    int choice;
    while(1) {
        display_menu();
        if(scanf("%d", &choice) != 1) {
            printf("Invalid input, please enter a value between 1 and 3.\n");
            while(getchar() != '\n');
            continue;
        }
        getchar();
        switch(choice)
        {
            case 1:
                handle_user_registration();
                break;
            case 2:
                handle_get_file();
                break;
            case 3:
                printf("Exiting program.\n");
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "Invalid choice. Please enter a number between 1 and 3.\n");
        }
    }
    exit(EXIT_SUCCESS);
}