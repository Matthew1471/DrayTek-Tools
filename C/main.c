/* 
 * This file is part of DrayTek-Tools <https://github.com/Matthew1471/DrayTek-Tools>
 * Copyright (c) 2024 Matthew1471!
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
 
// Adapted from https://gist.github.com/sgarwood/c60883ad2921893d1e9def4bd22b0728

#include <assert.h>        // For the assert functionality.
#include <arpa/inet.h>     // For inet_* functions.
#include <errno.h>         // For standard error numbers.
#include <netinet/ether.h> // For ether_* functions.
#include <openssl/sha.h>   // "apt-get install libssl-dev" if missing.
#include <stdio.h>         // For printf() and fprintf().
#include <string.h>        // For memset().
#include <stdlib.h>        // For exit().
#include <unistd.h>        // For close() function

#include "lib/tiny-AES-c/aes.h" // For the AES decryption.

#define DEBUG 0               // Whether to print debugging information.
#define TRUE 1                // Define TRUE.
#define MAX_BYTES_LENGTH 116  // Longest string to receive.

// Define the DslType enumeration.
enum DslType {
    ADSL = 1,
    VDSL = 6
};

// Define the DslStatus structure.
struct DslStatus {
    unsigned char protocol_identifier[4]; // 0
    int32_t dsl_upload_speed;             // 4
    int32_t dsl_download_speed;           // 8
    int32_t adsl_tx_cells;                // 12
    int32_t adsl_rx_cells;                // 16
    int32_t adsl_tx_crc_errors;           // 20
    int32_t adsl_rx_crc_errors;           // 24
    DslType dsl_type;                     // 28
    int32_t timestamp;                    // 32
    int32_t vdsl_snr_upload;              // 36
    int32_t vdsl_snr_download;            // 40
    int32_t adsl_loop_att;                // 44
    int32_t adsl_snr_margin;              // 48
    char modem_firmware_version[20];      // 52
    char running_mode[18];                // 72 VDSL Profile or ADSL mode
    char state[26];                       // 90
    // 116 Total Bytes
};

// Function to convert enum DslType to string.
const char* dsl_type_to_string(enum DslType dsl_type) {
    switch (dsl_type) {
        case ADSL:
            return "ADSL";
        case VDSL:
            return "VDSL";
        default:
            return "Unknown";
    }
}

// Function to optionally output the MAC address and decryption key.
void print_debug_info(const struct ether_addr *mac_address, const uint8_t *key, size_t key_length) {
    printf("MAC Address: %02X%02X%02X%02X%02X%02X\n",
       mac_address->ether_addr_octet[0],
       mac_address->ether_addr_octet[1],
       mac_address->ether_addr_octet[2],
       mac_address->ether_addr_octet[3],
       mac_address->ether_addr_octet[4],
       mac_address->ether_addr_octet[5]);

    printf("Key/IV: %s\n", key);
    for (int count = 0; count < key_length; count++) {
        printf(" Key #%d = %c = %02X\n", count, key[count], key[count]);
    }
    printf("\n");
}

void print_dsl_status(DslType dsl_type, const struct DslStatus* dsl_status_data) {
    printf("\n");
    if (DEBUG) {
        printf(" DSL Status Protocol Identifier: 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
                dsl_status_data->protocol_identifier[0],
                dsl_status_data->protocol_identifier[1],
                dsl_status_data->protocol_identifier[2],
                dsl_status_data->protocol_identifier[3]
        );
    }
    printf(" DSL Upload Speed: %d bps", (int32_t)ntohl(dsl_status_data->dsl_upload_speed));
    printf(" (%d Mbps)\n", (int32_t)ntohl(dsl_status_data->dsl_upload_speed) / 1000000);
    printf(" DSL Download Speed: %d bps", (int32_t)ntohl(dsl_status_data->dsl_download_speed));
    printf(" (%d Mbps)\n", (int32_t)ntohl(dsl_status_data->dsl_download_speed) / 1000000);

    if (DEBUG || dsl_type == ADSL) {
        printf(" ADSL TX Cells: %d\n", (int32_t)ntohl(dsl_status_data->adsl_tx_cells));
        printf(" ADSL RX Cells: %d\n", (int32_t)ntohl(dsl_status_data->adsl_rx_cells));
        printf(" ADSL TX CRC Errors: %d\n", (int32_t)ntohl(dsl_status_data->adsl_tx_crc_errors));
        printf(" ADSL RX CRC Errors: %d\n", (int32_t)ntohl(dsl_status_data->adsl_rx_crc_errors));
    }

    printf(" DSL Type: %s\n", dsl_type_to_string(dsl_type));
    printf(" Timestamp: %d\n", (int32_t)ntohl(dsl_status_data->timestamp));

    if (DEBUG || dsl_type == VDSL) {
        printf(" VDSL SNR Upload: %d\n", (int32_t)ntohl(dsl_status_data->vdsl_snr_upload));
        printf(" VDSL SNR Download: %d\n", (int32_t)ntohl(dsl_status_data->vdsl_snr_download));
    }

    if (DEBUG || dsl_type == ADSL) {
        printf(" ADSL Loop Attenuation: %d\n", (int32_t)ntohl(dsl_status_data->adsl_loop_att));
        printf(" ADSL SNR Margin: %d\n", (int32_t)ntohl(dsl_status_data->adsl_snr_margin));
    }

    printf(" Modem Firmware Version: %.*s\n", 20, dsl_status_data->modem_firmware_version);
    printf(" Running Mode: %.*s\n", 18, dsl_status_data->running_mode);
    printf(" State: %.*s\n\n", 26, dsl_status_data->state);    
}

// Decrypts DSL Status broadcast bytes into the DslStatus structure.
int decrypt_dsl_status(
        const struct ether_addr *mac_address,
        uint8_t *encrypted_buffer,
        struct DslStatus *dsl_status) {
    // The protocol identifies itself with these bytes.
    const unsigned char signature_bytes[4] = {0x20, 0x52, 0x05, 0x20};

    // Check the payload is a DSL Status message.
    if (memcmp((unsigned char *) encrypted_buffer, signature_bytes, 4) != 0) {
        fprintf(stderr, "Error: Incorrect protocol signature bytes.\n");
        return -EPROTO;
    }

    // The encryption key is the first 5 bytes from the SHA-1 digest.
    uint8_t message_digest[SHA_DIGEST_LENGTH];
    SHA1((uint8_t *) mac_address, ETH_ALEN, message_digest);

    // Create a 17 byte array and set all positions to null (we will populate only 10 bytes).
    uint8_t key[17];
    memset(key, 0x0, 17);

    // Get the uppercase hexadecimal characters of the digest (10 characters).
    int current_digest_byte = 0;
    for (int current_key_position = 0; current_key_position < 10; current_key_position += 2) {
        // Fill 2 positions of the key with the 2 hex characters from a single digest byte.
        // We will do this for only 10 bytes in the key, the 6 remaining bytes remain null.
        sprintf((char *) &key[current_key_position], "%02X", message_digest[current_digest_byte]);
        current_digest_byte++;
    }

    // Debugging.
    if (DEBUG) {
        print_debug_info(mac_address, key, sizeof(key) / sizeof(key[0]));
    }

    // Copy the encrypted_buffer to the dsl_status prior to decryption.
    memcpy(dsl_status, encrypted_buffer, 116);

    // Initialise the AES decrypter (the iv/key has to be 16 bytes for AES128).
    struct AES_ctx aesCtx;
    AES_init_ctx_iv(&aesCtx, key, key);

    // Decrypt the payload (skipping the first 4 signature bytes).
    AES_CBC_decrypt_buffer(&aesCtx, ((uint8_t *) dsl_status) + sizeof(signature_bytes), 112);

    return TRUE;
}

void receive_data(char *mac_address_string) {
    // Create an IPv4 datagram socket using UDP.
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Permit multiple receiver threads listening.
    int opt = TRUE;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "setsockopt() failed: %s\n", strerror(errno));
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Construct bind structure.
    struct sockaddr_in broadcast_address;
    memset(&broadcast_address, 0, sizeof(broadcast_address)); // Zero out structure.
    broadcast_address.sin_family = AF_INET;                   // Internet address family.
    broadcast_address.sin_addr.s_addr = htonl(INADDR_ANY);    // Any incoming interface.
    broadcast_address.sin_port = htons(4944);                 // Broadcast port.

    // Bind to the broadcast port.
    if (bind(sock, (struct sockaddr *) &broadcast_address, sizeof(broadcast_address)) < 0) {
        fprintf(stderr, "bind() failed: %s\n", strerror(errno));
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Get the MAC address string in bytes.
    struct ether_addr mac_address;
    if (ether_aton_r(mac_address_string, &mac_address) == NULL) {
        fprintf(stderr, "Error: Invalid MAC address format.\n");
        exit(EXIT_FAILURE);
    }

    // Now listening for messages until the program is exited.
    while (TRUE) {
        fd_set socket_fd_set;
        FD_ZERO(&socket_fd_set);
        FD_SET(sock, &socket_fd_set);

        // Buffer for received string.
        unsigned char received_data[MAX_BYTES_LENGTH + 1];

        // Is a socket ready for reading?
        if (select(sock + 1, &socket_fd_set, NULL, NULL, 0) > 0) {
            if (FD_ISSET(sock, &socket_fd_set)) {
                // The client address.
                struct sockaddr_in client_address;
                socklen_t address_length = sizeof(client_address);

                // Attempt to receive a broadcast packet.
                size_t received_data_length = recvfrom(
                        sock,
                        received_data,
                        MAX_BYTES_LENGTH,
                        0,
                        (struct sockaddr *) &client_address,
                        &address_length
                );

                // Check to see if this would be the right length for a DSL Status message.
                if (received_data_length != 116) {
                    // Wait for another message as this is not a DSL Status message.
                    continue;
                }

                // Notify user a message has been received.
                printf(
                        "Received UDP Datagram from %s of correct size; using MAC Address %s to decrypt contents:\n",
                        inet_ntoa(client_address.sin_addr),
                        ether_ntoa(&mac_address)
                );

                // Perform the decryption.
                struct DslStatus dsl_status_data;
                if (decrypt_dsl_status(&mac_address, received_data, &dsl_status_data)) {

                    // printf("Size of DSL Status Data: %lu\n", sizeof(dsl_status_data));
                    assert(sizeof(dsl_status_data) == 116);
                    
                    // Convert the dsl_type byte to a DslType enum.
                    DslType dsl_type = (DslType)ntohl(dsl_status_data.dsl_type);
                    
                    // Check the DSL type is valid.
                    if (dsl_type != ADSL && dsl_type != VDSL) {
                        // Notify the user the decrypted payload failed validation.
                        printf(" * Message failed DSL Type validation, check decryption key.\n\n");
                        
                        // Wait for another message as this is not a valid DSL Status message.
                        continue;
                    }

                    // Output to console.
                    print_dsl_status(dsl_type, &dsl_status_data);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    // Check whether the user has supplied a source MAC address.
    if (argc != 2) {
        printf("Usage:\n");
        printf(" %s <MAC Address of Vigor™ DSL Modem>\n\n", argv[0]);
        printf("e.g. %s aa:bb:cc:dd:ee:ff\n", argv[0]);
        return -EINVAL;
    }

    // Start listening for data.
    receive_data(argv[1]);
}
