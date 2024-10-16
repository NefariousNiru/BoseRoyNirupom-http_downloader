#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <arpa/inet.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <unistd.h>  
#include <openssl/md5.h>
#include <openssl/evp.h>


// Define structure of a URL 
typedef struct {
    char scheme[10]; 
    char domain[256]; 
    char path[1024];
} URL;


// Define structure for CLI Arguments
typedef struct {
    URL target_url;
    char *output_file_name;
    int download_parts;
} Arguments;


// Define Byte Range for parts 
typedef struct {
    long start;
    long end;  
} ByteRange;


// Define Download Arguments
typedef struct {
    SSL_CTX *ssl_ctx;
    char ip_address[INET6_ADDRSTRLEN];
    URL url;
    ByteRange range;
    int part_number;
    int address_family;
} DownloadArguments;


// This function wraps the TCP Connection Socket with SSL/TLS and perform SSL handshake 
SSL *wrap_tcp_socket(SSL_CTX *ssl_ctx, int sock, const char *hostname) {
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);

    // Set the TLS SNI hostname (Server Name Indication)
    if (!SSL_set_tlsext_host_name(ssl, hostname)) {
        fprintf(stderr, "Error: Failed to set SNI hostname.\n");
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) { 
        fprintf(stderr, "SSL handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        exit(EXIT_FAILURE);
    }

    return ssl;
}


// This function opens a socket and establishes a TCP Connection 
int open_TCP_socket(const char *ip_address, int port, int address_family) {
    int sock;
    struct sockaddr_in server_address_ipv4;
    struct sockaddr_in6 server_address_ipv6;

    // Create a TCP Socket (specified by SOCK_STREAM and 0)
    // For UDP use (SOCK_DGRAM)
    sock = socket(address_family, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Error: Socket Creation was unsuccessful!");
        exit(EXIT_FAILURE);
    }

    // Set up server address based on IPv4 or IPv6
    if (address_family == AF_INET) {
        server_address_ipv4.sin_family = AF_INET;
        server_address_ipv4.sin_port = htons(port);
        inet_pton(AF_INET, ip_address, &server_address_ipv4.sin_addr);

        // Connect using IPv4
        if (connect(sock, (struct sockaddr *)&server_address_ipv4, sizeof(server_address_ipv4)) < 0) {
            perror("Error: TCP connection (IPv4) failed");
            close(sock);
            exit(EXIT_FAILURE);
        }

    } else if (address_family == AF_INET6) {
        server_address_ipv6.sin6_family = AF_INET6;
        server_address_ipv6.sin6_port = htons(port);
        inet_pton(AF_INET6, ip_address, &server_address_ipv6.sin6_addr);

        // Connect using IPv6
        if (connect(sock, (struct sockaddr *)&server_address_ipv6, sizeof(server_address_ipv6)) < 0) {
            perror("Error: TCP connection (IPv6) failed");
            close(sock);
            exit(EXIT_FAILURE);
        }
    }

    return sock;
}


// Function to calculate the MD5 hash of a given file using EVP
void calculate_md5_checksum(const char *filename, unsigned char *result) {
    // Open the output file
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for MD5 calculation.\n", filename);
        return;
    }

    // Initialize the MD5 context using EVP
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        fprintf(stderr, "Error: Could not create EVP_MD_CTX.\n");
        fclose(file);
        return;
    }

    // Initialize the digest
    const EVP_MD *md = EVP_md5();
    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
        fprintf(stderr, "Error: Could not initialize MD5 digest.\n");
        EVP_MD_CTX_free(md_ctx);
        fclose(file);
        return;
    }

    // Read file data and update MD5 context
    char buffer[4096];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(md_ctx, buffer, bytes_read) != 1) {
            fprintf(stderr, "Error: Could not update MD5 digest.\n");
            EVP_MD_CTX_free(md_ctx);
            fclose(file);
            return;
        }
    }

    // Finalize the MD5 calculation and retrieve the result
    unsigned int length_of_hash = 0;
    if (EVP_DigestFinal_ex(md_ctx, result, &length_of_hash) != 1) {
        fprintf(stderr, "Error: Could not finalize MD5 digest.\n");
    }

    EVP_MD_CTX_free(md_ctx);
    fclose(file);
}


// Function to combine all downloaded parts into the final output file
void combine_downloaded_parts(const char *output_file, int num_parts) {
    // Create output file
    FILE *output = fopen(output_file, "wb");
    if (!output) {
        fprintf(stderr, "Error: Could not open file %s for writing.\n", output_file);
        return;
    }

    // Write to output file
    char filename[50];
    char buffer[4096];
    int bytes_read;
    for (int i = 1; i <= num_parts; i++) {
        snprintf(filename, sizeof(filename), "part_%d", i);
        FILE *part_file = fopen(filename, "rb");
        if (!part_file) {
            fprintf(stderr, "Error: Could not open part file %s.\n", filename);
            fclose(output);
            return;
        }

        // Read from part file and write to the output file
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), part_file)) > 0) {
            fwrite(buffer, 1, bytes_read, output);
        }

        fclose(part_file);
        printf("Part %d combined successfully.\n", i);
    }

    fclose(output);
    printf("All parts combined into %s successfully.\n", output_file);
}


// Thread function to download a byte range of file
void *download_part(void *arg) {
    DownloadArguments *args = (DownloadArguments *)arg;
    int sock = open_TCP_socket(args->ip_address, 443, args->address_family);
    SSL *ssl = wrap_tcp_socket(args->ssl_ctx, sock, args->url.domain);

    // Construct the HTTP GET request with Range header
    char request[2048];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36\r\n"
             "Range: bytes=%ld-%ld\r\n"
             "Connection: close\r\n\r\n",
             args->url.path, args->url.domain, args->range.start, args->range.end);

    // Send the GET request
    if (SSL_write(ssl, request, strlen(request)) <= 0) {
        fprintf(stderr, "Error: Failed to send GET request for part %d.\n", args->part_number);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    // Open file to save the part
    char filename[50];
    snprintf(filename, sizeof(filename), "part_%d", args->part_number);
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for writing.\n", filename);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    // Read the response and skip HTTP headers
    char buffer[4096];
    int bytes_received;
    int headers_parsed = 0;
    while ((bytes_received = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        // Check if headers have been parsed
        if (!headers_parsed) {
            char *header_end = strstr(buffer, "\r\n\r\n");
            if (header_end) {
                headers_parsed = 1;
                // Move the pointer to the end of headers + 4 bytes for \r\n\r\n
                char *data_start = header_end + 4;
                fwrite(data_start, 1, bytes_received - (data_start - buffer), file);
            }
        } else {
            // Write the image data to the file
            fwrite(buffer, 1, bytes_received, file);
        }
    }

    printf("Part %d downloaded and saved to %s\n", args->part_number, filename);

    fclose(file);
    SSL_free(ssl);
    close(sock);
    return NULL;
}


// This function sets byte range for each part
void set_byte_range(ByteRange *ranges, int num_parts, long file_size) {
    long part_size = file_size / num_parts;  // Divide file_size into equal parts
    long remainder = file_size % num_parts;  // Get remaining bytes

    // Assign the start and end for each part (byte ranges for every part)
    for (int i = 0; i < num_parts; i++) {
        ranges[i].start = i * part_size;
        ranges[i].end = (i + 1) * part_size - 1;
    }

    // Add remaining bytes to the last part
    ranges[num_parts - 1].end += remainder;  
}


// Function to print calculated byte ranges
void print_byte_range(ByteRange *ranges, int num_parts) {
    for (int i = 0; i < num_parts; i++) {
        printf("Part %d: Start = %ld, End = %ld\n", i + 1, ranges[i].start, ranges[i].end);
    }
}


// Function to get the file size from the server before downloading using the SSL wrapped TCP Connection and URL
long get_file_size(SSL *ssl, URL url) {
    char request[2048];
    char response[4096];
    
    // Construct the HTTP HEAD request
    snprintf(request, sizeof(request),
             "HEAD %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36\r\n"
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
             "Accept-Encoding: gzip, deflate, br\r\n"
             "Connection: close\r\n\r\n", url.path, url.domain);

    printf("\nHTTP Request:\n%s", request);

    // Send the HTTP HEAD request
    if (SSL_write(ssl, request, strlen(request)) <= 0) {
        fprintf(stderr, "Error: Failed to send HEAD request.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Read the response from the server
    int bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
    if (bytes_received <= 0) {
        fprintf(stderr, "Error: Failed to read response from server.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Null-terminate the response string
    response[bytes_received] = '\0';
    printf("HTTP Response:\n%s", response);

    // "Content-Length" header in the response tells size 
    char *content_length_str = strstr(response, "Content-Length:");
    if (content_length_str) {
        long content_length;
        sscanf(content_length_str, "Content-Length: %ld", &content_length);
        return content_length;
    } else {
        fprintf(stderr, "Error: Content-Length header not found in response.\n");
        return -1;
    }
}


// Resolve a domain name to an IP address
void resolve_domain(const char *domain, char *ip_address, int *address_family) {
    struct addrinfo hints, *res;         // For specifying criteria and storing result
    int status;                          // To store the status of getaddrinfo
    char ip_string[INET6_ADDRSTRLEN];    // Buffer for storing the IP address as a string

    memset(&hints, 0, sizeof(hints));     // Zero out the hints structure
    hints.ai_family = AF_UNSPEC;          // Use AF_UNSPEC to allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;      // Specify TCP stream sockets

    // Get the address information of the domain
    if ((status = getaddrinfo(domain, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE); 
    }

    void *addr;                           // To store the resolved IP address
    
    // Check if the result is IPv4 or IPv6
    *address_family = res->ai_family;
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *) res->ai_addr;   // Cast to IPv4
        addr = &(ipv4->sin_addr);         // Get the IPv4 address
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) res->ai_addr; // Cast to IPv6
        addr = &(ipv6->sin6_addr);        // Get the IPv6 address
    }

    // Convert the IP address to a string
    inet_ntop(res->ai_family, addr, ip_string, sizeof(ip_string));
    strcpy(ip_address, ip_string);

    freeaddrinfo(res);
}


// This function initializes the SSL Library and returns a SSL context 
SSL_CTX *ssl_init() {
    SSL_library_init();                                 // Initialize the library 
    SSL_load_error_strings();                           // Load error strings for reporting
    OpenSSL_add_all_algorithms();                       // Add all digests and ciphers

    const SSL_METHOD *tls_method = TLS_client_method(); // Create a TLS method
    SSL_CTX *ssl_ctx = SSL_CTX_new(tls_method);         // Create a SSL Context with TLS

    if (!ssl_ctx) {
        fprintf(stderr, "Unable to create SSL Context \n");
        ERR_print_errors_fp(stderr); 
        exit(EXIT_FAILURE);
    }

    return ssl_ctx;
}


// This function parses a URL into its components and stores it as struct URL
URL parse_url(const char *url) {
    URL parsed_url = {0};
    const char *scheme_end = strstr(url, "://");

    // The scheme ends with '://'
    if (scheme_end) {
        size_t scheme_length = scheme_end - url;
        if (scheme_length < sizeof(parsed_url.scheme)) {
            strncpy(parsed_url.scheme, url, scheme_length);
            parsed_url.scheme[scheme_length] = '\0';
        } else {
            fprintf(stderr, "Scheme length exceeds buffer size\n");
            exit(EXIT_FAILURE);
        }
        url = scheme_end + 3;
    } else {
        fprintf(stderr, "Invalid URL format: missing scheme\n");
        exit(EXIT_FAILURE);
    }


    // The domain starts after scheme and ends with '/'
    const char *path_start = strchr(url, '/');
    if (path_start) {
        size_t domain_length = path_start - url;
        if (domain_length < sizeof(parsed_url.domain)) {
            strncpy(parsed_url.domain, url, domain_length);
            parsed_url.domain[domain_length] = '\0';
        } else {
            fprintf(stderr, "Domain length exceeds buffer size\n");
            exit(EXIT_FAILURE);
        }
        strncpy(parsed_url.path, path_start, sizeof(parsed_url.path) - 1);
    } else {
        strncpy(parsed_url.domain, url, sizeof(parsed_url.domain) - 1); // If no path is found, copy the remaining string as the domain
        parsed_url.path[0] = '/';                                       // Default path to "/"
    }

    return parsed_url;
}


//  This function throws an error when argument list encounters any errors (incomplete, invalid etc..) and exits with status code 1
void throw_invalid_option_error(char *argv[]) {
    fprintf(stderr, "\033[31mUsage: %s -u URL -o OUTPUT_PATH -n DOWNLOAD_PARTS\n\033[0m", argv[0]);
    exit(EXIT_FAILURE);
}


// This function uses getopt to parse the command line arguments
Arguments parse_argument(int argc, char *argv[]){
    int opt;
    char *target_url = NULL;
    char *output_file_name = NULL;
    int download_parts = 0;
    Arguments args = {{{0}}, NULL, 0};

    if (argc < 7) { // Minimum required arguments count
        throw_invalid_option_error(argv);
    }

    while ((opt = getopt(argc, argv, "u:o:n:")) != -1) {
        switch(opt) {
            case 'u':
                target_url = strdup(optarg);;
                break;
            case 'o':
                output_file_name = strdup(optarg);
                break;
            case 'n':
                download_parts = atoi(optarg);
                break;
            default:
                throw_invalid_option_error(argv);
        }
    }

    if (!target_url || !output_file_name || download_parts <= 0) {
        throw_invalid_option_error(argv);
    }
    
    args.target_url = parse_url(target_url);
    args.output_file_name = output_file_name;
    args.download_parts = download_parts;

    free(target_url); 
    return args;
}


int main(int argc, char *argv[]) {
    // Parse Arguments and store to struct args
    Arguments args = parse_argument(argc, argv);
    printf("\nScheme: %s \nDomain: %s \nPath: %s\n", args.target_url.scheme, args.target_url.domain, args.target_url.path);
    printf("Number of Parts: %d\n", args.download_parts);
    printf("Output File Path: %s\n", args.output_file_name);

    // Get the domain ip_address by resolving it
    char ip_address[INET6_ADDRSTRLEN];
    int address_family;
    resolve_domain(args.target_url.domain, ip_address, &address_family);
    printf("\nResolved IP address: %s\n", ip_address);

    // Open a socket for a tcp connection
    int port = 443;
    int sock = open_TCP_socket(ip_address, port, address_family);
    printf("Success: Connected to server at %s:%d\n", ip_address, port);

    // Initialise SSL and store it in ssl_context
    SSL_CTX *ssl_ctx = ssl_init();

    // Wrap TCP socket with SSL/TLS and establish secure connection (handshake)
    SSL *ssl = wrap_tcp_socket(ssl_ctx, sock, args.target_url.domain);
    printf("SSL handshake successful\n");

    // Get the file size from server
    long file_size = get_file_size(ssl, args.target_url);
    if (file_size == -1) {
        fprintf(stderr, "\nFailed to get file size.");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ssl_ctx);
        free(args.output_file_name);
        return EXIT_FAILURE;
    }
    printf("File Size: %ld bytes", file_size);

    // Get byte ranges for multi-threaded download
    ByteRange ranges[args.download_parts];
    set_byte_range(ranges, args.download_parts, file_size);
    printf("\nChunking Bytes into %i Parts.\n", args.download_parts);
    print_byte_range(ranges, args.download_parts);
    printf("\nStarting Download... \n");

    // Start threads for each part
    pthread_t threads[args.download_parts];
    DownloadArguments download_args[args.download_parts];
    for (int i = 0; i < args.download_parts; i++) {
        download_args[i].ssl_ctx = ssl_ctx;
        strncpy(download_args[i].ip_address, ip_address, INET6_ADDRSTRLEN);
        download_args[i].url = args.target_url;
        download_args[i].range = ranges[i];
        download_args[i].part_number = i + 1;
        download_args[i].address_family = address_family; 

        pthread_create(&threads[i], NULL, download_part, &download_args[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < args.download_parts; i++) {
        pthread_join(threads[i], NULL);
    }

    // Combine all the parts
    printf("\nAll parts downloaded succesfully! Combining now...\n");
    combine_downloaded_parts(args.output_file_name, args.download_parts);

    // Generate MD5 hash and print the MD5 hash in Base 16
    unsigned char md5_result[MD5_DIGEST_LENGTH];
    calculate_md5_checksum(args.output_file_name, md5_result);
    printf("\nMD5 Hash of %s: ", args.output_file_name);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", md5_result[i]);
    }
    printf("\n");

    // Free after use
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ssl_ctx);
    free(args.output_file_name);
    return 0;
}