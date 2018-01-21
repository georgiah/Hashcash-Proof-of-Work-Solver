/* A simple server in the internet domain using TCP
The desired port number is passed as a command line argument

To compile: gcc server.c -o server
To run: ./server PORTNUMBER, eg. ./server 12345
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include "uint256.h"
#include "sha256.h"

#define INVALID "ERRO\tinvalid sequence of messages"
#define ERROR "ERRO\tserver does not handle ERRO messages"
#define UNKNOWN "ERRO\tunknown header received: "
#define DELIMITER "\r\n"

#define SOLN_MESSAGE_LENGTH 95 + strlen(DELIMITER)
#define WORK_MESSAGE_LENGTH 98 + strlen(DELIMITER)

#define SERVERIP "0.0.0.0"

/* Passes parameters to the threads */
struct thread_params {
    int socketfd;
    struct sockaddr_in *client_address;
    char buffer_input[256];
};

/* Stores information to print to log file */
struct log_text {
    char *timestamp;
    char *ip_address;
    char *fd;
    char *message;
};

/* Maintains hashcash queue info */
struct hashcash {
    BYTE seed[32];
    BYTE nonce[8];
    BYTE target[32];
    int solved;
    int sockfd;
    struct hashcash *next;
};

struct hashcash *hashcash_queue = NULL;

sem_t sem;
sem_t queue;
int kill_switch;
int num_clients = 0;

BYTE pong_reserved[40]   = "   PONG reserved for server responses\r\n";
BYTE invalid[40]         = "         invalid sequence of messages\r\n";
BYTE error[40]           = " server does not handle ERRO messages\r\n";
BYTE unknown[40]         = "        unknown header received: ";
BYTE solution_error[40]  = "                 not a valid solution\r\n";
BYTE length_error[40]    = "           message has invalid length\r\n";
BYTE delimiter_error[40] = "  message did not conform to protocol\r\n";

BYTE server_res[7] = "PONG\r\n";
BYTE error_res[5]  = "ERRO";

/* Prints information to log file and to stdout */
void print_to_log(struct log_text *input) {
    FILE *log;
    log = fopen("log.txt", "a");
    fprintf(log, input->timestamp);
    fprintf(log, input->ip_address);
    fprintf(log, input->fd);
    fprintf(log, input->message);

    printf("%s%s%s", input->timestamp, input->ip_address, input->fd);
    printf("%s", input->message);

/* If end of log message, print horizontal separator */
    if(strcmp(input->ip_address, SERVERIP) == 0) {
        fprintf(log, "--------------------------------------------------\n");
        printf("--------------------------------------------------\n");
    } else {
        fprintf(log, "\n");
        printf("\n");
    }
    fclose(log);
}

/* Constructs information to be printed to log */
void construct_log_input(struct log_text *log_info, char *time, char *ip,
  char *socket, char *message) {
    log_info->timestamp = time;
    log_info->ip_address = ip;
    log_info->fd = socket;
    log_info->message = message;
}

/* Handles simple messages depending on their header.
   Desired behaviour:
   PING -> PONG
   PONG -> PONG reserved for server responses
   OKAY -> ERROR invalid sequence of messages
   ERRO -> server does not handle ERRO messages
   XXXX -> ERROR unknown header received: XXXX
*/
void simple_header_handler(char *header, char *res) {
	if (strcmp(header, "PING") == 0) {
		strncpy(res, server_res, sizeof(server_res));
	} else if (strcmp(header, "PONG") == 0) {
		strncpy(res, error_res, sizeof(error_res));
		strncat(res, pong_reserved, sizeof(pong_reserved));
	} else if (strcmp(header, "OKAY") == 0) {
		strncpy(res, error_res, sizeof(error_res));
		strncat(res, invalid, sizeof(invalid));
	} else if (strcmp(header, "ERRO") == 0) {
		strncpy(res, error_res, sizeof(error_res));
		strncat(res, error, sizeof(error));
	} else {
		strncpy(res, error_res, sizeof(error_res));
    strncat(res, unknown, sizeof(unknown));
		strncat(res, header, sizeof(header));
		strncat(res, DELIMITER, sizeof(DELIMITER));
	}
}

/* Validates whether a specified seed, nonce, and target meet the criteria for
   the Hashcash algorithm, that is:
   H(H(seed | nonce)) = y, such that y < target,
   where H is the SHA-256 hash function.
*/
int validate_hashcash(BYTE *seed, BYTE *nonce, BYTE *target) {
    BYTE x[40];
    int i;

/* Copies the seed and nonce into a BYTE array */
    for (i = 0; i < 32; i++) {
        x[i] = seed[i];
    }
    for (i = 32; i < 40; i++) {
        x[i] = nonce[i - 32];
    }

/* Hashes the BYTE array and hashes the result */
    SHA256_CTX ctx;
    BYTE hash[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, x, sizeof(x));
    sha256_final(&ctx, hash);

    BYTE hash2[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, hash, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, hash2);

    return sha256_compare(target, hash2);
}

/* Handles messages with header SOLN by parsing the buffer and arranging
   data structures to be passed into the validation function.
*/
void solution_handler(char *buffer, size_t buffer_size, char *res) {
/* Expecting a buffer of exactly 97 characters: a 4-byte header, an 8-byte
   hexadecimal difficulty, a 64-byte seed, and a 16-byte solution, all
   separated by spaces, plus a 2-byte delimiter.
*/
    if (strlen(buffer) != SOLN_MESSAGE_LENGTH) {
        strncpy(res, error_res, sizeof(error_res));
        strncat(res, length_error, sizeof(length_error));
        return;
    }

/* Copies the difficulty and stores it as an unsigned long int */
    uint32_t difficulty;
    BYTE difficulty_string[9];
    strncpy(difficulty_string, &buffer[5], 8);
    difficulty_string[8] = '\0';
    difficulty = strtoul(difficulty_string, NULL, 16);

/* Copies the seed in 2-character segments and converts it to an unsigned 8-bit
   integer, storing the result in an array of BYTEs.
*/
    BYTE seed[32];
    uint8_t seed_buffer;
    char seed_buffer_string[3];
    int j;
    for(j = 0; j < 32; j++) {
        strncpy(seed_buffer_string, &buffer[14 + j*2], 2);
        seed_buffer_string[2] = '\0';
        seed_buffer = (uint8_t)strtol(seed_buffer_string, NULL, 16);
        seed[j] = seed_buffer;
    }

/* Copies the solution in 2-character segments and converts it to an unsigned
   8-bit integer, storing the result in an array of BYTEs.
*/
    BYTE solution[8];
    uint8_t solution_buffer;
    char solution_buffer_string[3];
    for(j = 0; j < 8; j++) {
        strncpy(solution_buffer_string, &buffer[79 + j*2], 2);
        solution_buffer_string[2] = '\0';
        solution_buffer = (uint8_t)strtol(solution_buffer_string, NULL, 16);
        solution[j] = solution_buffer;
    }

/* Difficulty is encoded in big endian byte order. First, reverse to little
   endian. Difficulty is converted to target using the formula:
   target = beta x 2^(8 x (alpha - 3)),
   where alpha is difficulty[0..7], and beta is difficulty[8..31].
*/
    uint32_t ho_difficulty = ntohl(difficulty);
    uint32_t exp = 8 * ((ho_difficulty & ((1 << 8) - 1)) - 3);

/* Calculate beta by isolating 1-byte segments and bit-wise operations */
    BYTE beta[32];
    uint256_init(beta);
    int i;
    for (i = 0; i < 28; i++) {
        beta[i] = 0x0;
    }
    beta[29] = (ho_difficulty & 0x0000ff00) >> 8;;
    beta[30] = (ho_difficulty & 0x00ff0000) >> 16;
    beta[31] = (ho_difficulty & 0xff000000) >> 24;


    BYTE base[32];
    uint256_init(base);
    for (i = 0; i < 30; i++) {
        base[i] = 0x0;
    }
    base[31] = 0x2;
    BYTE answer[32];
    uint256_init(answer);
    uint256_exp(answer, base, exp);

    BYTE target[32];
    uint256_init(target);
    uint256_mul(target, answer, beta);

/* Use the determined seed, solution, and target in the validate function.
   If it is a valid solution, return OKAY,
   otherwise return ERRO: not a valid solution.
*/
    if (validate_hashcash(seed, solution, target) == 1) {
        strncpy(res, "OKAY\r\n\0", 7);
    } else {
        strncpy(res, error_res, sizeof(error_res));
        strncat(res, solution_error, sizeof(solution_error));
    }
}

/* Adds a new item to the queue of possible solutions to be validated. */
void add_to_queue(struct hashcash *new_item) {
    struct hashcash *last_item;
    new_item->next = NULL;

/* Uses a semaphore to put a lock on the queue structure */
    sem_wait(&queue);

/* If the queue is empty, the item becomes the queue head. Otherwise, the queue
   is traversed until the last item is found, and the new item is inserted.
*/
    if (hashcash_queue == NULL) {
       hashcash_queue = new_item;
    } else {
        last_item = hashcash_queue;
        while (last_item->next != NULL) {
            last_item = last_item->next;
        }
        last_item->next = new_item;
    }

/* Removes the lock on the queue */
    sem_post(&queue);
}

/* Handles messages with header WORK by parsing the buffer and arranging
   a data structure to be passed into the work queue.
*/
void work_handler(char *buffer, size_t buffer_size, char *res, int sockfd) {
/* Expecting a buffer of exactly 100 characters: a 4-byte header, an 8-byte
   hexadecimal difficulty, a 64-byte seed, a 16-byte initial value for nonce,
   and a 2-byte value that specifies the number of threads to use, all
   separated by spaces, plus a 2-byte delimiter.
*/
    if (strlen(buffer) != WORK_MESSAGE_LENGTH) {
        strncpy(res, error_res, sizeof(error_res));
        strncat(res, length_error, sizeof(length_error));
        return;
    }

/* Initialise the hashcash structure to hold work message in */
    struct hashcash *info = malloc(sizeof(struct hashcash));

/* Copies the difficulty and stores it as an unsigned long int */
    uint32_t difficulty;
    BYTE difficulty_string[9];
    strncpy(difficulty_string, &buffer[5], 8);
    difficulty_string[8] = '\0';
    difficulty = strtoul(difficulty_string, NULL, 16);

/* Copies the seed in 2-character segments and converts it to an unsigned 8-bit
   integer, storing the result in an array of BYTEs.
*/
    char seed_buffer_string[3];
    int i;
    for (i = 0; i < 32; i++) {
        strncpy(seed_buffer_string, &buffer[14 + i * 2], 2);
        seed_buffer_string[2] = '\0';
        info->seed[i] = (uint8_t)strtol(seed_buffer_string, NULL, 16);
    }

/* Copies the nonce is 2-character segments and converts it to an unsigned 8-bit
   integer, storing the result in an array of BYTES.
*/
    char nonce_buffer_string[3];
    for (i = 0; i < 8; i++) {
        strncpy(nonce_buffer_string, &buffer[79 + i * 2], 2);
        nonce_buffer_string[2] = '\0';
        info->nonce[i] = (uint8_t)strtol(nonce_buffer_string, NULL, 16);
    }

/* Difficulty is encoded in big endian byte order. First, reverse to little
   endian. Difficulty is converted to target using the formula:
   target = beta x 2^(8 x (alpha - 3)),
   where alpha is difficulty[0..7], and beta is difficulty[8..31].
*/
    uint32_t ho_difficulty = ntohl(difficulty);
    uint32_t exp = 8 * ((ho_difficulty & ((1 << 8) - 1)) - 3);

/* Calculate beta by isolating 1-byte segments and bit-wise operations */
    BYTE beta[32];
    uint256_init(beta);
    for (i = 0; i < 28; i++) {
        beta[i] = 0x0;
    }
    beta[29] = (ho_difficulty & 0x0000ff00) >> 8;
    beta[30] = (ho_difficulty & 0x00ff0000) >> 16;
    beta[31] = (ho_difficulty & 0xff000000) >> 24;

    BYTE base[32];
    uint256_init(base);
    for (i = 0; i < 30; i++) {
        base[i] = 0x0;
    }
    base[31] = 0x2;

    BYTE answer[32];
    uint256_init(answer);
    uint256_exp(answer, base, exp);

    uint256_init(info->target);
    uint256_mul(info->target, answer, beta);

/* Declare the message unsolved, and assign the socket file descriptor that the
   message originated from.
*/
    info->solved = 0;
    info->sockfd = sockfd;
    add_to_queue(info);

/* Wait until the message has been solved */
    while(info->solved == 0) {
    }

/* Compose the response message */
    if (info->solved == 1) {
        strncpy(res, "SOLN ", 5);
        strncpy(&res[5], &buffer[5], 9);
        strncpy(&res[14], &buffer[14], 65);
        for (i = 0; i < 8; i++) {
            sprintf(&res[79 + 2 * i], "%02x", info->nonce[i]);
        }
        strncpy(&res[95], "\r\n\0", 3);
    } else {
        strncpy(res, "FLAG", 4);
    }
    free(info);
}

/* Handles a message received from a connection and responds to it. */
void *connection_responder(void *args) {
/* Stores the thread parameters, socket file descriptor, and copies the message
   input into a buffer.
*/
    struct thread_params *input = (struct thread_params*)args;
    int newsockfd = input->socketfd;
    struct sockaddr_in *client_address = input->client_address;
    char buffer[256];
    strncpy(buffer, input->buffer_input, 255);

    int n;
    BYTE res[256];
    BYTE header[5];

/* Construct log information */
    struct log_text *log_input = malloc(sizeof(struct log_text));
    time_t input_time;
    input_time = time(NULL);
    char *input_time_string = ctime(&input_time);
    char log_input_time[40];
    sprintf(log_input_time, "%s", input_time_string);
    char ip4[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_address->sin_addr), ip4, INET_ADDRSTRLEN);

    char client_socket[10];
    sprintf(client_socket, " fd: (%d)\n", newsockfd);

    construct_log_input(log_input, log_input_time, ip4, client_socket, buffer);

/* Copy the header from the buffer to a new array */
    strncpy(header, buffer, 4);
    header[4] = '\0';

/* The message must be at least as long as the standard delimiter /r/n, and all
   messages must end in the delimiter.
   If the message meets these criteria, sort into SOLN, WORK, ABRT, or
   miscellaneous headers.
*/
    if (!(strlen(buffer) > strlen(DELIMITER) && !strcmp(buffer + strlen(buffer) - strlen(DELIMITER), DELIMITER))) {
        strncpy(res, error_res, sizeof(error_res));
        strncat(res, delimiter_error, sizeof(delimiter_error));
    } else {
        if (strcmp(header, "SOLN") == 0) {
            solution_handler(buffer, sizeof(buffer), res);
        } else if (strcmp(header, "WORK") == 0) {
            work_handler(buffer, sizeof(buffer), res, newsockfd);
        } else if (strcmp(header, "ABRT") == 0) {
            kill_switch = newsockfd;
            strncpy(res, "OKAY\r\n", 6);
        } else {
            simple_header_handler(header, res);
        }
    }

/* FLAG response indicates that something has gone wrong finding a solution. */
    if (strcmp(res, "FLAG") != 0) {
        n = write(newsockfd, res, strlen(res));

        if (n < 0) {
            free(log_input);
            printf("error writing: exiting thread\n");
            pthread_exit(NULL);
        }
    } else {
        bzero(res, 256);
    }

/* Construct log information */
    struct log_text *log_output = malloc(sizeof(struct log_text));
    time_t output_time;
    output_time = time(NULL);
    char *output_time_string = ctime(&output_time);
    construct_log_input(log_output, output_time_string, SERVERIP,
      client_socket, res);

/* Critical section - use semaphores to ensure only one thread writes to the
   log at one time.
*/
    sem_wait(&sem);
    print_to_log(log_input);
    print_to_log(log_output);
    sem_post(&sem);

    free(log_input);
    free(log_output);
    pthread_exit(NULL);
}

/* Handles a connection received from a client. */
void *connection_handler(void *args) {
/* Initialise buffers to store input and output messages */
    BYTE buffer[256];
    BYTE res[256];
    int n, newsockfd;
    struct thread_params *input = (struct thread_params*) args;
    newsockfd = input->socketfd;
    struct sockaddr_in *client_address = input->client_address;
    pthread_t responder_thread;

/* When a detached thread terminates, its resources are automatically
 released back to the system without the need for another thread to join
 with the terminated thread */
    pthread_detach(pthread_self());

    bzero(buffer, 256);
    bzero(res, 256);

/* Read characters from the connection, then process */
    while (1) {
        while((n = read(newsockfd, buffer, 255)) != 0) {
            if (n < 0) {
                printf("Error reading from socket\n");
                free(args);
                pthread_join(responder_thread, NULL);
                close(newsockfd);
                num_clients--;
                pthread_exit(NULL);
            }

/* Construct the input parameters */
            struct thread_params *input_params = malloc(sizeof(
              struct thread_params));
            input_params->socketfd = newsockfd;
            input_params->client_address = client_address;
            strncpy(input_params->buffer_input, buffer, 255);

/* Create a thread to handle the message */
            pthread_create(&responder_thread, NULL, connection_responder,
              input_params);
            bzero(buffer, 256);
        }

/* Update kill switch to indicate that this message has been handled */
        kill_switch = newsockfd;
        free(args);
        close(newsockfd);
        num_clients--;
        pthread_exit(NULL);
    }

    free(args);
    close(newsockfd);
    num_clients--;
    pthread_exit(NULL);
}

/* Increments an array of bytes at a specified index */
void increment_byte_array(BYTE *array, int index) {
    if (array[index] == 0xff) {
        array[index] = 0x00;
        if (index > 0) {
            increment_byte_array(array, index - 1);
        }
    } else {
        array[index]++;
    }
}

/* Removes items from the work queue once the message has been solved. */
int queue_killer() {
/* Kill switch is set to the socket file descriptor of the message that has
   been solved.
*/
    if (kill_switch) {
/* Use semaphore to get access to the queue */
        sem_wait(&queue);
        struct hashcash *curr_item = hashcash_queue;
        struct hashcash *prev_item = NULL;

/* Traverse the queue until the correct item is found, then remove it */
        while (curr_item != NULL) {
            if (curr_item->sockfd == kill_switch) {
                if (prev_item != NULL) {
                    prev_item->next = curr_item->next;
                } else {
                    hashcash_queue = NULL;
                }
                curr_item->solved = -1;
            } else {
                prev_item = curr_item;
            }
            curr_item = curr_item->next;
        }

/* Signal end of queue access and reset kill switch */
        sem_post(&queue);
        kill_switch = 0;
        return 1;
    }
    return 0;
}

/* Handles the queue of work messages to be solved */
void *work_queue(void *args) {
    int queue_killed = 0;
    pthread_detach(pthread_self());

/* Runs until server is terminated */
    while(1) {
        queue_killer();
        if (hashcash_queue != NULL) {
            int iterations = 0;
/* While the current work message isn't a valid solution, increase the nonce,
   and check to make sure another thread hasn't solved the same message.
*/
            while (!queue_killed && validate_hashcash(hashcash_queue->seed,
              hashcash_queue->nonce, hashcash_queue->target) != 1) {
                increment_byte_array(hashcash_queue->nonce, 7);
                iterations++;
                queue_killed = queue_killer();
            }

/* If another thread has solved the message, don't execute the rest of the loop,
   and increase the queue to the next message.
*/
            if (queue_killed) {
                queue_killed = 0;
                continue;
            }
            hashcash_queue->solved = 1;
            hashcash_queue = hashcash_queue->next;
        }
    }
    pthread_exit(NULL);
}

int main(int argc, char **argv) {
	 int sockfd, portno, clilen;
	  struct sockaddr_in serv_addr, cli_addr;
    struct thread_params *args;
    pthread_t worker_thread, work_thread;
    FILE *fp;
    kill_switch = 0;
    num_clients = 0;

/* Check to see a port was provided */
    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }

/* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);

/* Create address we're going to listen on (given port number) - converted to
   network byte order & any IP address for this machine. Stored in
   machine-neutral format.
*/
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

/* Bind address to the socket */
    while (bind(sockfd, (struct sockaddr *) &serv_addr,
      sizeof(serv_addr)) < 0) {
        sleep(1);
    }

/* Open log file */
    fp = fopen("log.txt", "w+");
    fprintf(fp,
      "Log File\n--------------------------------------------------\n");
    fclose(fp);

/* Initialise semaphores */
    sem_init(&sem, 0, 1);
    sem_init(&queue, 0, 1);

/* Listen on socket - means we're ready to accept connections - incoming
   connection requests will be queued.
*/
    listen(sockfd,5);

/* Initialise work queue */
    pthread_create(&work_thread, NULL, work_queue, NULL);
    clilen = sizeof(cli_addr);

    while (1) {
        if (num_clients < 100) {
/* Accept a connection - block until a connection is ready to be accepted. Get
   back a new file descriptor to communicate on.
*/
            int newsockfd;
            newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

            if (newsockfd < 0) {
                perror("ERROR on accept");
                exit(1);
            }

/* Create a pointer to the socket file descriptor to pass to the processing
   function.
*/
            args = malloc(sizeof(struct thread_params));
            args->socketfd = newsockfd;
            args->client_address = (struct sockaddr_in *) &cli_addr;

/* Create a new thread to handle this connection */
            int n;
            n = pthread_create(&worker_thread, NULL, connection_handler, args);
            if (n != 0) {
                printf("error creating a new thread\n");
                close(newsockfd);
                continue;
            }
            num_clients++;
        }
    }

/* Close socket */
    close(sockfd);
    return 0;
}
