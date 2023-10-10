
//Header Files
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<string.h>
#include<stdlib.h>
#include<poll.h>

//Type field of Query and Answer
#define T_A     1 /* host address */
#define T_NS    2 /* authoritative server */
#define T_CNAME 5 /* canonical name */
#define T_SOA   6 /* start of authority zone */
#define T_PTR   12 /* domain name pointer */
#define T_MX    15 /* mail routing information */
#define T_AAAA  28 /* host address ipv6 */

//Some DNS limits
#define MAX_DNS_ID   65534
#define MAX_DNS_NAME 253
#define MAX_UDP_SIZE 512
#define DNS_PORT     53

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

struct CONFIG 
{
    char listen_ip[20];
    int listen_port;
    char dns_ip[20];
    char blacklist[50];
    int blacklist_size;
};

struct CLIENT_QUERY
{
    int trans_id;
    int client_trans_id;
    char ip[20];
    int port;
    void *next_query;
};


//Function Prototypes
void init_config(struct CONFIG *config);
void get_blacklist(char* blacklist_path);
int is_name_blocked(char* name);
void reverse_ip(const char* ip, char* r_ip);
void wait_data(int server_sd, int dns_sd, struct sockaddr_in *dns_addr);
void get_name(char* q_name, char* name);
void get_dns_name(char* name, char* dns_name);
void handle_client_query(int server_sd, int dns_sd, struct sockaddr_in *dns_addr);
void handle_dns_answer(int server_sd, int dns_sd);


