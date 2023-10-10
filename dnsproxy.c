#include"dnsproxy.h"

struct CLIENT_QUERY *p_client_query_queue;
struct CONFIG config;
char *p_blacklist;
int client_query_queue = 0;
int last_trans_id = 1;

int main()
{
    init_config(&config);
    get_blacklist(config.blacklist);

    struct sockaddr_in server_addr;
    struct sockaddr_in dns_addr;
    int server_sd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    if(server_sd < 0)
    {
	perror("Failed open socket");
	exit( EXIT_FAILURE);
    }

    int dns_sd = socket(AF_INET,SOCK_DGRAM, IPPROTO_UDP);
    memset(&server_addr ,0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(config.listen_ip);
    server_addr.sin_port = htons(config.listen_port);

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    dns_addr.sin_addr.s_addr = inet_addr("8.8.8.8");


    if(bind(server_sd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
	perror("Failed bind 53 port");
	exit( EXIT_FAILURE);
    }

    wait_data(server_sd, dns_sd, &dns_addr);
}
void get_name(char* q_name, char* name)
{
    int bytes_next_dot = (int)*q_name;
    for(int i = 0; i < MAX_DNS_NAME; i++)
    {
	q_name++;
	if((char)*q_name == '\0')
	{
	    name[i] = '\0';
	    break;
	}
	else if(bytes_next_dot == 0)
	{
	    name[i] = '.';
	    bytes_next_dot = (int)*q_name;
	}
	else
	{
	    bytes_next_dot--;	
	    name[i] = (char)*q_name;
	}
    }
}
void reverse_ip(const char* ip, char* r_ip)
{
    r_ip[0] = '\0';
    int len_ip = strlen(ip);
    int dot = len_ip;
    for(int i = len_ip; i >= 0; i--)
    {
	if(i == 0)
	{
	    strncat(r_ip, &ip[0], dot + 1);
	}
	else if(ip[i] == '.')
	{
	    strncat(r_ip, &ip[i + 1], dot - i);
	    strcat(r_ip, ".");
	    dot = i - 1;
	}
    }
}
void get_dns_name(char* name, char*dns_name)
{
    dns_name[0] = '.';
    dns_name[1] = '\0';
    strcat(&dns_name[1], name);
    int bytes_dot = 0;
    int dots[5] = {0};
    int i = 0;

    while(1)
    {
	if(*name == '.')
	{
	    dots[i] = bytes_dot;
	    bytes_dot = 0;
	    i++;
	}
	else if(*name == '\0')
	{
	    dots[i] = bytes_dot;
	    break;
	}
	else
	{
	    bytes_dot++;
	}
	name++; 
    }

    i = 0;
    for(int j = 0; j < MAX_DNS_NAME; j++)
    {
	if(dns_name[j] == '.')
	{
	    dns_name[j] = (char)dots[i];
	    i++;	    
	}
	else if(dns_name[j] == '\0')
	{
	    break;
	}
    }

}
void wait_data(int server_sd, int dns_sd, struct sockaddr_in *dns_addr)
{
    struct pollfd sds[2];
    sds[0].fd = server_sd;
    sds[0].events = POLLIN;

    sds[1].fd = dns_sd;
    sds[1].events = POLLIN;

    while(1)
    {
	int revents = poll(sds, 2, 1);
	if(revents > 0)
	{
	    if(sds[0].revents & POLLIN)
	    {
		sds[0].revents = 0;
		handle_client_query(server_sd, dns_sd, dns_addr);
	    }

	    if(sds[1].revents & POLLIN)
	    {
		sds[1].revents = 0;
		handle_dns_answer(server_sd, dns_sd);
	    }

	}
    }
}

void handle_client_query(int server_sd, int dns_sd, struct sockaddr_in *dns_addr)
{
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t client_len = sizeof(client_addr); 
    char buf[MAX_UDP_SIZE];

    ssize_t got_bytes = recvfrom(server_sd, buf, 1000,0,(struct sockaddr *)&client_addr, &client_len);
    if (got_bytes < 0)
    {
	perror("Failed receive data from client");
    }

    struct DNS_HEADER *p_dns_header = (struct DNS_HEADER *)&buf;
    char * p_dns_name = &buf[sizeof(struct DNS_HEADER)];
    char name[MAX_DNS_NAME];
    get_name(p_dns_name, name);
    int len_name = strlen(name) + 2;
    struct QUESTION * p_question =(struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + len_name];

    // Check if dns name is in blacklist then
    if(is_name_blocked(name))
    {
	p_dns_header->qr = 1;
	p_dns_header->rcode = 3;
	if((sendto(server_sd, buf, got_bytes,0, (struct sockaddr *)&client_addr, sizeof(client_addr))) < 0)
	{
	    perror("Failed send data to client");

	}	    
    }
    else
    {
	char* client_ip = inet_ntoa(client_addr.sin_addr);
	struct CLIENT_QUERY* p_client_query = malloc(sizeof(struct CLIENT_QUERY));
	p_client_query->client_trans_id = ntohs(p_dns_header->id);
	strcpy(p_client_query->ip, client_ip);
	p_client_query->port = ntohs(client_addr.sin_port);
	p_client_query->next_query = NULL;

	if(last_trans_id > MAX_DNS_ID)
	{
	    last_trans_id = 0;
	}
	p_dns_header->id = htons(last_trans_id); 
	p_client_query->trans_id = last_trans_id;

	if(client_query_queue == 0)
	{
	    p_client_query_queue = (void*)p_client_query;
	}
	else
	{
	    void* last_query = p_client_query_queue;
	    while(1)
	    {
		last_query = ((struct CLIENT_QUERY*)last_query)->next_query;
		if(last_query == NULL)
		{
		    break;
		}
	    }	
	    ((struct CLIENT_QUERY*)&last_query)->next_query = p_client_query;
	}

	switch(ntohs(p_question->qtype))
	{
	    case T_PTR:	
		char ptr[MAX_DNS_NAME] = {'\0'};
		char r_ip[20];
		reverse_ip(config.dns_ip, r_ip);
		strcpy(ptr, r_ip);
		strcat(ptr, ".in-addr.arpa");
		char dns_name[MAX_DNS_NAME];
		get_dns_name(ptr, dns_name);
		char answer_buf[MAX_UDP_SIZE];

		memcpy(answer_buf, p_dns_header, sizeof(struct DNS_HEADER));
		memcpy(&answer_buf[sizeof(struct DNS_HEADER)], dns_name, strlen(dns_name) + 1);
		memcpy(&answer_buf[sizeof(struct DNS_HEADER) + strlen(dns_name) + 1], p_question, sizeof(struct QUESTION));
		int len = sizeof(struct DNS_HEADER) + strlen(dns_name) + 1 + sizeof(struct QUESTION);
		if( sendto(dns_sd,&answer_buf[0],len,0,(struct sockaddr*)dns_addr,sizeof(struct sockaddr_in)) < 0)
		{
		    perror("Failed send data to dns server");
		}
		break; 
	    case T_A:
	    case T_AAAA:
		if( sendto(dns_sd,buf, got_bytes ,0,(struct sockaddr*)dns_addr,sizeof(struct sockaddr_in)) < 0)
		{
		    perror("Failed send data to dns server");
		}
	}	    
	client_query_queue++;
	last_trans_id++;
    }
}

void handle_dns_answer(int server_sd, int dns_sd)
{
    char buf[MAX_UDP_SIZE];
    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    socklen_t lenaddr = sizeof(dns_addr);

    ssize_t got_bytes = recvfrom(dns_sd,buf, 1000, 0,(struct sockaddr*)&dns_addr, &lenaddr); 
    if(got_bytes < 0)
    {
	perror("Failed receive data from dns server");
    }

    struct DNS_HEADER *p_dns_header = (struct DNS_HEADER *)&buf;
    char * p_dns_name = &buf[sizeof(struct DNS_HEADER)];
    char name[MAX_DNS_NAME];
    get_name(p_dns_name, name);
    int len_name = strlen(name) + 2;
    struct QUESTION * p_question =(struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + len_name];

    int trans_id =  ntohs(p_dns_header->id);

    struct CLIENT_QUERY* previous_query_q = NULL;
    struct CLIENT_QUERY* client_query_q =(struct CLIENT_QUERY*) p_client_query_queue;

    while(1)
    {
	if(client_query_q == NULL)
	{
	    //TODO: handle if client query not found
	    break;
	}

	int id = client_query_q->trans_id;
	if (trans_id == id)
	{
	    if(client_query_queue > 1)
	    {
		previous_query_q->next_query = client_query_q->next_query; 
	    }
	    break;
	}
	previous_query_q = client_query_q;
	client_query_q = ((struct CLIENT_QUERY*)client_query_q->next_query);
    }

    p_dns_header->id  = htons(client_query_q->client_trans_id);
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(client_query_q->port);
    client_addr.sin_addr.s_addr = inet_addr(client_query_q->ip);

    if((sendto(server_sd, buf, got_bytes,0, (struct sockaddr *)&client_addr, sizeof(client_addr))) < 0)
    {
	perror("Failed send data to client");

    }	    
    free(client_query_q);
    client_query_queue--;
} 

void init_config(struct CONFIG *config)
{
    char* line = NULL;
    size_t line_buf_size = 0;
    ssize_t line_length;
    FILE* fd = fopen("dnsproxy.cfg", "r");
    if(!fd)
    {
	perror("Failed open dnsproxy.cfg");
	exit( EXIT_FAILURE);
    }

    line_length = getline(&line, &line_length, fd);
    while(line_length != -1)
    {
	if(line_length > 1 && line[0] !='#')
	{
	    char parameter[30];
	    char name_parameter[30];
	    int i = 0;
	    for( ; i < line_length; i++)
	    {
		if(line[i] == '=' || line[i] == ' ' )
		{
                    name_parameter[i] = '\0';
		    break;

		}
                name_parameter[i] = line[i];
	    }
	    
	    for(int j =0; i <= line_length; i++)
	    {
		if(line[i] == '\n')
		{
		    parameter[j] = '\0';
		    break;
		}
		else if(line[i] != '=' && line[i] != ' ')
		{
		    parameter[j] = line[i];
		    j++;
		}

	    }
	    
	    if(!strcmp("listen_ip", name_parameter))
	    {
		strcpy(config->listen_ip, parameter);
	    }
	    else if(!strcmp("listen_port",name_parameter))
	    {
		config->listen_port = atoi(parameter);
	    }    
	    else if(!strcmp("dns_ip", name_parameter))
	    {
		strcpy(config->dns_ip, parameter);
	    }    
	    else if(!strcmp("blacklist", name_parameter))
	    {
		strcpy(config->blacklist, parameter);
	    }    
	}
	    line_length = getline(&line, &line_buf_size, fd);
    }

    free(line);    
    fclose(fd);

}

void get_blacklist(char* blacklist_path)
{
    char* line = NULL;
    size_t line_buf_size = 0;
    ssize_t line_length;
    FILE* fd = fopen(blacklist_path, "r");    
    if(!fd)
    {
	perror("Failed open blacklist.txt");
	exit( EXIT_FAILURE);
    }
    
    config.blacklist_size = 0;
    while(!feof(fd))
    {
	char ch = fgetc(fd);
	if(ch == '\n')
	{
	   config.blacklist_size++;
	}
    }
    int file_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    char* begin_blacklist = malloc(file_size);
    p_blacklist = begin_blacklist;
    line_length = getline(&line, &line_length, fd);
    while(line_length > 0)
    {
	line[line_length-1] = '\0';
	strcpy(begin_blacklist,line);
	begin_blacklist += line_length;	    
	line_length = getline(&line, &line_length, fd);
    }
}

int is_name_blocked(char* name)
{
    char* begin_blacklist = p_blacklist;
    for(int i = 0; i < config.blacklist_size; i++)
    {
	if(strstr(begin_blacklist, name) != NULL)
	{
	    return 1;
	}
	begin_blacklist += strlen((char*)begin_blacklist) + 1;
    }
    return 0;
}
