/*
 * pg_rest.c
 *
 *
 * Copyright (c) 2022, Kalendarev Alexandre akalend@mail.ru
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written agreement
 * is hereby granted, provided that the above copyright notice and this
 * paragraph and the following two paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE AUTHOR OR DISTRIBUTORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUTHOR AND DISTRIBUTORS HAS NO OBLIGATIONS TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 */
#include "postgres.h"

#include <event.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

#include "access/htup.h"
#include "access/htup_details.h"
#include "c.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "utils/backend_status.h"
#include "utils/builtins.h"
#include "pg_rest.h"

PG_MODULE_MAGIC;



#define xpfree(var_) \
	do { \
		if (var_ != NULL) \
		{ \
			pfree(var_); \
			var_ = NULL; \
		} \
	} while (0)

#define xpstrdup(tgtvar_, srcvar_) \
	do { \
		if (srcvar_) \
			tgtvar_ = pstrdup(srcvar_); \
		else \
			tgtvar_ = NULL; \
	} while (0)


#define DEFAULT_PORT 8080
#define MAX_PATH_LEN 1024

enum Http_method {	
	HTTP_GET =1,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
	HTTP_UNKNOW = -1
} ;

struct client 
{
    int fd;
    struct bufferevent *buf_ev;
};


void set_nonblock(int fd);
int initialize_socket(int port);
void * http_server();

bool is_run = false;
char uri_root[512];


PG_FUNCTION_INFO_V1(exec);
Datum
exec(PG_FUNCTION_ARGS)
{
	char	*sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
	int res = 0;

	StringInfoData buf;
	initStringInfo(&buf);
	res = exec_queue(sql, &buf);
	pfree(buf.data);
	PG_RETURN_INT32(res);
}


int
exec_queue(char* sql, StringInfoData *buf)
{
	HeapTuple	tuple;
	int			ret;
	uint64		proc;
	
	/* Connect to SPI manager */
	if ((ret = SPI_connect()) < 0){
		/* internal error */
		elog(LOG, "crosstab: SPI_connect returned %d", ret);
		return -1;
	}

	/* Retrieve the desired rows */
	elog(LOG, "exec:%s",sql);
	ret = SPI_execute(sql, true, 0);

	/* If no qualifying tuples, fall out early */
	if (ret != SPI_OK_SELECT )
	{
		elog(WARNING,"returned null");
		SPI_finish();
		return -1;
	}
	proc = SPI_processed;
	elog(WARNING,"return %ld", proc);

	appendStringInfo(buf,"{\"rows\":[{");

	if (SPI_tuptable == NULL)
	{
		SPI_finish();
		return 0;
	}

	int i,j;
	const char* str_null = "null";
	TupleDesc tupdesc;
	char* val;
	
	tupdesc = SPI_tuptable->tupdesc;

	for (j = 0; j < SPI_tuptable->numvals; j++)
	{			
		// appendStringInfo(&buf,"{\"row\":{");

		tuple = SPI_tuptable->vals[j];
		for (i = 0; i < tupdesc->natts; i++)
		{
			Form_pg_attribute att = TupleDescAttr(tupdesc, i);

			if (att->attisdropped)
				continue;

			val = SPI_getvalue(tuple, tupdesc, i + 1);

			switch (att->atttypid)
			{
				case BOOLOID:
					appendStringInfo(buf,"\"%s\":%s",NameStr(att->attname), val ? (val[0]=='t' ? "true":"false" ): str_null);
					break;
				case INT8OID:
				case INT2OID:
				case INT4OID:
				case FLOAT4OID:
				case FLOAT8OID:
				case NUMERICOID:
					appendStringInfo(buf,"\"%s\":%s",NameStr(att->attname), val ? val : str_null);
					break;
				case JSONBOID:						
					appendStringInfo(buf,"\"%s\":%s",NameStr(att->attname), val ? val : str_null);
					break;
				case UUIDOID:
				case CHAROID:
				case BPCHAROID:
				case TEXTOID:
				case VARCHAROID:
				case DATEOID:
				case TIMEOID:
				case TIMETZOID:
				// case TIMETZOID:
				case TIMESTAMPOID:
				case TIMESTAMPTZOID:
				case INTERVALOID:
					if (val)
					{
						appendStringInfo(buf,"\"%s\":\"%s\"",NameStr(att->attname), val);
					} 
					else
					{
						appendStringInfo(buf,"\"%s\":null",NameStr(att->attname));							
					}
					break;
				default:
					appendStringInfo(buf,"\"%s\":\"unsupport oid=%d\"",NameStr(att->attname),att->atttypid);
			}	

			if (i < tupdesc->natts-1) appendStringInfo(buf,",");

			if (val) pfree(val);
		}
		
		if (j < SPI_tuptable->numvals-1) 
		{
			appendStringInfo(buf,"},{");
		}
		else appendStringInfo(buf,"}]}");
	}

	elog(LOG, "result:%s",(char*)buf->data);


	SPI_finish();
	return 0;
}

int
parse_request(char* request, char** tableName)
{
	enum Http_method method;
	int off;
	size_t len;
	char* p, *p1, *p0;

	if (strncmp(request, "GET ",4) == 0)
	{		
		method = HTTP_GET;
		elog(LOG, "HTTP GET");
		off = 4;
	}
	else if (strncmp(request, "POST",4) == 0)
	{
		method = HTTP_POST;
		off = 5;
	}
	else if (strncmp(request, "PUT",3) == 0)
	{
		method = HTTP_PUT;
		off = 4;
	}
	else if (strncmp(request, "DELETE",6) == 0)
	{
		method = HTTP_DELETE;
		off = 7;
	}
	else
		return HTTP_UNKNOW;

	elog(LOG, "HTTP method_id=%d", method);

	p0 = request + off;
	len = strlen(p0);
	p = memchr(  p0, (int)' ', len);
	if (!p)
	{
		elog(LOG, "parse error");
		return HTTP_UNKNOW;
	}
	
	off = abs(request - p);
	elog(LOG, "off=%d",off);

	p1 = memchr(  request+off, (int)' ', len - off);
	if (!p1)
	{
		elog(LOG, "parse error");
		return HTTP_UNKNOW;
	}
	*p1 = 0;
	elog(LOG, "'%s'", p0);

	*tableName = p1;
	return 0;
}

void set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

int initialize_socket(int port)
{
	int sock;
	struct sockaddr_in serv_addr;
	int reusable;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
		close(sock);
		elog(ERROR, "Cannot open socket");
	}

	reusable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reusable, sizeof (reusable)) == -1) {
		elog(ERROR, "Cannot set option");
	}

	bzero((char *) &serv_addr, sizeof (serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0) {
		close(sock);
		elog(ERROR, "Failed to bind socket");
	}
	
	if (listen(sock, 5) < 0) {
		close(sock);
		elog(ERROR, "Failed to listen to socket");
	}

	set_nonblock(sock);

	return sock;
}


void add_404_response(struct evbuffer *event_response) {
	evbuffer_add_printf(event_response, "HTTP/1.1 404 Not Found\n");
	evbuffer_add_printf(event_response, "Content-Type: text/plain\n");
	evbuffer_add_printf(event_response, "Content-Length: 9\n");
	evbuffer_add_printf(event_response, "\n");
	evbuffer_add_printf(event_response, "Not Found\n");
}

void add_200_response(struct evbuffer *event_response, char* data) {
	FILE* f;

	evbuffer_add_printf(event_response, "HTTP/1.1 200 OK\n");
	evbuffer_add_printf(event_response, "Content-Type: application/json\n");
	evbuffer_add_printf(event_response, "Content-Length: %d\n", strlen(data));
	evbuffer_add_printf(event_response, "\n");

	evbuffer_add_printf(event_response, data);
}


void buf_read_callback(struct bufferevent *incoming, void *arg) {
	struct evbuffer *event_response;
	char *request, *response;
	int res;
	char *tableName;

	request = evbuffer_readln(incoming->input, NULL, EVBUFFER_EOL_ANY);
	if (request == NULL) {
		return;
	}
	// skip the rest of request
	while (evbuffer_readln(incoming->input, NULL, EVBUFFER_EOL_ANY) != NULL);
	event_response = evbuffer_new();

	elog(LOG,"Processing request: '%s'\n", request);
	
	res = parse_request(request, &tableName);
	if (res) 
	{
		add_404_response(event_response);
		evbuffer_free(event_response);
		free(request);
		return;
	} 

	elog(LOG, "table '%s'",tableName);
	

	StringInfoData buf;
	initStringInfo(&buf);	
	const char * sql = "select typname , typnamespace , typowner , typlen  from pg_type limit 5";

	res = exec_queue(sql, &buf);
	if (res)
	{
		elog(LOG, "exec error");
		add_404_response(event_response);
		evbuffer_free(event_response);
		free(request);
		return;	
	}

	add_200_response(event_response, buf.data);
	bufferevent_write_buffer(incoming, event_response);

	evbuffer_free(event_response);	
	xpfree(buf.data);	
	free(request);
}

void buf_error_callback(struct bufferevent *bev, short what, void *arg) {
	elog(WARNING, "HTTP error\n");
	struct client *client = (struct client *)arg;
	bufferevent_free(client->buf_ev);
	close(client->fd);
	free(client);
}

void accept_callback(int fd, short ev, void *arg) {
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct client *client;
	struct timeval *timeout;

	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_fd < 0) 
	{
		elog(WARNING,"Client: accept() failed");
		return;
	}

	set_nonblock(client_fd);

	client = calloc(1,sizeof(*client));
	if (client == NULL) {
		elog(WARNING, "Failed to allocate memory on client");
	}
	client->fd = client_fd;

	client->buf_ev = bufferevent_new(
			client_fd,
			buf_read_callback,
			NULL,
			buf_error_callback,
			client);

	bufferevent_enable(client->buf_ev, EV_READ);

	timeout = (struct timeval*)malloc(sizeof(struct timeval*));
	timeout->tv_usec = 100000;
	bufferevent_set_timeouts(client->buf_ev, timeout, NULL);
}


static bool status_http = true; /* start worker? */

PG_FUNCTION_INFO_V1(http_run);
Datum
http_run(PG_FUNCTION_ARGS)
{
	status_http = true;
	PG_RETURN_INT32(1);	
}

PG_FUNCTION_INFO_V1(http_stop);
Datum
http_stop(PG_FUNCTION_ARGS)
{
	status_http = false;
	PG_RETURN_INT32((int)status_http);
}

PG_FUNCTION_INFO_V1(http_status);
Datum
http_status(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32((int)status_http);
}




void * http_server()
{
	int sock;
	int port = DEFAULT_PORT;
	struct event accept_event;	

	port = DEFAULT_PORT;
	sock = initialize_socket(port);
	elog(LOG,"HTTP server is up on 127.0.0.1:%d\n", port);

	event_init();
	event_set(&accept_event, sock, EV_READ|EV_PERSIST, accept_callback, NULL);
	event_add(&accept_event, NULL);
	
	is_run = true;
	event_dispatch();

	close(sock);


    return NULL;
}





void pg_rest_background(Datum main_arg)
{
    StringInfoData buf;
    int ret;

    elog(WARNING, "background_main start");

    BackgroundWorkerUnblockSignals();
 
    elog(LOG, "pg_rest(bgw): create HTTP");

    // http_server();
	initStringInfo(&buf);
	exec_queue("select typname , typnamespace , typowner , typlen  from pg_type limit 5", &buf);

    elog(LOG, buf.data);
	pfree(buf.data);

    elog(LOG, "pg_rest(bgw): stop HTTP");


    proc_exit(0);
}





void
_PG_init(void)
{
	
	BackgroundWorker worker;
	elog(WARNING,"init pg_rest IsUnderPostmaster=%d", IsUnderPostmaster);

	if (IsUnderPostmaster) return;

	if (!process_shared_preload_libraries_in_progress)
	{
		elog(ERROR,"this module must be in the preload_library in postgres.conf");
		return;
	}


    MemSet(&worker, 0, sizeof(BackgroundWorker));
    worker.bgw_flags = BGWORKER_BACKEND_DATABASE_CONNECTION | BGWORKER_SHMEM_ACCESS;
    worker.bgw_start_time = BgWorkerStart_ConsistentState;
    strcpy(worker.bgw_library_name, "pg_rest");
    strcpy(worker.bgw_function_name, "pg_rest_background");
	
	sprintf(worker.bgw_name,"pg_rest HTTP server:%d", DEFAULT_PORT);
    strcpy(worker.bgw_type, "pg_rest_initializer");
    if (process_shared_preload_libraries_in_progress)
    {
        RegisterBackgroundWorker(&worker);
    }

	elog(WARNING, "process_shmem_requests_in_progress=%d", process_shmem_requests_in_progress);
}

/*
* this part is never called 
* only for future use
*/
void
_PG_fini(void)
{
	elog(LOG,"stop http Server");
}
