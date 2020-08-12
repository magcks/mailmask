/* 
 * Mailmask
 * 
 * Copyright (c) 2020, Max von Buelow
 * All rights reserved.
 * Contact: https://maxvonbuelow.de
 * 
 * This file is part of the MailMask project.
 * https://github.com/magcks/mailmask
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <mysql.h>

#define DRIVER_MYSQL 0
#define CONNINFO_STR_MAX (1024 * 4)

struct dbconninfo {
	int driver;
	char host[CONNINFO_STR_MAX], user[CONNINFO_STR_MAX], pass[CONNINFO_STR_MAX], dbname[CONNINFO_STR_MAX];
	char query_dom[CONNINFO_STR_MAX], query_get[CONNINFO_STR_MAX], query_ins[CONNINFO_STR_MAX], query_del[CONNINFO_STR_MAX];
};
void dbinfo_defaults(struct dbconninfo *inf)
{
	inf->driver = -1;
	inf->host[0] = '\0';
	inf->user[0] = '\0';
	inf->pass[0] = '\0';
	inf->dbname[0] = '\0';
	strcpy(inf->query_dom, "SELECT 1 FROM privacy_domains WHERE domain LIKE ? LIMIT 1");
	strcpy(inf->query_get, "SELECT destination, expiration FROM privacy_forwardings WHERE source LIKE ? LIMIT 1");
	strcpy(inf->query_ins, "INSERT INTO privacy_forwardings (source, destination, expiration) VALUES (?, ?, ?)");
	strcpy(inf->query_del, "DELETE FROM privacy_forwardings WHERE source LIKE ? AND destination LIKE ?");
}

struct dbh
{
	int driver;
	pthread_mutex_t lock;
	MYSQL my;
	MYSQL_STMT *stmt_dom, *stmt_get, *stmt_ins, *stmt_del;
};

struct forwarding
{
	char source[512];
	char destination[512];
	uint64_t expiration;
};

int db_connect(struct dbh *db, const struct dbconninfo *inf)
{
	db->driver = inf->driver;

	if (db->driver == DRIVER_MYSQL) {
		mysql_init(&db->my);

		if (mysql_real_connect(&db->my, inf->host, inf->user, inf->pass, inf->dbname, 0, NULL, 0) == NULL) return -1;

		my_bool reconnect = 1;
		mysql_options(&db->my, MYSQL_OPT_RECONNECT, &reconnect);

		db->stmt_dom = mysql_stmt_init(&db->my);
		db->stmt_get = mysql_stmt_init(&db->my);
		db->stmt_ins = mysql_stmt_init(&db->my);
		db->stmt_del = mysql_stmt_init(&db->my);

		mysql_stmt_prepare(db->stmt_dom, inf->query_dom, strlen(inf->query_dom));
		mysql_stmt_prepare(db->stmt_get, inf->query_get, strlen(inf->query_get));
		mysql_stmt_prepare(db->stmt_ins, inf->query_ins, strlen(inf->query_ins));
		mysql_stmt_prepare(db->stmt_del, inf->query_del, strlen(inf->query_del));

		pthread_mutex_init(&db->lock, NULL);
	}

	return 0;
}
void db_close(struct dbh *db)
{
	pthread_mutex_destroy(&db->lock);

	if (db->driver == DRIVER_MYSQL) {
		mysql_stmt_close(db->stmt_dom);
		mysql_stmt_close(db->stmt_get);
		mysql_stmt_close(db->stmt_ins);
		mysql_stmt_close(db->stmt_del);
		mysql_close(&db->my);
	}
}
int db_check_domain(struct dbh *db, char *domain)
{
	pthread_mutex_lock(&db->lock);

	int res = -1;
	if (db->driver == DRIVER_MYSQL) {
		mysql_ping(&db->my);
		MYSQL_BIND bind_in[1];
		MYSQL_BIND bind_out[1];
		memset(bind_in, 0, sizeof(bind_in));
		memset(bind_out, 0, sizeof(bind_out));
		bind_in[0].buffer_type = MYSQL_TYPE_STRING;
		bind_in[0].buffer = domain;
		bind_in[0].buffer_length = strlen(domain);

		uint32_t buf;
		bind_out[0].buffer_type = MYSQL_TYPE_LONG;
		bind_out[0].buffer = (char*)&buf;
		bind_out[0].buffer_length = 4;

		mysql_stmt_bind_param(db->stmt_dom, bind_in);
		mysql_stmt_execute(db->stmt_dom);
		mysql_stmt_bind_result(db->stmt_dom, bind_out);
		int status;
		int cnt = 0;
		do {
			status = mysql_stmt_fetch(db->stmt_dom);
			if (status == 1 || status == MYSQL_NO_DATA) break;
			++cnt;
		} while (1);
		res = cnt == 0 ? -1 : 0;
	}
	pthread_mutex_unlock(&db->lock);
	return res;
}
int db_get_forwarding(struct dbh *db, struct forwarding *fwd)
{
	pthread_mutex_lock(&db->lock);

	int res = -1;
	if (db->driver == DRIVER_MYSQL) {
		mysql_ping(&db->my);
		MYSQL_BIND bind_in[1];
		MYSQL_BIND bind_out[2];
		memset(bind_in, 0, sizeof(bind_in));
		memset(bind_out, 0, sizeof(bind_out));
		bind_in[0].buffer_type = MYSQL_TYPE_STRING;
		bind_in[0].buffer = fwd->source;
		bind_in[0].buffer_length = strlen(fwd->source);

		long unsigned int strlen = 0;
		bind_out[0].buffer_type = MYSQL_TYPE_STRING;
		bind_out[0].buffer = fwd->destination;
		bind_out[0].buffer_length = 512;
		bind_out[0].length = &strlen;
		bind_out[1].buffer_type = MYSQL_TYPE_LONGLONG;
		bind_out[1].buffer = (char*)&fwd->expiration;
		bind_out[1].buffer_length = 8;

		mysql_stmt_bind_param(db->stmt_get, bind_in);
		mysql_stmt_execute(db->stmt_get);
		mysql_stmt_bind_result(db->stmt_get, bind_out);
		int status;
		int cnt = 0;
		do {
			status = mysql_stmt_fetch(db->stmt_get);
			if (status == 1 || status == MYSQL_NO_DATA) break;
			fwd->destination[strlen] = '\0';
			++cnt;
		} while (1);
		res = cnt == 0 ? -1 : 0;
	}
	pthread_mutex_unlock(&db->lock);
	return res;
}
int db_ins_forwarding(struct dbh *db, struct forwarding *fwd)
{
	int res = -1;
	pthread_mutex_lock(&db->lock);
	if (db->driver == DRIVER_MYSQL) {
		mysql_ping(&db->my);
		MYSQL_BIND bind_in[3];
		memset(bind_in, 0, sizeof(bind_in));
		bind_in[0].buffer_type = MYSQL_TYPE_STRING;
		bind_in[0].buffer = fwd->source;
		bind_in[0].buffer_length = strlen(fwd->source);
		bind_in[1].buffer_type = MYSQL_TYPE_STRING;
		bind_in[1].buffer = fwd->destination;
		bind_in[1].buffer_length = strlen(fwd->destination);
		bind_in[2].buffer_type = MYSQL_TYPE_LONGLONG;
		bind_in[2].buffer = (char*)&fwd->expiration;
		bind_in[2].buffer_length = 8;

		mysql_stmt_bind_param(db->stmt_ins, bind_in);
		mysql_stmt_execute(db->stmt_ins);
		res = mysql_stmt_affected_rows(db->stmt_ins) == 1 ? 0 : -1;
	}
	pthread_mutex_unlock(&db->lock);
	return res;
}
int db_del_forwarding(struct dbh *db, struct forwarding *fwd)
{
	int res = -1;
	pthread_mutex_lock(&db->lock);
	if (db->driver == DRIVER_MYSQL) {
		mysql_ping(&db->my);
		MYSQL_BIND bind_in[2];
		memset(bind_in, 0, sizeof(bind_in));
		bind_in[0].buffer_type = MYSQL_TYPE_STRING;
		bind_in[0].buffer = fwd->source;
		bind_in[0].buffer_length = strlen(fwd->source);
		bind_in[1].buffer_type = MYSQL_TYPE_STRING;
		bind_in[1].buffer = fwd->destination;
		bind_in[1].buffer_length = strlen(fwd->destination);

		mysql_stmt_bind_param(db->stmt_del, bind_in);
		mysql_stmt_execute(db->stmt_del);
		res = mysql_stmt_affected_rows(db->stmt_del) == 1 ? 0 : -1;
	}
	pthread_mutex_unlock(&db->lock);
	return res;
}
