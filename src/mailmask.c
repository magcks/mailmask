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

#include "db.h"

#include <libmilter/mfapi.h>
#include <libmilter/mfdef.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <stdint.h>
#include <libconfig.h>

struct dbh db;

struct envToLinkedList {
	int pos_at, pos_plus;
	int domain_check;
	struct forwarding fwd;
	struct envToLinkedList *next;
};

struct mlfiPriv {
	char env_from[512];
	char replyto[512];
	struct envToLinkedList *env_to_first;
	struct envToLinkedList *env_to_cur;
	int reject;
};

void mlfi_priv_init(struct mlfiPriv *priv)
{
	priv->env_from[0] = '\0';
	priv->replyto[0] = '\0';
	priv->env_to_first = NULL;
	priv->env_to_cur = NULL;
}

// Function to extract addresses from the header/envelope fields.  If the field
// contains a < with a subsequent >, the inner part is used. If not, the whole
// header field is used. This allows matching "Max Mustermann
// <max.mustermann@example.invalid>".
char *parse_address(char *address, size_t *len)
{
	while (*address == ' ' || *address == '\t') ++address;
	size_t inlen = strlen(address);
	size_t pos_open = SIZE_MAX, pos_close = SIZE_MAX;
	size_t i;
	for (i = 0; i < inlen; ++i) {
		if (address[i] == '<') pos_open = i;
		else if (address[i] == '>' && pos_open != SIZE_MAX) pos_close = i;
		else if (address[i] == ',') inlen = i;
	}
	// trim
	if (pos_open != SIZE_MAX) while (address[pos_open + 1] == ' ' || address[pos_open + 1] == '\t') ++pos_open;
	if (pos_close != SIZE_MAX) while (address[pos_close - 1] == ' ' || address[pos_close - 1] == '\t') --pos_close;
	if (inlen) while (address[inlen - 1] == ' ' || address[inlen - 1] == '\t') --inlen;

	if (pos_open != SIZE_MAX && pos_close != SIZE_MAX && pos_open < pos_close) {
		*len = pos_close - pos_open - 1;
		return address + pos_open + 1;
	} else {
		*len = inlen;
		return address;
	}
}

#define MLFIPRIV ((struct mlfiPriv*)smfi_getpriv(ctx))

static unsigned long mta_caps = 0;

void mlfi_cleanup(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;

	if (priv == NULL) return;

	struct envToLinkedList *cur = priv->env_to_first, *last;
	while (cur != NULL) {
		last = cur;
		cur = cur->next;
		free(last);
	}

	free(priv);
	smfi_setpriv(ctx, NULL);
}

sfsistat mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	struct mlfiPriv *priv;

	// Allocate some private memory.
	priv = MLFIPRIV;
	if (priv == NULL) {
		priv = calloc(1, sizeof(*priv));
		mlfi_priv_init(priv);
		if (priv == NULL) {
			goto fail;
		}
		smfi_setpriv(ctx, priv);
	}

	size_t len;
	const char *from = parse_address(*envfrom, &len);
	strncpy(priv->env_from, from, len);
	priv->env_from[len] = 0;

	return SMFIS_CONTINUE;
fail:
	return SMFIS_TEMPFAIL;
}


sfsistat mlfi_envto(SMFICTX *ctx, char **envto)
{
	struct mlfiPriv *priv;

	// Allocate some private memory.
	priv = MLFIPRIV;
	if (priv == NULL) {
		priv = calloc(1, sizeof(*priv));
		mlfi_priv_init(priv);
		if (priv == NULL) {
			goto fail;
		}
		smfi_setpriv(ctx, priv);
	}

	size_t len;
	char *to = parse_address(*envto, &len);

	// search for last @ and first +
	int at = -1;
	int plus = -1;
	for (int i = 0; i < len; ++i) {
		if (to[i] == '@') {
			at = i;
		}
		if (to[i] == '+' && plus == -1) {
			plus = i;
		}
	}
	if (at == -1) goto cont;

	struct envToLinkedList *cur;
	if (priv->env_to_first == NULL) {
		cur = priv->env_to_cur = priv->env_to_first = calloc(1, sizeof(*priv->env_to_first));
	} else {
		cur = calloc(1, sizeof(*priv->env_to_first));
		priv->env_to_cur->next = cur;
		priv->env_to_cur = cur;
	}
	if (cur == NULL) {
		goto fail;
	}
	cur->next = NULL;

	strncpy(cur->fwd.source, to, len);
	cur->fwd.source[len] = 0;
	cur->pos_at = at;
	cur->pos_plus = plus;
	cur->domain_check = db_check_domain(&db, cur->fwd.source + at + 1) == 0;
	if (plus == -1) db_get_forwarding(&db, &cur->fwd);

cont:
	return SMFIS_CONTINUE;
fail:
	return SMFIS_TEMPFAIL;
}

sfsistat mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	struct mlfiPriv *priv;
	priv = MLFIPRIV;
	if (priv == NULL) {
		priv = calloc(1, sizeof(*priv));
		mlfi_priv_init(priv);
		if (priv == NULL) {
			goto fail;
		}
		smfi_setpriv(ctx, priv);
	}

	if (strcasecmp(headerf, "from") == 0) {
		size_t len = 0;
		const char *replyto = parse_address(headerv, &len);

		strncpy(priv->replyto, replyto, len);
	} else if (strcasecmp(headerf, "reply-to") == 0 && !*priv->replyto) {
		size_t len = 0;
		const char *replyto = parse_address(headerv, &len);

		strncpy(priv->replyto, replyto, len);
	}

	return ((mta_caps & SMFIP_NR_HDR) != 0) ? SMFIS_NOREPLY : SMFIS_CONTINUE;
fail:
	return SMFIS_TEMPFAIL;
}

int decode_reply(const char *to, char *out_from, char *out_to)
{
	int state = 0;
	for (int i = 0; to[i]; ++i) {
		switch (state) {
		// user part to
		case 0:
			if (to[i] == '+') {
				state = 1;
			} else if (to[i] == '@') {
				goto fail;
			} else {
				*out_to = to[i];
				++out_to;
			}
			break;
		case 1:
			if (to[i] == '+') {
				*out_to = to[i];
				++out_to;
				state = 0;
			} else if (to[i] == '@') {
				goto fail;
			} else {
				*out_to = '@';
				++out_to;
				*out_from = to[i];
				++out_from;
				state = 2;
			}
			break;

		// user part from
		case 2:
			if (to[i] == '+') {
				state = 3;
			} else if (to[i] == '@') {
				goto fail;
			} else {
				*out_from = to[i];
				++out_from;
			}
			break;
		case 3:
			if (to[i] == '+') {
				*out_from = to[i];
				++out_from;
				state = 2;
			} else if (to[i] == '@') {
				goto fail;
			} else {
				*out_from = '@';
				++out_from;
				*out_from = to[i];
				++out_from;
				state = 4;
			}
			break;

		// domain part from
		case 4:
			if (to[i] == '@') {
				state = 5;
			} else {
				*out_from = to[i];
				++out_from;
			}
			break;


		case 5:
			*out_to = to[i];
			++out_to;
			break;
		}
	}
	*out_from = '\0';
	*out_to = '\0';
	return 0;
fail:
	return -1;
}
#define CHECK_OUTI if (outi == 64) return -1;
int encode_reply(const char *from, const char *to, char *out)
{
	int outi = 0;
	while (*to && *to != '@') {
		out[outi++] = *to; CHECK_OUTI
		++to;
	}
	out[outi++] = '+';

	while (*from) {
		if (*from == '@') {
			out[outi++] = '+'; CHECK_OUTI
			++from;
			continue;
		}
		if (*from == '+') {
			out[outi++] = '+'; CHECK_OUTI
		}
		out[outi++] = *from; CHECK_OUTI
		++from;
	}
	while (*to) {
		out[outi++] = *to;
		++to;
	}
	out[outi++] = '\0';
	return 0;
}

sfsistat mlfi_eom(SMFICTX *ctx)
{
	int is_auth = smfi_getsymval(ctx, "{auth_type}") ? 1 : 0;
	struct mlfiPriv *priv = MLFIPRIV;
	int status;
	// search for +commands
	if (is_auth) {
		for (struct envToLinkedList *cur = priv->env_to_first; cur != NULL; cur = cur->next) {
			printf("Current recipient: %s\n", cur->fwd.source);
			if (!cur->domain_check) continue;
			if (cur->pos_plus == -1 && !*cur->fwd.destination) {
				strcpy(cur->fwd.destination, priv->env_from);
				cur->fwd.expiration = 0;
				status = db_ins_forwarding(&db, &cur->fwd);
				if (status != 0) smfi_setreply(ctx, "550", "5.7.1", "Insert unsuccessful");
				goto reject;
			} else if (cur->fwd.source[cur->pos_plus + 1] == 'd' && cur->pos_plus + 2 == cur->pos_at) {
				struct forwarding fwd;
				strcpy(stpncpy(fwd.source, cur->fwd.source, cur->pos_plus), cur->fwd.source + cur->pos_at);
				strcpy(fwd.destination, priv->env_from);
				printf("Delete forwarding %s %s\n", fwd.source, fwd.destination);
				status = db_del_forwarding(&db, &fwd);
				if (status != 0) smfi_setreply(ctx, "550", "5.7.1", "Forwarding not found");
				goto reject;
			} else {
				// decode reply
				char out_from[512], out_to[512];
				if (decode_reply(cur->fwd.source, out_from, out_to) != 0) continue;

				// delete all recipients
				for (struct envToLinkedList *cur = priv->env_to_first; cur != NULL; cur = cur->next) {
					smfi_delrcpt(ctx, cur->fwd.source);
				}

				printf("Parsed addresses: Original sender: %s, Original recipient: %s\n", out_from, out_to);
				smfi_addrcpt(ctx, out_from);
				smfi_chgfrom(ctx, out_to, NULL);
				smfi_chgheader(ctx, "From", 1, out_to);
				smfi_chgheader(ctx, "To", 1, out_from);

				// Anonymize
				smfi_chgheader(ctx, "Cc", 1, NULL);
				smfi_chgheader(ctx, "Bcc", 1, NULL);
				smfi_chgheader(ctx, "Reply-To", 1, NULL);
				smfi_chgheader(ctx, "Autocrypt", 1, NULL);
				smfi_chgheader(ctx, "Message-ID", 1, NULL);
				goto cont;
			}
		}
	}

	// handle forwardings
	for (struct envToLinkedList *cur = priv->env_to_first; cur != NULL; cur = cur->next) {
		printf("Current recipient: %s\n", cur->fwd.source);
		if (!cur->domain_check) continue;
		if (!*cur->fwd.destination) continue;

		char new_from[512];
		encode_reply(*priv->replyto ? priv->replyto : priv->env_from, cur->fwd.source, new_from);
		smfi_delrcpt(ctx, cur->fwd.source);
		smfi_addrcpt(ctx, cur->fwd.destination);
		smfi_chgheader(ctx, "Reply-To", 1, new_from);

		printf("Forward to %s with Reply-To: %s\n", cur->fwd.destination, new_from);
	}

cont:
	mlfi_cleanup(ctx);
	return SMFIS_CONTINUE;
reject:
	mlfi_cleanup(ctx);
	return status == 0 ? SMFIS_DISCARD : SMFIS_REJECT;
}


sfsistat mlfi_abort(SMFICTX *ctx)
{
	mlfi_cleanup(ctx);
	return SMFIS_CONTINUE;
}

sfsistat mlfi_negotiate(SMFICTX *ctx, unsigned long f0, unsigned long f1, unsigned long f2, unsigned long f3, unsigned long *pf0, unsigned long *pf1, unsigned long *pf2, unsigned long *pf3)
{
	*pf0 = 0;
	/* milter protocol steps: all but connect, HELO */
	*pf1 = SMFIP_NOCONNECT | SMFIP_NOHELO;
	mta_caps = f1;
	if ((mta_caps & SMFIP_NR_HDR) != 0) *pf1 |= SMFIP_NR_HDR;
	*pf2 = 0;
	*pf3 = 0;
	return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
{
	"MilterMask",     /* filter name */
	SMFI_VERSION,        /* version code -- do not change */
	SMFIF_ADDHDRS | SMFIF_CHGHDRS | SMFIF_CHGFROM | SMFIF_ADDRCPT | SMFIF_DELRCPT,                   /* flags */
	NULL,                /* connection info filter */
	NULL,                /* SMTP HELO command filter */
	mlfi_envfrom,        /* envelope sender filter */
	mlfi_envto,          /* envelope recipient filter */
	mlfi_header,         /* header filter */
	NULL,                /* end of header */
	NULL,                /* body block filter */
	mlfi_eom,            /* end of message */
	mlfi_abort,          /* message aborted */
	NULL,                /* connection cleanup */
	NULL,                /* unknown/unimplemented SMTP commands */
	NULL,                /* DATA command filter */
// 	mlfi_negotiate       /* option negotiation at connection startup */
};

uid_t get_uid(const char *name)
{
    struct passwd *pwd = getpwnam(name);
    return pwd == NULL ? -1 : pwd->pw_uid;
}
gid_t get_gid(const char *name)
{
    struct group *grp = getgrnam(name);
    return grp == NULL ? -1 : grp->gr_gid;
}

int enumerate(const char *name, const char **names, size_t n)
{
	for (int i = 0; i < n; ++i) {
		if (strcasecmp(name, names[i]) == 0) return i;
	}
	return -1;
}
void strmaxcpy(char *dst, const char *src, size_t max)
{
	int i;
	for (i = 0; i < max; ++i) {
		dst[i] = src[i];
		if (!src[i]) break;
	}
	dst[i] = '\0';
}
int parse_dbconf(struct dbconninfo *conninfo, const char *configfile)
{
	dbinfo_defaults(conninfo);
	config_t cfg;
	config_init(&cfg);
	if (!config_read_file(&cfg, configfile)) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}
	const char *drivers[] = { "mysql" };
	const char *str;
	if (!config_lookup_string(&cfg, "driver", &str) || (conninfo->driver = enumerate(str, drivers, sizeof(drivers) / sizeof(const char*))) == -1) {
		fprintf(stderr, "Invalid driver\n");
		config_destroy(&cfg);
		return -1;
	}

	if (conninfo->driver == DRIVER_MYSQL) {
		if (config_lookup_string(&cfg, "host", &str)) strmaxcpy(conninfo->host, str, CONNINFO_STR_MAX);
		if (config_lookup_string(&cfg, "user", &str)) strmaxcpy(conninfo->user, str, CONNINFO_STR_MAX);
		if (config_lookup_string(&cfg, "pass", &str)) strmaxcpy(conninfo->pass, str, CONNINFO_STR_MAX);
		if (config_lookup_string(&cfg, "dbname", &str)) strmaxcpy(conninfo->dbname, str, CONNINFO_STR_MAX);
	}
	if (config_lookup_string(&cfg, "query_dom_get", &str)) strmaxcpy(conninfo->query_dom, str, CONNINFO_STR_MAX);
	if (config_lookup_string(&cfg, "query_fwd_get", &str)) strmaxcpy(conninfo->query_get, str, CONNINFO_STR_MAX);
	if (config_lookup_string(&cfg, "query_fwd_ins", &str)) strmaxcpy(conninfo->query_ins, str, CONNINFO_STR_MAX);
	if (config_lookup_string(&cfg, "query_fwd_del", &str)) strmaxcpy(conninfo->query_del, str, CONNINFO_STR_MAX);
	config_destroy(&cfg);
	return 0;
}
int main(int argc, char **argv)
{
	int c, daemonize = 0;
	uid_t uid = -1; gid_t gid = -1;
	mode_t um = -1;
	char *pidfilename = NULL, *sockname = NULL, *configfile = NULL;
	FILE *pidfile = NULL;

	while ((c = getopt(argc, argv, "ds:c:p:u:g:m:")) != -1) {
		switch (c) {
		case 's':
			sockname = strdup(optarg);
			break;
		case 'c':
			configfile = strdup(optarg);
			break;
		case 'p':
			pidfilename = strdup(optarg);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'u':
			uid = get_uid(optarg);
			break;
		case 'g':
			gid = get_gid(optarg);
			break;
		case 'm':
			um = strtol(optarg, 0, 8);
			break;
		}
	}

	if (!sockname) {
		fprintf(stderr, "%s: Missing required -s argument\n", argv[0]);
		return EX_USAGE;
	}
	if (!configfile) {
		fprintf(stderr, "%s: Missing required -c argument\n", argv[0]);
		return EX_USAGE;
	}

	struct dbconninfo conninfo;
	if (parse_dbconf(&conninfo, configfile) != 0) {
		fprintf(stderr, "config file error");
		return EXIT_FAILURE;
	}

	if (db_connect(&db, &conninfo) != 0) {
		fprintf(stderr, "Cannot connect to DB\n");
		return EXIT_FAILURE;
	}

	if (pidfilename) {
		unlink(pidfilename);
		pidfile = fopen(pidfilename, "w");
		if (!pidfile) {
			fprintf(stderr, "Could not open pidfile: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
		free(pidfilename);
	}

	if (um != (mode_t)-1) umask(um);
	if (gid != (gid_t)-1) setgid(gid);
	if (uid != (uid_t)-1) setuid(uid);

	if (daemonize) {
		if (daemon(0, 0) == -1) {
			fprintf(stderr, "daemon() failed: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}
	if (pidfile) {
		fprintf(pidfile, "%ld\n", (long)getpid());
		fclose(pidfile);
	}

	struct stat junk;
	if (stat(sockname, &junk) == 0) unlink(sockname);
	smfi_setconn(sockname);
	free(sockname);

	if (smfi_register(smfilter) == MI_FAILURE) {
		fprintf(stderr, "smfi_register failed\n");
		return EX_UNAVAILABLE;
	}
	return smfi_main();
}
