/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (c) 2008, Digium, Inc.
 *
 * Zonkey VoIP platform. MWI module
 * Copyright (c) 2013, Modulis.ca Inc.
 *
 * Stas Kobzar <stas.kobzar@modulis.ca>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief zonkey_mwi MWI module
 *
 * \author Stas Kobzar <stas.kobzar@modulis.ca>
 *
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: $")

#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/config.h"
#include "asterisk/cli.h"
#include "asterisk/event.h"

#ifndef AST_MODULE
#define AST_MODULE "res_zonkey_mwi"
#endif

#define REALTIME_FAMILY "zonkeymwi"
#define LEN_MWI_USER 32
#define LEN_MWI_DOMAIN 128
#define LEN_MWI_TOTAG 256
#define LEN_MWI_FROMTAG 256
#define LEN_MWI_CALLID 256

unsigned int realtime_enabled= 0;       // flag status of realtime configuration detected
struct ast_event_sub *mwi_sub = NULL;   // Subscribe to MWI event
/*! \brief Active MWI subscriber data */
struct subscription {
  /*! User name */
  char name[LEN_MWI_USER];
  /*! User domain */
  char domain[LEN_MWI_DOMAIN];
  /*! To tag from subscribe dialog */
  char to_tag[LEN_MWI_TOTAG];
  /*! From tag from subscribe dialog */
  char from_tag[LEN_MWI_FROMTAG];
  /*! Call-ID from subscribe dialog */
  char callid[LEN_MWI_CALLID];
  /*! MWI subscribsion expires */
  unsigned int expires; 
  /*! CSeq number */
  unsigned int cseq;
};

static void zonkey_mwi_cb(const struct ast_event *ast_event, void *data);
static char *handle_cli_zonkeymwi_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_zonkeymwi_show_subscription(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static struct subscription *find_watcher(char *name, char *domain);

static char show_mwi(int fd);

static struct ast_cli_entry cli_zonkeymwi[] = {
  AST_CLI_DEFINE(handle_cli_zonkeymwi_status,       "Show Zonkey MWI status"),
  AST_CLI_DEFINE(handle_cli_zonkeymwi_show_subscription,       "Show MWI subscription for user in domain")
};

/*!
 * \internal
 * \brief Load the Zonkey MWI module
 * \return void
 */
static int load_module(void)
{
  int res = 0;
  // subscribe to MWI event
  mwi_sub = ast_event_subscribe(AST_EVENT_MWI, zonkey_mwi_cb, "Zonkey MWI module", NULL, AST_EVENT_IE_END);
  // register CLI 
  ast_cli_register_multiple(cli_zonkeymwi, ARRAY_LEN(cli_zonkeymwi));
  return res;
}

/*!
 * \internal
 * \brief Unload the Zonkey MWI module
 * \return void
 */
static int unload_module(void)
{
  int res = 0;
  if(mwi_sub){
    ast_event_unsubscribe(mwi_sub);
  }
  // unregister CLI
  ast_cli_unregister_multiple(cli_zonkeymwi, ARRAY_LEN(cli_zonkeymwi));

  return res;
}

/*!
 * \brief Callback function for MWI event
 * \param ast_event
 * \param data void pointer to ast_client structure
 * \return void
 */
static void zonkey_mwi_cb(const struct ast_event *ast_event, void *data)
{
  const char *mailbox;
  const char *context;
  char oldmsgs[10];
  char newmsgs[10];

  ast_log(LOG_DEBUG, "Voicemail event got. Zonkey is going to notify OpenSIPS\n");

  mailbox = ast_event_get_ie_str(ast_event, AST_EVENT_IE_MAILBOX);
  context = ast_event_get_ie_str(ast_event, AST_EVENT_IE_CONTEXT);
  snprintf(newmsgs, sizeof(newmsgs), "%d", ast_event_get_ie_uint(ast_event, AST_EVENT_IE_NEWMSGS));
  snprintf(oldmsgs, sizeof(oldmsgs), "%d", ast_event_get_ie_uint(ast_event, AST_EVENT_IE_OLDMSGS));

  ast_log(LOG_DEBUG, "MWI DATA:\nMailbox: %s\nContext: %s\nNew messages: %s\nOld messages: %s\n",
      mailbox, context, newmsgs, oldmsgs);
}

/*!
 * \brief CLI zonkeymwi show subscription for user in domain
 * \param ast_cli_entry
 * \param command
 * \param command arguments
 * \return char
 */
static char *handle_cli_zonkeymwi_show_subscription(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
  struct subscription *watcher;
  char user[32];
  char domain[256];

  switch (cmd) {
  case CLI_INIT:
    e->command = "zonkeymwi show subscription";
    e->usage =
      "Usage: zonkeymwi show subscription <user> <domain>\n"
      "       Print subscription information for <user> in <domain>\n"
      "\n";
    return NULL;
  case CLI_GENERATE:
    return NULL;
  }

  if(a->argc != 5) {
    ast_cli(a->fd, "You did not provide user and domain.\n");
    return CLI_SHOWUSAGE;
  }

  ast_copy_string(user, a->argv[3], sizeof(user));
  ast_copy_string(domain, a->argv[4], sizeof(domain));

  if((watcher=find_watcher(user, domain)) != NULL){
    ast_cli(a->fd, "MWI subscription details for %s@%s:\n", watcher->name, watcher->domain);
    ast_cli(a->fd, "  To tag:   %s\n", watcher->to_tag);
    ast_cli(a->fd, "  From tag: %s\n", watcher->from_tag);
    ast_cli(a->fd, "  Call-ID:  %s\n", watcher->callid);
    ast_cli(a->fd, "  Expires:  %d\n", watcher->expires);
    ast_cli(a->fd, "  CSeq:     %d\n", watcher->cseq);
    ast_cli(a->fd, "\n");
  }else{
    ast_cli(a->fd, "   Currently no valid MWI subscription found for %s@%s\n",user,domain);
  }
  free(watcher);
  return CLI_SUCCESS;
}

/*!
 * \brief CLI zonkeymwi status
 * \param ast_cli_entry
 * \param command
 * \param command arguments
 * \return char
 */
static char *handle_cli_zonkeymwi_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
  switch (cmd) {
  case CLI_INIT:
    e->command = "zonkeymwi status";
    e->usage =
      "Usage: zonkeymwi status\n"
      "       Print module status\n"
      "\n";
    return NULL;
  case CLI_GENERATE:
    return NULL;
  }

  realtime_enabled = ast_check_realtime(REALTIME_FAMILY);
  ast_cli(a->fd, "Module %s\n", realtime_enabled ? "ENABLED" : "DISABLED (Realtime not configured)");
  if(!realtime_enabled) {
    ast_cli(a->fd, "    To enable module configure realtime family zonkey and driver\n");
    ast_cli(a->fd, "    For example: zonkeymwi => odbc,opensips,active_watchers\n");
  }else{
    return show_mwi(a->fd);
  }

  return CLI_SUCCESS;
}

/*!
 * \brief CLI to display subscriber information
 * \param command arguments
 * \return subscription
 */
static struct subscription *find_watcher(char *name, char *domain)
{
  struct subscription *sub = malloc(sizeof(struct subscription));
  const char tmp[] = "aaa";
  ast_copy_string(sub->name, name, sizeof(sub->name));
  ast_copy_string(sub->domain, domain, sizeof(sub->domain));
  ast_copy_string(sub->to_tag, tmp, sizeof(sub->to_tag));
  ast_copy_string(sub->from_tag, tmp, sizeof(sub->from_tag));
  ast_copy_string(sub->callid, tmp, sizeof(sub->callid));
  sub->expires = 1213;
  sub->cseq = 12;

  return sub;
}

static char show_mwi(int fd)
{
  struct ast_variable *var, *el =  NULL;

  if (!(var = ast_load_realtime(REALTIME_FAMILY,"event","message-summary", "expires DESC",SENTINEL))){
    ast_cli(fd, "\n====> Failed ast_load_realtime\n");
    return CLI_FAILURE;
  }
  ast_cli(fd, "\n================= Presence ==================\n");
  for(el = var; el; el=el->next){
    ast_cli(fd, "=== ==> %s: %s\n", el->name, el->value);
  }
  ast_variables_destroy(var);
  ast_variables_destroy(el);
  return CLI_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Zonkey MWI module",
    .load = load_module,
    .unload = unload_module
  );
