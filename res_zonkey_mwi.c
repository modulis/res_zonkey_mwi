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
#include "asterisk/config_options.h"
#include "asterisk/cli.h"
#include "asterisk/event.h"
#include "asterisk/strings.h"
#include "asterisk/netsock2.h"
#include "asterisk/utils.h"

#ifndef AST_MODULE
#define AST_MODULE        "res_zonkey_mwi"
#endif

#define REALTIME_FAMILY   "zonkeymwi"
#define LEN_MWI_USER      32
#define LEN_MWI_DOMAIN    128
#define LEN_MWI_TOTAG     256
#define LEN_MWI_FROMTAG   256
#define LEN_MWI_CALLID    256
#define LEN_MWI_SIPMSG    4096                  // same length chan_sip.c uses
#define DEFAULT_USERAGENT "Asterisk"            // default User-Agent value if not defined in config file
#define DEFAULT_CONTACTUSER "asterisk"          // default user part of Contact header URI
#define DEFAULT_BINDUP    "127.0.0.1"           // default bind IP, used in Contact and Via header
#define DEFAULT_VMEXTEN   "*97"                 // default user part of Message-Account header

unsigned int realtime_enabled= 0;       // flag status of realtime configuration detected
struct ast_event_sub *mwi_sub = NULL;   // Subscribe to MWI event
 
/*! \brief The global options available for this module */
 struct global_options {
   /*! destination outbound proxy. Usualy OpenSIPS server. host:port */
   char proxy[128];
   /*! Bind IP to use in Contact and Via headers */
   char bindip[128];
   /*! User-Agent header value */
   char useragent[32];
   /*! user part of Contact header URI */
   char contactuser[32];
   /*! Message-Account body header user part of URI */
   char vmexten[32];
 };

/*! \brief Debug on/off */
static int debug=0;

/*! \brief All configuration objects for this module */
struct module_config {
  struct global_options *general; /*< Our global settings */
};

/*! \brief A container that holds our global module configuration */
static AO2_GLOBAL_OBJ_STATIC(module_configs);

/*! \brief A mapping of the module_config struct's general settings to the context
 *         in the configuration file that will populate its values */
static struct aco_type general_option = {
  .type = ACO_GLOBAL,
  .item_offset = offsetof(struct module_config, general),
  .category = "^general$",
  .category_match = ACO_WHITELIST,
};
 
/*! \brief A configuration file that will be processed for the module */
static struct aco_file module_conf = {
  .filename = "zonkeymwi.conf",
  .types = ACO_TYPES(&general_option),
};
 
static struct aco_type *general_options[] = ACO_TYPES(&general_option);

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

static void *module_config_alloc(void);
static void module_config_destructor(void *obj);
static void zonkey_mwi_cb(const struct ast_event *ast_event, void *data);
static char *handle_cli_zonkeymwi_status(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_zonkeymwi_show_subscription(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_zonkeymwi_notify(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_zonkeymwi_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_zonkeymwi_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static struct subscription *find_watcher(char *name, char *domain);
int send_notify(struct subscription *watcher, int msgnew, int msgold);
void notify_create(struct ast_str *msg, struct subscription *watcher, int new, int old);
static void log_module_values(void);

static struct ast_cli_entry cli_zonkeymwi[] = {
  AST_CLI_DEFINE(handle_cli_zonkeymwi_status,             "Show Zonkey MWI status"),
  AST_CLI_DEFINE(handle_cli_zonkeymwi_show_subscription,  "Show MWI subscription for user in domain"),
  AST_CLI_DEFINE(handle_cli_zonkeymwi_reload,             "Reload module configuration"),
  AST_CLI_DEFINE(handle_cli_zonkeymwi_notify,             "Send NOTIFY MWI to user in domain with defined messages number"),
  AST_CLI_DEFINE(handle_cli_zonkeymwi_debug,              "Debug NOTIFY packet on/off")
};

CONFIG_INFO_STANDARD(cfg_info, module_configs, module_config_alloc,
  .files = ACO_FILES(&module_conf),
);

/*!
 * \internal
 * \brief Load the Zonkey MWI module
 * \return void
 */
static int load_module(void)
{
  // subscribe to MWI event
  mwi_sub = ast_event_subscribe(AST_EVENT_MWI, zonkey_mwi_cb, "Zonkey MWI module", NULL, AST_EVENT_IE_END);
  // register CLI 
  ast_cli_register_multiple(cli_zonkeymwi, ARRAY_LEN(cli_zonkeymwi));
  // module configuration
  if (aco_info_init(&cfg_info)) {
    aco_info_destroy(&cfg_info);
    return AST_MODULE_LOAD_DECLINE;
  }
  aco_option_register(&cfg_info, "proxy", ACO_EXACT, general_options, NULL, OPT_CHAR_ARRAY_T, 0, CHARFLDSET(struct global_options, proxy));
  aco_option_register(&cfg_info, "bindip", ACO_EXACT, general_options, DEFAULT_BINDUP, OPT_CHAR_ARRAY_T, 0, CHARFLDSET(struct global_options, bindip));
  aco_option_register(&cfg_info, "useragent", ACO_EXACT, general_options, DEFAULT_USERAGENT, OPT_CHAR_ARRAY_T, 0, CHARFLDSET(struct global_options, useragent));
  aco_option_register(&cfg_info, "contactuser", ACO_EXACT, general_options, DEFAULT_CONTACTUSER, OPT_CHAR_ARRAY_T, 0, CHARFLDSET(struct global_options, contactuser));
  aco_option_register(&cfg_info, "vmexten", ACO_EXACT, general_options, DEFAULT_VMEXTEN, OPT_CHAR_ARRAY_T, 0, CHARFLDSET(struct global_options, vmexten));

  if (aco_process_config(&cfg_info, 0)) {
    aco_info_destroy(&cfg_info);
    return AST_MODULE_LOAD_DECLINE;
  }
  log_module_values();
  return AST_MODULE_LOAD_SUCCESS;
}

/*!
 * \internal
 * \brief Unload the Zonkey MWI module
 * \return void
 */
static int unload_module(void)
{
  if(mwi_sub){
    ast_event_unsubscribe(mwi_sub);
  }
  // unregister CLI
  ast_cli_unregister_multiple(cli_zonkeymwi, ARRAY_LEN(cli_zonkeymwi));
  // unload configuration
  aco_info_destroy(&cfg_info);

  return 0;
}

/*! \internal \brief reload handler
 * \retval AST_MODULE_LOAD_SUCCESS on success
 * \retval AST_MODULE_LOAD_DECLINE on failure
 */
 
static int reload_module(void)
{
  if (aco_process_config(&cfg_info, 1)) {
    return AST_MODULE_LOAD_DECLINE;
  }

  return 0;
}
  
/*!
 * \brief Callback function for MWI event
 * \param ast_event
 * \param data void pointer to ast_client structure
 * \return void
 */
static void zonkey_mwi_cb(const struct ast_event *ast_event, void *data)
{
  char user[LEN_MWI_USER];
  char domain[LEN_MWI_DOMAIN];
  unsigned int  msgnew = 0, msgold = 0;

  RAII_VAR(struct subscription *, watcher, NULL, ast_free);

  ast_log(LOG_DEBUG, "Voicemail event got. Zonkey is going to notify OpenSIPS\n");

  ast_copy_string(user, ast_event_get_ie_str(ast_event, AST_EVENT_IE_MAILBOX), sizeof(user));
  ast_copy_string(domain, ast_event_get_ie_str(ast_event, AST_EVENT_IE_CONTEXT), sizeof(domain));
  msgnew = ast_event_get_ie_uint(ast_event, AST_EVENT_IE_NEWMSGS);
  msgold = ast_event_get_ie_uint(ast_event, AST_EVENT_IE_OLDMSGS);

  ast_log(LOG_DEBUG, "Mailbox: %s; Context: %s; New messages: %d; Old messages: %d\n",
      user, domain, msgnew, msgold);
  if((watcher=find_watcher(user, domain)) == NULL){
    ast_log(LOG_ERROR, "No subscription found for %s@%s\n", user, domain);
    return;
  }
  if(send_notify(watcher, msgnew, msgold)){
    ast_log(LOG_DEBUG, "Successfully sent NOTIFY for %s@%s\n", user, domain);
  }else{
    ast_log(LOG_ERROR, "Failed to sent NOTIFY for %s@%s\n", user, domain);
  }
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
  char user[LEN_MWI_USER];
  char domain[LEN_MWI_DOMAIN];

  RAII_VAR(struct subscription *, watcher, NULL, ast_free);

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
  return CLI_SUCCESS;
}

/*!
 * \brief Debug on/off
 * \param ast_cli_entry
 * \param command
 * \param command arguments
 * \return char
 */
static char *handle_cli_zonkeymwi_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
  switch (cmd) {
  case CLI_INIT:
    e->command = "zonkeymwi debug";
    e->usage =
      "Usage: zonkeymwi debug on|off\n"
      "       Debug output on/off\n"
      "\n";
    return NULL;
  case CLI_GENERATE:
    return NULL;
  }
  if(a->argc != 3) {
    ast_cli(a->fd, "Wrong number of arguments.\n");
    return CLI_SHOWUSAGE;
  }
  if(ast_true(a->argv[2])){
    debug = 1;
    ast_cli(a->fd, "Debug enabled.\n");
  }else if(ast_false(a->argv[2])){
    debug = 0;
    ast_cli(a->fd, "Debug disabled.\n");
  }else{
    ast_cli(a->fd, "Unknown argument '%s'.\n", a->argv[2]);
    return CLI_SHOWUSAGE;
  }

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
  }

  return CLI_SUCCESS;
}

/*!
 * \brief Reload module configuration
 * \param ast_cli_entry
 * \param command
 * \param command arguments
 * \return char
 */
static char *handle_cli_zonkeymwi_reload(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
  switch (cmd) {
  case CLI_INIT:
    e->command = "zonkeymwi reload";
    e->usage =
      "Usage: zonkeymwi reload\n"
      "       Reload module configuration\n"
      "\n";
    return NULL;
  case CLI_GENERATE:
    return NULL;
  }

  if (aco_process_config(&cfg_info, 1) == ACO_PROCESS_ERROR) {
    ast_log(LOG_DEBUG, "Error while reloading module configuration");
    return CLI_FAILURE;
  }
  log_module_values();
  return CLI_SUCCESS;
}

/*!
 * \brief Send NOTIFY MWI event to given user@domain with given number of messages.
 * \param ast_cli_entry
 * \param command
 * \param command arguments
 * \return char
 */
static char *handle_cli_zonkeymwi_notify(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
  char user[LEN_MWI_USER];
  char domain[LEN_MWI_DOMAIN];
  int  msgnew = 0, msgold = 0;

  RAII_VAR(struct subscription *, watcher, NULL, ast_free);

  switch (cmd) {
  case CLI_INIT:
    e->command = "zonkeymwi notify";
    e->usage =
      "Usage: zonkeymwi notify <user> <domain> <msgnew> <msgold>\n"
      "       Notify MWI for subscription of <user> in <domain> with number of new messages <msgnum> and old messages <msgold>\n"
      "       To clear MWI just set <msgnum> to 0\n"
      "\n";
    return NULL;
  case CLI_GENERATE:
    return NULL;
  }
  if(a->argc != 6) {
    ast_cli(a->fd, "Wrong number of arguments.\n");
    return CLI_SHOWUSAGE;
  }
  
  ast_copy_string(user, a->argv[2], sizeof(user));
  ast_copy_string(domain, a->argv[3], sizeof(domain));
  msgnew = atoi(a->argv[4]);
  msgold = atoi(a->argv[5]);

  if((watcher=find_watcher(user, domain)) == NULL){
    ast_cli(a->fd, "Subscription NOT found for %s@%s\n",user, domain);
    return CLI_SUCCESS;
  }
  
  if(send_notify(watcher, msgnew, msgold)){
    ast_cli(a->fd, "Notify %s@%s with %d new messages and %d old messages was sent\n", user, domain, msgnew, msgold);
  }

  return CLI_SUCCESS;
}

/*!
 * \brief Generate and send SIP NOTIFY request
 * \param watcher struct
 * \param number of waiting messages
 * \return int
 */
int send_notify(struct subscription *watcher, int msgnew, int msgold)
{
  struct ast_str *msg = ast_str_create(LEN_MWI_SIPMSG);
  RAII_VAR(struct ast_sockaddr *, addr, NULL, ast_free);
  RAII_VAR(struct module_config *, cfg, ao2_global_obj_ref(module_configs), ao2_cleanup);
  int num_addrs = 0, sock = -1, res = 0;

  if (!(num_addrs = ast_sockaddr_resolve(&addr, cfg->general->proxy, PARSE_PORT_REQUIRE, AST_AF_UNSPEC))) {
    ast_log(LOG_ERROR, "Failed to create destination address from proxy %s. "
                "Make sure proxy parameter is a valid IP/Domain and Port\n",
                cfg->general->proxy);
    goto ensure;
  }
  if((sock = socket(addr->ss.ss_family, SOCK_DGRAM, 0)) == -1){
    ast_log(LOG_ERROR, "Failed to create socket. Give up here!");
    goto ensure;
  }
  notify_create(msg, watcher, msgnew, msgold);
  if(debug)
    ast_verb(0, "\nDEBUG------------------>\n%s\nDEBUG<------------------\n", ast_str_buffer(msg));

  if(ast_sendto(sock, ast_str_buffer(msg), ast_str_strlen(msg), 0, addr) == -1){
    ast_log(LOG_ERROR, "Failed to send notify!");
    goto ensure;
  }

  // everything is fine
  res = 1;

ensure:
  close(sock);
  ast_free(msg);
  return res;
}

/*!
 * \brief Create SIP NOTIFY message
 * \param message string
 * \param watcher struct
 * \param new messages
 * \param old messages
 * \return void
 */
void notify_create(struct ast_str *msg, struct subscription *watcher, int new, int old)
{
  RAII_VAR(struct module_config *, cfg, ao2_global_obj_ref(module_configs), ao2_cleanup);
  // Date field
  char date[256];
  struct tm tm;
  time_t t = time(NULL);
  gmtime_r(&t, &tm);
  strftime(date, sizeof(date), "%a, %d %b %Y %T GMT", &tm);

  // message body
  struct ast_str *body = ast_str_create(LEN_MWI_SIPMSG);

  ast_str_set(&body, 0, "Messages-Waiting: %s\r\n", new ? "yes": "no");
  ast_str_append(&body, 0, "Message-Account: sip:%s@%s\r\n", cfg->general->vmexten, watcher->domain);
  ast_str_append(&body, 0, "Voice-Message: %d/%d (%d/%d)\r\n", new, old, 0, 0);

  // NOTIFY message constructing
  ast_str_set(&msg, 0, "NOTIFY sip:%s@%s SIP/2.0\r\n", watcher->name, watcher->domain);
  ast_str_append(&msg, 0, "Via: SIP/2.0/UDP %s;branch=z9hG4bK%08lx\r\n", cfg->general->bindip, ast_random());
  ast_str_append(&msg, 0, "To: sip:%s@%s;tag=%s\r\n", watcher->name, watcher->domain, watcher->to_tag);
  ast_str_append(&msg, 0, "From: sip:%s@%s;tag=%s\r\n", watcher->name, watcher->domain, watcher->from_tag);
  ast_str_append(&msg, 0, "Date: %s\r\n", date);
  ast_str_append(&msg, 0, "Call-id: %s\r\n", watcher->callid);
  ast_str_append(&msg, 0, "CSeq: %d NOTIFY\r\n", watcher->cseq + 1);
  ast_str_append(&msg, 0, "Contact: <sip:%s@%s>\r\n", cfg->general->contactuser, cfg->general->bindip);
  ast_str_append(&msg, 0, "User-Agent: %s\r\n", cfg->general->useragent);
  ast_str_append(&msg, 0, "Event: message-summary\r\n");
  ast_str_append(&msg, 0, "Subscription-State: active\r\n");
  ast_str_append(&msg, 0, "Content-Type: application/simple-message-summary\r\n");
  ast_str_append(&msg, 0, "Content-Length: %zd\r\n", ast_str_strlen(body));
  ast_str_append(&msg, 0, "\r\n");
  ast_str_append(&msg, 0, "%s", ast_str_buffer(body));

  ast_free(body);
}

/*!
 * \brief CLI to display subscriber information
 * \param command arguments
 * \return subscription
 */
static struct subscription *find_watcher(char *name, char *domain)
{
  struct subscription *sub = malloc(sizeof(struct subscription));
  char *rec = NULL;
  struct ast_config *cfg;

  /* There can be more then one subscription for MWI in the 
   * table. When subscriber sends re-SUBSCRIBE for subscription
   * that will expire. Usualy 10 seconds before expire time.
   * So we need to select the latest subscription.
   *
   * So far I did not found how to select records with realtime
   * ordered by expire fild. That wy we browse them all and 
   * get the latest. It should not be a problem as usually 
   * there are maximum two message-summary records.
   */
  if (!(cfg = ast_load_realtime_multientry(REALTIME_FAMILY,
          "event", "message-summary",
          "watcher_username", name,
          "watcher_domain", domain, SENTINEL))){
    free(sub);
    return NULL;
  }

  // set initial expire
  sub->expires = 0;
  // browse records
  while ((rec = ast_category_browse(cfg, rec))) {
    struct ast_variable *var = NULL;
    struct subscription *tmp = malloc(sizeof(struct subscription));

    ast_copy_string(tmp->name, name, sizeof(tmp->name));
    ast_copy_string(tmp->domain, domain, sizeof(tmp->domain));
    for (var = ast_variable_browse(cfg, rec); var; var = var->next){
      if(!strcasecmp(var->name, "to_tag")){
        ast_copy_string(tmp->to_tag, var->value, sizeof(tmp->to_tag));
      }else if(!strcasecmp(var->name, "from_tag")) {
        ast_copy_string(tmp->from_tag, var->value, sizeof(tmp->from_tag));
      }else if(!strcasecmp(var->name, "callid")) {
        ast_copy_string(tmp->callid, var->value, sizeof(tmp->callid));
      }else if(!strcasecmp(var->name, "expires")) {
        tmp->expires = atoi(var->value);
      }else if(!strcasecmp(var->name, "local_cseq")) {
        tmp->cseq = atoi(var->value);
      }
    }
    // swap pointers if current expire timestamp is bigger then sub
    if(sub->expires < tmp->expires){
      *sub= *tmp;
    }
    ast_variables_destroy(var);
    free(tmp);
  }

  ast_config_destroy(cfg);
  return sub;
}

/*! Module configuration helper functions */

/*! \internal \brief Create a module_config object */
static void *module_config_alloc(void)
{
  struct module_config *cfg;

  if (!(cfg = ao2_alloc(sizeof(*cfg), module_config_destructor))) {
    return NULL;
  }
  if (!(cfg->general = ao2_alloc(sizeof(*cfg->general), NULL))) {
    ao2_ref(cfg, -1);
    return NULL;
  }

  return cfg;
}
 
/*! \internal \brief Dispose of a module_config object */
static void module_config_destructor(void *obj)
{
  struct module_config *cfg = obj;
  ao2_cleanup(cfg->general);
}
  
/*! \internal \brief Log the current module values */
static void log_module_values(void)
{
  RAII_VAR(struct module_config *, cfg, ao2_global_obj_ref(module_configs), ao2_cleanup);

  if (!cfg || !cfg->general) {
    ast_log(LOG_ERROR, "ERROR: Can not load configuration");
    return;
  }

  /* Assume that something will call this function */
  ast_log(LOG_DEBUG, "Module values: proxy=%s; bindip=%s, useragent=%s; contactuser=%s; vmexten=%s\n",
  cfg->general->proxy,
  cfg->general->bindip,
  cfg->general->useragent,
  cfg->general->contactuser,
  cfg->general->vmexten);
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Zonkey MWI module",
  .load = load_module,
  .unload = unload_module,
  .reload = reload_module,
  .load_pri = AST_MODPRI_DEFAULT,
);
