module saslwrapped.sasl;

extern(C):

enum SASL_VERSION_MAJOR  = 2;
enum SASL_VERSION_MINOR  = 1;
enum SASL_VERSION_STEP   = 26;

enum SASL_CONTINUE = 1;
enum SASL_OK = 0;
enum SASL_FAIL = -1;
enum SASL_NOMEM = -2;
enum SASL_BUFOVER = -3;
enum SASL_NOMECH = -4;
enum SASL_BADPROT = -5;
enum SASL_NOTDONE = -6;
enum SASL_BADPARAM = -7;
enum SASL_TRYAGAIN = -8;
enum SASL_BADMAC = -9;
enum SASL_NOTINIT = -12;

enum SASL_INTERACT = 2;
enum SASL_BADSERV = -10;
enum SASL_WRONGMECH = -11;

enum SASL_BADAUGH = -13;
enum SASL_NOAUTHZ = -14;
enum SASL_TOOWAEK = -15;
enum SASL_ENCRYPT = -16;
enum SASL_TRANS = -17;

enum SASL_EXPIRED = -18;
enum SASL_DISABLED = -19;
enum SASL_NOUSER = -20;
enum SASL_BADVERS = -23;
enum SASL_UNAVAIL = -24;
enum SASL_NOVERIFY = -26;
enum SASL_PWLOCK = -21;
enum SASL_NOCHANGE = -22;
enum SASL_WEAKPASS = -27;
enum SASL_NOUSERPASS = -28;
enum SASL_NEED_OLD_PASSWD = -29;
enum SASL_CONSTRAINT_VIOLAT = -30;

enum SASL_BADBINDING = -32;
enum SASL_CONFIGERR = -100;

enum SASL_MECHNAMEMAX = 20;

import core.stdc.config;

import saslwrapped.prop;

version(Windows)
{
    struct iovec
    {
        c_long iov_len;
        char *iov_base;
    }
}
else version(Posix)
{
    import core.sys.posix.sys.uio;
}

struct sasl_conn_t;

struct sasl_secret_t
{
    c_ulong len;
    ubyte* data;
}

struct sasl_rand_t;

alias sasl_malloc_t = void* function(size_t) nothrow;
alias sasl_calloc_t = void* function(size_t, size_t) nothrow;
alias sasl_realloc_t = void* function(void*, size_t) nothrow;
alias sasl_free_t = void function(void*) nothrow;

void sasl_set_alloc(sasl_malloc_t, sasl_calloc_t, sasl_realloc_t, sasl_free_t);

alias sasl_mutex_alloc_t = void* function() nothrow;
alias sasl_mutex_lock_t = int function(void *mutex) nothrow;
alias sasl_mutex_unlock_t = int function(void *mutex) nothrow;
alias sasl_mutex_free_t = void function(void *mutex) nothrow;

void sasl_set_mutex(sasl_mutex_alloc_t, sasl_mutex_lock_t, sasl_mutex_unlock_t, sasl_mutex_free_t);

alias sasl_ssf_t = uint;

enum SASL_SUCCESS_DATA = 0x0004;
enum SASL_NEED_PROXY = 0x0008;
enum SASL_NEED_HTTP = 0x0010;

enum SASL_SEC_NOPLAINTEXT = 0x0001;
enum SASL_SEC_NOACTIVE = 0x0002;
enum SASL_SEC_NODICTIONARY = 0x0004;
enum SASL_SEC_FORWARD_SECRECY = 0x0008;
enum SASL_SEC_NOANONYMOUS = 0x0010;
enum SASL_SEC_PASS_CREDENTIALS = 0x0020;
enum SASL_SEC_MUTUAL_AUTH = 0x0040;
enum SASL_SEC_MAXIMUM = 0x00FF;

struct sasl_security_properties_t
{
    sasl_ssf_t min_ssf;
    sasl_ssf_t max_ssf;

    uint maxbufsize;
    uint security_flags;

    char **property_names;
    char **property_values;
}

alias sasl_callback_func = int function() nothrow;

struct sasl_callback
{
    c_ulong id;
    sasl_callback_func proc;
    void *context;
}

alias sasl_callback_t = sasl_callback;

enum SASL_CB_LIST_END = 0;

alias sasl_getopt_t = int function(void *context, char *plugin_name, char *option, char **result, uint *len) nothrow;

enum SASL_CB_GETOPT = 1;

enum SASL_LOG_NONE = 0;
enum SASL_LOG_ERR = 1;
enum SASL_LOG_FAIL = 2;
enum SASL_LOG_WARN = 3;
enum SASL_LOG_NOTE = 4;
enum SASL_LOG_DEBUG = 5;
enum SASL_LOG_TRACE = 6;
enum SASL_LOG_PASS = 7;

alias sasl_log_t = int function(void *context, int level, char *message) nothrow;

enum SASL_CB_LOG = 2;

alias sasl_getpath_t = int function(void *context, char **path) nothrow;

enum SASL_CB_GETPATH = 3;

enum sasl_verify_type_t
{
    SASL_VRFY_PLUGIN = 0,
    SASL_VRFY_CONF = 1,
    SASL_VRFY_PASSWD = 2,
    SASL_VRFY_OTHER = 3
}

alias sasl_verify_file_t = int function(void *context, char *file, sasl_verify_type_t type) nothrow;

enum SASL_CB_VERIFYFILE = 4;

alias sasl_getconfpath_t = int function(void *context, char **path) nothrow;

enum SASL_CB_GETCONFPATH = 5;

alias sasl_getsimple_t = int function(void *context, int id, char **result, uint *len) nothrow;

enum SASL_CB_USER = 0x4001;
enum SASL_CB_AUTHNAME = 0x4002;
enum SASL_CB_LANGUAGE = 0x4003;

enum SASL_CB_CNONCE = 0x4007;

alias sasl_getsecret_t = int function(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret) nothrow;

enum SASL_CB_PASS = 0x4004;

alias sasl_chalprompt_t = int function(void *context, int id, char *challenge, char *prompt, char *defresult, char **result, uint *len) nothrow;

enum SASL_CB_ECHOPROMPT = 0x4005;
enum SASL_CB_NOECHOPROMPT = 0x4006;

alias sasl_getrealm_t = int function(void *context, int id, char **availrealms, char **result) nothrow;

enum SASL_CB_GETREALM = 0x4008;

alias sasl_authorize_t = int function(sasl_conn_t *conn, void *context, char *requested_user, uint rlen, char *auth_identity, uint alen, char *def_realm, uint urlen, propctx *prop) nothrow;

enum SASL_CB_PROXY_POLICY = 0x8001;

alias sasl_server_userdb_checkpass_t = int function(sasl_conn_t *conn, void *context, char *user, char *pass, uint passlen, propctx *prop) nothrow;

enum SASL_CB_SERVER_USERDB_CHECKPASS = 0x8005;

alias sasl_server_userdb_setpass_t = int function(sasl_conn_t *conn, void *context, char *user, char *pass, uint passlen, propctx *prop, uint flags) nothrow;

enum SASL_CB_SERVER_USERDB_SETPASS = 0x8006;

enum SASL_CU_NONE = 0x00;
enum SASL_CU_AUTHID = 0x01;
enum SASL_CU_AUTHZID = 0x02;

enum SASL_CU_EXTERNALLY_VERIFIED = 0x04;

enum SASL_CU_OVERRIDE = 0x08;

enum SASL_CU_ASIS_MASK = 0xFFF0;
enum SASL_CU_VERIFY_AGAINST_HASH = 0x10;

alias sasl_cannon_user_t = int function(sasl_conn_t *conn, void *context, char *ins, uint inlen, uint flags, char *user_realm, char *outs, uint out_max, uint *out_len) nothrow;

enum SASL_CB_CANON_USER = 0x8007;

enum SASL_PATH_TYPE_PLUGIN = 0;
enum SASL_PATH_TYPE_CONFIG = 1;

int sasl_set_path(int path_type, char *path);

void sasl_version(char **implementation, int *versionl);

void sasl_version_info(char **implementation, char **version_string, int *version_major, int *version_minor, int *version_step, int *version_patch);

void sasl_done();

int sasl_server_done();

int sasl_client_done();

void sasl_dispose(sasl_conn_t **pconn);

char *sasl_errstring(int saslerr, char *langlist, char **outlang);

char *sasl_errdetail(sasl_conn_t *conn);

void sasl_seterror(sasl_conn_t *conn, uint flags, char *fmt, ...);

enum SASL_NOLOG = 0x01;

int sasl_getprop(sasl_conn_t *conn, int propnum, void **pvalue);

enum SASL_USERNAME = 0;
enum SASL_SSF = 1;
enum SASL_MAXOUTBUF = 2;
enum SASL_DEFUSERREALM = 3;
enum SASL_GETOPTCTX = 4;
enum SASL_CALLBACK = 7;
enum SASL_IPLOCALPORT = 8;
enum SASL_IPREMPTEPORT = 9;

enum SASL_PLUGERR = 10;

enum SASL_DELEGATEDCREDS = 11;
enum SASL_SERVICE = 12;
enum SASL_SERVERFQDN = 13;
enum SASL_AUTHSOURCE = 14;
enum SASL_MECHNAME = 15;
enum SASL_AUTHUSER = 16;
enum SASL_APNAME = 17;

enum SASL_GSS_CREDS = 18;

enum SASL_GSS_PEER_NAME = 19;
enum SASL_GSS_LOCAL_NAME = 20;

struct sasl_channel_binding
{
    char *name;
    int critical;
    c_ulong len;
    ubyte *data;
}

alias sasl_channel_binding_t = sasl_channel_binding;

enum SASL_CHANNEL_BINDING = 21;

struct sasl_http_request
{
    char *method;
    char *uri;
    ubyte *entity;
    c_ulong elen;
    uint non_persist;
}

alias sasl_http_request_t = sasl_http_request;

enum SASL_HTTP_REQUEST = 22;

int sasl_setprop(sasl_conn_t *conn, int propnum, void *value);

enum SASL_SSF_EXTERNAL = 100;
enum SASL_SEC_PROPS = 101;
enum SASL_AUTH_EXTERNAL = 102;

int sasl_idle(sasl_conn_t *conn);

struct sasl_interact
{
    c_ulong id;
    char *challenge;
    char *prompt;
    char *defresult;
    void *result;
    uint len;
}

alias sasl_interact_t = sasl_interact;

int sasl_client_init(sasl_callback *callbacks);

int sasl_client_new(char *service, char *serverFQDN, char *iplocalport, char *ipremote, sasl_callback *prompt_supp, uint flags, sasl_conn_t **pconn);

int sasl_client_start(sasl_conn_t *conn, char *mechlist, sasl_interact **prompt_need, char **clientout, uint *clientoutlen, char **mech);

int sasl_client_step(sasl_conn_t *conn, char *serverin, uint serverinlen, sasl_interact **prompt_need, char **clientout, uint *clientoutlen);

int sasl_server_init(sasl_callback *callbacks, char *appname);

int sasl_server_new(char *service, char *serverFQDN, char *user_realm, char *iplocalport, char *ipremoteport, sasl_callback *callbacks, uint flags, sasl_conn_t **pconn);

char **sasl_global_listmech();

int assl_listmech(sasl_conn_t *conn, char *user, char *prefix, char *sep, char *suffix, char **result, uint *plen, int *pcount);

int sasl_server_start(sasl_conn_t *conn, char *mech, char *clientin, uint clientinlen, char **serverout, uint *serveroutlen);

int sasl_server_step(sasl_conn_t *conn, char *clientin, uint clientinlen, char **serverout, uint *serveroutlen);

int sasl_checkapop(sasl_conn_t *conn, char *challenge, uint challen, char *response, uint resplen);

int sasl_checkpass(sasl_conn_t *conn, char *user, uint userlen, char *pass, uint passlen);

int sasl_user_exists(sasl_conn_t *conn, char *serice, char *user_realm, char *user);

int sasl_setpass(sasl_conn_t *conn, char *user, char *pass, uint passlen, char *oldpass, uint oldpasslen, uint flags);

enum SASLSET_CREATE = 0x01;
enum SASL_SET_DISABLE = 0x02;
enum SASL_SET_NOPLAIN = 0x04;
enum SASL_SET_CURMECH_ONLY = 0x08;

enum SASL_AUX_END = null;
enum SASL_AUX_ALL = "*";

enum SASL_AUX_PASSWORD_PROP = "userPassword";
enum SASL_AUX_PASSWORD = "*" ~ SASL_AUX_PASSWORD_PROP;
enum SASL_AUX_UIDNUM = "uidNumber";
enum SASL_AUX_GIDNUM = "gidNumber";
enum SASL_AUX_FULLNAME = "gecos";
enum SASL_AUX_HOMEDIR = "homeDirectory";
enum SASL_AUX_SHELL = "loginShell";

enum SASL_AUX_MAILADDR = "mail";
enum SASL_AUX_UNIXMBX = "mailMessageStore";
enum SASL_AUX_MAILCHAN = "mailSMTPSubmitChannel";

int sasl_auxprop_request(sasl_conn_t *conn, char **propnames);

propctx *sasl_auxprop_getctx(sasl_conn_t *conn);

int sasl_auxprop_store(sasl_conn_t *conn, propctx *ctx, char *user);

int sasl_encode(sasl_conn_t *conn, char *input, uint inputlen, char **output, uint *outputlen);

int sasl_encodev(sasl_conn_t *conn, iovec *invec, uint numiov, char **output, uint *outputlen);

int sasl_decode(sasl_conn_t *conn, char *input, uint inputlen, char **output, uint *outputlen);
