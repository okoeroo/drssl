#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <limits.h>
#include <getopt.h>
#include <sys/stat.h>
#include <limits.h>
#include <sys/select.h>
#include <fcntl.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/ocsp.h>

#include "queue.h"

#define CIPHER_LIST "ALL:COMPLEMENTOFALL"

#define RESET_COLOR     "\e[m"
#define MAKE_D_GRAY     "\e[30m"
#define MAKE_RED        "\e[31m"
#define MAKE_GREEN      "\e[32m"
#define MAKE_YELLOW     "\e[33m"
#define MAKE_BLUE       "\e[34m"
#define MAKE_PURPLE     "\e[35m"
#define MAKE_LIGHT_BLUE "\e[36m"
#define MAKE_I_RED      "\e[41m"
#define MAKE_I_GREEN    "\e[42m"
#define MAKE_I_YELLOW   "\e[43m"
#define MAKE_I_BLUE     "\e[44m"
#define MAKE_I_PURPLE   "\e[45m"
#define MAKE_I_L_BLUE   "\e[46m"
#define MAKE_I_GREY     "\e[47m"

#define MSG_OK      ": " MAKE_GREEN  "ok                " RESET_COLOR ":"
#define MSG_WARNING ": " MAKE_YELLOW "warning           " RESET_COLOR ":"
#define MSG_ERROR   ": " MAKE_RED    "error             " RESET_COLOR ":"
#define MSG_DEBUG   ": " MAKE_PURPLE "debug             " RESET_COLOR ":"
#define MSG_BLANK   ":                   :"

#define MALFORMED_ASN1_OBJECT MAKE_I_RED "<MALFORMED ASN1_OBJECT>" RESET_COLOR

#define COLOR(c,str) c str RESET_COLOR


/* Types */
struct error_trace {
    X509 *cert;
    char *subject_dn;
    char *issuer_dn;
    int   pre_ok;
    int   post_ok;
    int   errnum;
    int   errdepth;

    TAILQ_ENTRY(error_trace) entries;
};

typedef enum san_type_e {
    NONE,
    DNS,
    IP,
    EMAIL,
    UNKNOWN
} san_type;

struct subjectaltname {
    char     *value;
    san_type type;

    TAILQ_ENTRY(subjectaltname) entries;
};

struct certinfo {
    X509            *cert;
    char            *commonname;
    char            *subject_dn;
    char            *issuer_dn;
    unsigned int     bits;
    char            *serial;
    char            *valid_notbefore;
    char            *valid_notafter;
    char            *fingerprint_md4;
    char            *fingerprint_md5;
    char            *fingerprint_sha1;
    char            *fingerprint_sha256;
    char            *fingerprint_sha512;
    unsigned int     at_depth;
    unsigned short   selfsigned;
    unsigned short   ca;

    TAILQ_HEAD(, subjectaltname) san_head;

    TAILQ_ENTRY(certinfo) entries;
};


struct diagnostics {
    unsigned short   has_peer;
    unsigned short   has_stack;
    unsigned short   peer_uses_selfsigned;
    unsigned short   peer_has_ca_true;
    unsigned short   found_root_ca_in_stack;

    TAILQ_HEAD(, error_trace) error_trace_head;
};


struct sslconn {
    char *host_ip;
    char *sni;
    char *port;
    int ipversion;
    int sock;

    SSL_CTX *ctx;
    BIO *bio;
    SSL *ssl;
    unsigned short sslversion;
    OCSP_RESPONSE *ocsp_stapling;
    char *cafile;
    char *capath;
    char *clientcert;
    char *clientkey;
    char *clientpass;
    char *cipherlist;

    char *dumpdir;
    char *csvfile;
    int   forcedumpdir;
    int   noverify;
    int   quiet;
    int   timeout;

    /* struct certinfo *certinfo; */
    struct diagnostics *diagnostics;
    TAILQ_HEAD(, certinfo) certinfo_head;
};

/* Prototypes */
struct certinfo *create_certinfo(void);
struct sslconn *create_sslconn(void);
int global_ssl_init(void);
int x509IsCA(X509 *cert);
char *ASN1_INTEGER_to_str(ASN1_INTEGER *a);
char *ASN1_GENERALIZEDTIME_to_str(const ASN1_GENERALIZEDTIME *tm);
char *ASN1_UTCTIME_to_str(const ASN1_UTCTIME *tm);
char *ASN1_TIME_to_str(const ASN1_TIME *tm);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
static int ocsp_resp_cb(SSL *s, void *arg);
#endif
static int no_verify_callback(int ok, X509_STORE_CTX *store_ctx);
static int verify_callback(int ok, X509_STORE_CTX *store_ctx);
int setup_client_ctx(struct sslconn *conn);
int create_client_socket (int * client_socket, const char * server,
                          char *port, int ipversion,
                          int time_out_milliseconds);
int connect_bio_to_serv_port(struct sslconn *conn);
int connect_ssl_over_socket(struct sslconn *conn);
int extract_subjectaltnames(struct sslconn *conn, struct certinfo *certinfo);
int extract_commonname(struct sslconn *conn, struct certinfo *certinfo);
char *extract_certinfo_fingerprint(struct certinfo *certinfo, const EVP_MD *digest_method);
int extract_certinfo_details(struct sslconn *conn, struct certinfo *certinfo);
int extract_peer_certinfo(struct sslconn *conn);
static int ocsp_certid_print(BIO *bp, OCSP_CERTID* a, int indent);
int extract_OCSP_RESPONSE_data(OCSP_RESPONSE* o, unsigned long flags);
void display_certinfo(struct certinfo *certinfo);
void display_conn_info(struct sslconn *conn);
void diagnose_conn_info(struct sslconn *conn);
void diagnose_error_trace(struct sslconn *conn);
void display_error_trace(struct sslconn *conn);
void dump_to_disk(struct sslconn *conn);
int append_to_csvfile(struct sslconn *conn);
int connect_to_serv_port(struct sslconn *conn);
void usage(void);
unsigned short compare_certinfo_to_X509(struct certinfo *certinfo, X509 *cert);
unsigned short find_X509_in_certinfo_tail(struct sslconn *conn, X509 *cert);
void diagnose_ocsp(struct sslconn *conn, OCSP_RESPONSE *ocsp,
                   X509 *origincert, unsigned short stapled);
time_t grid_asn1TimeToTimeT(unsigned char *asn1time, size_t len);
time_t my_timegm(struct tm *tm);
char *convert_time_t_to_utc_time_string(time_t t);
char *ASN1_OBJECT_to_buffer(ASN1_OBJECT *a);
int cgul_mkdir_with_parents(const char *absolutedir, mode_t mode);


/* Functions */
struct certinfo *
create_certinfo(void) {
    struct certinfo *certinfo;
    certinfo = calloc(sizeof(struct certinfo), 1);
    if (!certinfo)
        return NULL;

    TAILQ_INIT(&(certinfo->san_head));
    return certinfo;
}

struct sslconn *
create_sslconn(void) {
    struct sslconn *conn;

    conn = calloc(sizeof(struct sslconn), 1);
    if (!conn)
        goto fail;

    conn->diagnostics = calloc(sizeof(struct diagnostics), 1);
    if (!conn->diagnostics) {
        free(conn);
        goto fail;
    }

    TAILQ_INIT(&(conn->certinfo_head));
    TAILQ_INIT(&(conn->diagnostics->error_trace_head));
    return conn;
fail:
    return NULL;
}

int
global_ssl_init(void) {
    SSL_library_init();
    SSL_load_error_strings();

    if (RAND_load_file("/dev/urandom", 1024) == 0) {
        return -1;
    }

    return 0;
}

/* 0: Not a CA, 1: A CA */
int
x509IsCA(X509 *cert) {
   int purpose_id;

   purpose_id = X509_PURPOSE_get_by_sname("sslclient");

   /* final argument to X509_check_purpose() is whether to check for CAness */
   if (X509_check_purpose(cert, purpose_id + X509_PURPOSE_MIN, 1))
        return 1;
   else return 0;
}

char *
ASN1_INTEGER_to_str(ASN1_INTEGER *a) {
    int i;
    char buf[2], *str, *t;
    static const char *h="0123456789ABCDEF";

    if (!a || a->length <= 0) {
        return NULL;
    }

    t = str = calloc(1, a->length * 3);
    if (!str)
        return NULL;

    for (i=0; i<a->length; i++) {
        if ((i != 0) && (i%35 == 0)) {
            return NULL;
        }
        buf[0]=h[((unsigned char)a->data[i]>>4)&0x0f];
        buf[1]=h[((unsigned char)a->data[i]   )&0x0f];

        if (i != 0) {
            snprintf(t, 2, ":");
            t++;
        }

        snprintf(t, 3, "%c%c", buf[0], buf[1]);
        t += 2;
    }
    return str;
}

static const char *mon[12]=
    {
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec"
    };

char *
ASN1_GENERALIZEDTIME_to_str(const ASN1_GENERALIZEDTIME *tm) {
    char *v;
    int gmt=0;
    int i, num;
    int y=0,M=0,d=0,h=0,m=0,s=0;
    char *f = NULL;
    int f_len = 0;
    char *str;

    i=tm->length;
    v=(char *)tm->data;

    if (i < 12) goto err;
    if (v[i-1] == 'Z') gmt=1;
    for (i=0; i<12; i++)
        if ((v[i] > '9') || (v[i] < '0')) goto err;
    y= (v[0]-'0')*1000+(v[1]-'0')*100 + (v[2]-'0')*10+(v[3]-'0');
    M= (v[4]-'0')*10+(v[5]-'0');
    if ((M > 12) || (M < 1)) goto err;
    d= (v[6]-'0')*10+(v[7]-'0');
    h= (v[8]-'0')*10+(v[9]-'0');
    m=  (v[10]-'0')*10+(v[11]-'0');
    if (tm->length >= 14 &&
            (v[12] >= '0') && (v[12] <= '9') &&
            (v[13] >= '0') && (v[13] <= '9'))
    {
        s=  (v[12]-'0')*10+(v[13]-'0');
        /* Check for fractions of seconds. */
        if (tm->length >= 15 && v[14] == '.')
        {
            int l = tm->length;
            f = &v[14];     /* The decimal point. */
            f_len = 1;
            while (14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9')
                ++f_len;
        }
    }

    num = snprintf(NULL, 0, "%s %2d %02d:%02d:%02d%.*s %d%s",
                mon[M-1],d,h,m,s,f_len,f,y,(gmt)?" UTC":"");
    str = malloc(num + 1);
    if (!str)
        return NULL;

    snprintf(str, num + 1, "%s %2d %02d:%02d:%02d%.*s %d%s",
                mon[M-1],d,h,m,s,f_len,f,y,(gmt)?" UTC":"");
    return str;
err:
    return NULL;
}

char *
ASN1_UTCTIME_to_str(const ASN1_UTCTIME *tm) {
    const char *v;
    int gmt=0;
    int i, num;
    int y=0,M=0,d=0,h=0,m=0,s=0;
    char *str;

    i=tm->length;
    v=(const char *)tm->data;

    if (i < 10) goto err;
    if (v[i-1] == 'Z') gmt=1;
    for (i=0; i<10; i++)
            if ((v[i] > '9') || (v[i] < '0')) goto err;
    y= (v[0]-'0')*10+(v[1]-'0');
    if (y < 50) y+=100;
    M= (v[2]-'0')*10+(v[3]-'0');
    if ((M > 12) || (M < 1)) goto err;
    d= (v[4]-'0')*10+(v[5]-'0');
    h= (v[6]-'0')*10+(v[7]-'0');
    m=  (v[8]-'0')*10+(v[9]-'0');
    if (tm->length >=12 &&
        (v[10] >= '0') && (v[10] <= '9') &&
        (v[11] >= '0') && (v[11] <= '9'))
            s=  (v[10]-'0')*10+(v[11]-'0');

    num = snprintf(NULL, 0, "%s %2d %02d:%02d:%02d %d%s",
                   mon[M-1],d,h,m,s,y+1900,(gmt)?" UTC":"");
    str = malloc(num + 1);
    if (!str)
        return NULL;

    snprintf(str, num + 1, "%s %2d %02d:%02d:%02d %d%s",
                   mon[M-1],d,h,m,s,y+1900,(gmt)?" UTC":"");
    return str;
err:
    return NULL;
}

char *
ASN1_TIME_to_str(const ASN1_TIME *tm) {
    if(tm->type == V_ASN1_UTCTIME)         return ASN1_UTCTIME_to_str(tm);
    if(tm->type == V_ASN1_GENERALIZEDTIME) return ASN1_GENERALIZEDTIME_to_str(tm);
    return NULL;
}


/**
 * Note that timegm() is non-standard. Linux manpage advices the following
 * substition instead.
 */
time_t
my_timegm(struct tm *tm) {
    time_t ret;
    char *tz;

    tz = getenv("TZ");
    setenv("TZ", "", 1);
    tzset();
    ret = mktime(tm);
    if (tz)
        setenv("TZ", tz, 1);
    else
        unsetenv("TZ");
    tzset();

    return ret;
}


/* ASN1 time string (in a char *) to time_t */
/**
 *  (Use ASN1_STRING_data() to convert ASN1_GENERALIZEDTIME to char * if
 *   necessary)
 */
time_t
grid_asn1TimeToTimeT(unsigned char *asn1time, size_t len) {
    char           zone;
    struct tm      time_tm;
    char           buf[5];
    unsigned char *p;


    if (len == 0) len = strlen((char *)asn1time);

    if ((len != 13) && (len != 15)) {
        return 0; /* dont understand */
    }

    memset(&time_tm, 0, sizeof(struct tm));

    p = asn1time;
    if (len == 15) {
        memset(buf, 0, sizeof(buf)); memcpy(buf, p, 4); buf[4] = '\0'; time_tm.tm_year = atoi(buf); p = &p[4];
    } else if (len == 13) {
        memset(buf, 0, sizeof(buf)); memcpy(buf, p, 2); buf[2] = '\0'; time_tm.tm_year = atoi(buf); p = &p[2];
    }
    memset(buf, 0, sizeof(buf)); memcpy(buf, p, 2); buf[2] = '\0'; time_tm.tm_mon  = atoi(buf); p = &p[2];
    memset(buf, 0, sizeof(buf)); memcpy(buf, p, 2); buf[2] = '\0'; time_tm.tm_mday = atoi(buf); p = &p[2];
    memset(buf, 0, sizeof(buf)); memcpy(buf, p, 2); buf[2] = '\0'; time_tm.tm_hour = atoi(buf); p = &p[2];
    memset(buf, 0, sizeof(buf)); memcpy(buf, p, 2); buf[2] = '\0'; time_tm.tm_min  = atoi(buf); p = &p[2];
    memset(buf, 0, sizeof(buf)); memcpy(buf, p, 2); buf[2] = '\0'; time_tm.tm_sec  = atoi(buf); p = &p[2];
    memset(buf, 0, sizeof(buf)); memcpy(buf, p, 1); buf[1] = '\0'; zone            = buf[0];    p = &p[1];
    if (zone != 'Z')
        return 0;

    /* time format fixups */
    if (time_tm.tm_year < 90) time_tm.tm_year += 100;
    --(time_tm.tm_mon);

    return my_timegm(&time_tm);
}

char *
convert_time_t_to_utc_time_string(time_t t) {
    int i;
    char *buf;
    struct tm time_tm;

    buf = calloc(27, 1);
    if (!buf) {
        /* fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__); */
        return NULL;
    }

    gmtime_r(&t, &time_tm);
    asctime_r(&time_tm, buf);
    for (i = 0; i < strlen(buf); i++) {
        /* Remove newline */
        if (buf[i] == '\n' || buf[i] == '\r') buf[i] = '\0';
    }

    return buf;
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
/* OCSP Stapling callback */
static int
ocsp_resp_cb(SSL *s, void *arg) {
    struct sslconn *conn = (struct sslconn *)arg;
    OCSP_RESPONSE *rsp;
    const unsigned char *p;
    int len;

    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    if (!p) {
        if (!conn->quiet) fprintf(stderr, "%s no OCSP response sent\n", MSG_DEBUG);
        return 1;
    }
    if (!conn->quiet) fprintf(stderr, "%s OCSP response: ", MSG_DEBUG);
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        if (!conn->quiet) fprintf(stderr, "%s response parse error\n", MSG_WARNING);
        return 1;
    }
    if (!conn->quiet) fprintf(stderr, "%s got stapled response\n", MSG_DEBUG);

    /* Record stapled response */
    if (conn) {
        conn->ocsp_stapling = rsp;
    }

    return 1;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */


/* Custom NO verification callback */
static int
no_verify_callback(int ok, X509_STORE_CTX *store_ctx) {
    return 1; /* All ok, move along now... */
}

/* Custom verification callback */
static int
verify_callback(int ok, X509_STORE_CTX *store_ctx) {
    unsigned long       errnum      = X509_STORE_CTX_get_error(store_ctx);
    int                 errdepth    = X509_STORE_CTX_get_error_depth(store_ctx);
    char               *subject     = NULL;
    char               *issuer      = NULL;
    X509               *curr_cert   = NULL;
    SSL                *ssl         = NULL;
    struct sslconn     *conn        = NULL;
    struct error_trace *error_trace = NULL;


    /* Retrieve the SSL object parenting the X509_STORE_CTX */
    ssl = (SSL*)X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (ssl) {
        /* Retrieve the (struct sslconn *) object from the SSL object */
        conn = SSL_get_app_data(ssl);
    }

    if (!conn->quiet)
        fprintf(stderr, "%s (%s) Re-Verify certificate at depth: %i, "
                        "pre-OK is: %d (%s), errnum is: %lu, \"%s\"\n",
                        MSG_DEBUG, __func__, errdepth, ok,
                        ok ? MAKE_GREEN "OK" RESET_COLOR : MAKE_RED "BAD" RESET_COLOR,
                        errnum, X509_verify_cert_error_string(errnum));

    curr_cert = X509_STORE_CTX_get_current_cert(store_ctx);
    if (curr_cert) {
        issuer = X509_NAME_oneline(X509_get_issuer_name(curr_cert), NULL, 0);
        if (!conn->quiet) fprintf(stderr, "%s (%s) - issuer   = %s\n", MSG_DEBUG, __func__, issuer);
        subject = X509_NAME_oneline(X509_get_subject_name(curr_cert), NULL, 0);
        if (!conn->quiet) fprintf(stderr, "%s (%s) - subject  = %s\n", MSG_DEBUG, __func__, subject);
    }

    if (!conn) {
        free(issuer);
        free(subject);
    } else {
        error_trace = calloc(sizeof(struct error_trace), 1);
        if (!error_trace) {
            if (!conn->quiet) fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
            free(issuer);
            free(subject);
            return 0; /* Return as a verification failure */
        }

        if (curr_cert) {
            error_trace->cert = X509_dup(curr_cert);
        }

        error_trace->subject_dn = subject;
        error_trace->issuer_dn  = issuer;
        error_trace->pre_ok     = ok;
        error_trace->post_ok    = -1;
        error_trace->errnum     = errnum;
        error_trace->errdepth   = errdepth;
    }

    /********/

    /* When the verdict is not OK, see what we can do about it or fail */
    if (ok != 1) {
        switch (errnum) {
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                if (!conn->quiet)
                    fprintf(stderr, "%s %s: Override Self-Signed certificate error.\n",
                                            MSG_ERROR,
                                            __func__);
                ok = 1;
                break;
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                if (!conn->quiet)
                    fprintf(stderr, "%s %s: Unable to find the issuer (locally on disk) of the "
                                            "certificate now in evaluation.\n"\
                                    "%s         Options: 1. Certificate was signed by an unknown CA, see the "
                                                         "--capath and --cafile options to solve this perhaps.\n"
                                    "%s                  2. The server didn't send an intermediate CA "
                                                         "certificate to complete the certificate chain\n",
                                    MSG_ERROR,
                                    __func__,
                                    MSG_BLANK,
                                    MSG_BLANK);
                break;
            default:
                if (!conn->quiet)
                    fprintf(stderr, "%s %s: errnum %d: %s\n",
                                    MSG_ERROR, __func__, (int) errnum, X509_verify_cert_error_string(errnum));
                break;
        }
    }

    /* Record the (un)resolved error and store the struct */
    if (error_trace) {
        error_trace->post_ok = ok;
        TAILQ_INSERT_TAIL(&(conn->diagnostics->error_trace_head), error_trace, entries);
    }

    return ok;
}


/* Use: 2(SSLv2), 3(SSLv3), 10(TLS1.0), 11(TLS1.1), 12(TLS1.2) */
int
setup_client_ctx(struct sslconn *conn) {
    int rc = 0;

    if (!conn)
        return -1;

    switch (conn->sslversion) {
        case 2:
            conn->ctx = SSL_CTX_new(SSLv23_method());
            SSL_CTX_set_options(conn->ctx, SSL_OP_ALL|SSL_OP_NO_SSLv3);
            break;
        case 3:
            conn->ctx = SSL_CTX_new(SSLv3_client_method());
            SSL_CTX_set_options(conn->ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
            break;
        case 10:
            conn->ctx = SSL_CTX_new(TLSv1_client_method());
            break;
#ifdef HAVE_TLSV1_1_CLIENT_METHOD
        case 11:
            conn->ctx = SSL_CTX_new(TLSv1_1_client_method());
            break;
#endif
#ifdef HAVE_TLSV1_2_CLIENT_METHOD
        case 12:
            conn->ctx = SSL_CTX_new(TLSv1_2_client_method());
            break;
#endif
        default:
            if (!conn->quiet) fprintf(stderr, "Wrong SSL version/type provided to %s()\n",
                                      __func__);
            return -2;
    }

    SSL_CTX_set_verify_depth(conn->ctx, 99);
    if (SSL_CTX_set_cipher_list(conn->ctx, conn->cipherlist) != 1) {
        if (!conn->quiet) fprintf(stderr, "%s Failed to set cipher list, no valid ciphers provided in \"%s\"\n",
                                  MSG_ERROR, conn->cipherlist);
        return -3;
    }

    /* Add CA dir info */
    if ((conn->capath || conn->cafile) &&
        (1 != SSL_CTX_load_verify_locations(conn->ctx,
                                            conn->cafile,
                                            conn->capath))) {
        if (!conn->quiet) fprintf(stderr, "Warning: SSL_CTX_load_verify_locations failed\n");
    }

    /* Use a client certificate for authentication */
    if (conn->clientcert && conn->clientkey) {
        rc = SSL_CTX_use_certificate_chain_file(conn->ctx, conn->clientcert);
        if (rc != 1) {
            if (!conn->quiet) fprintf(stderr, "%s Error loading client certificate (chain) from "
                                      "file \"%s\", with reason: %s\n",
                                      MSG_ERROR,
                                      conn->clientcert,
                                      ERR_reason_error_string(ERR_get_error()));
            return -4;
        }

        rc = SSL_CTX_use_PrivateKey_file(conn->ctx, conn->clientkey, SSL_FILETYPE_PEM);
        if (rc != 1) {
            if (!conn->quiet) fprintf(stderr, "%s Error loading client private key file from "
                                      "file \"%s\", with reason: %s\n",
                                      MSG_ERROR,
                                      conn->clientcert,
                                      ERR_reason_error_string(ERR_get_error()));
            return -5;
        }
    }

    /* Set custom callback */
    if (conn->noverify) {
        SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_NONE, no_verify_callback);
    } else {
        /* SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, verify_callback); */
        /* Do not fail on the peer verification directly. Continue, and let the
         * rest of the code conclude on the failure(s) */
        SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_NONE, verify_callback);
    }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    /* Set up OCSP Stapling callback setup */
    SSL_CTX_set_tlsext_status_cb(conn->ctx, ocsp_resp_cb);
    SSL_CTX_set_tlsext_status_arg(conn->ctx, conn);
#endif

    return 0;
}


int
create_client_socket (int * client_socket,
                      const char * server,
                      char *port,
                      int ipversion,
                      int time_out_milliseconds) {
    struct addrinfo  hints;
    struct addrinfo *res;
    int              rc;
    int              mysock = -1;
    fd_set           fdset;
    int              so_error;
    socklen_t        so_error_len = sizeof so_error;
    struct timeval   wait_tv;

    FD_ZERO(&fdset);
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = ipversion;

    rc = getaddrinfo(server, port, &hints, &res);
    if (rc != 0) {
        /* fprintf(stderr, "%s Failed to getaddrinfo (%s, %s, *, *)\n", MSG_ERROR, server, portstr); */
        return 1;
    }

    /* Create new socket */
    if ((mysock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        /* fprintf(stderr, "%s Failed to create socket\n", MSG_ERROR); */
        return 1;
    }

    /* Set connection timeout on the socket */
    wait_tv.tv_sec  = (time_out_milliseconds - (time_out_milliseconds % 1000)) / 1000;
    wait_tv.tv_usec = (time_out_milliseconds % 1000) * 1000;

    /* Set to non-block, connect() output can be ignored */
    fcntl(mysock, F_SETFL, O_NONBLOCK);

    /* Connecting socket to host on port with timeout */
    connect(mysock, res -> ai_addr, res -> ai_addrlen);

    FD_SET(mysock, &fdset);

    if (select(mysock + 1, NULL, &fdset, NULL, &wait_tv) == 1) {
        getsockopt(mysock, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len);

        if (so_error == 0) {
            /* Socket is succesfuly connected */
            fcntl(mysock, F_SETFL, fcntl(mysock, F_GETFL) & ~O_NONBLOCK);
            setsockopt (mysock, SOL_SOCKET, SO_KEEPALIVE, 0, 0);

            *client_socket = mysock;
            return 0;
        }
    }

    /* Failure */
    return 1;
}



/* Connect the struct sslconn object using a BIO */
int
connect_bio_to_serv_port(struct sslconn *conn) {
    int sock;

    if (!conn->quiet) fprintf(stderr, "%s (%s) TCP/IP connect to host\n", MSG_DEBUG, __func__);

    if (!conn || !conn->host_ip)
        return -1;

    if (create_client_socket (&sock,
                              conn->host_ip, conn->port,
                              conn->ipversion, conn->timeout * 1000) != 0) {
        if (!conn->quiet) fprintf(stderr,
                                  "%s failed to connect to \"%s\" on port \'%s\'\n",
                                  MSG_ERROR, conn->host_ip, conn->port);
        return -2;
    }
    if (!conn->quiet) fprintf(stderr, "%s (%s) Connected to \"%s\" on port \'%s\'\n",
                                      MSG_DEBUG, __func__, conn->host_ip, conn->port);
    conn->sock = sock;
    return 0;
}

/* Connect struct sslconn object using SSL over an existing BIO */
int
connect_ssl_over_socket(struct sslconn *conn) {
    if (!conn->quiet) fprintf(stderr, "%s (%s) Setup SSL session over the TCP/IP connection\n", MSG_DEBUG, __func__);

    if (!conn || !conn->host_ip || !conn->sock)
        return -1;

    conn->ssl = SSL_new(conn->ctx);
    if (!conn->ssl) {
        return -2;
    }

    /* Record parent (struct sslconn *) object in SSL - used in callback */
    SSL_set_app_data(conn->ssl, conn);

    #if OPENSSL_VERSION_NUMBER >= 0x10000000L
    /* Setup OCSP stapling on the SSL object */
    SSL_set_tlsext_status_type(conn->ssl, TLSEXT_STATUSTYPE_ocsp);
    #endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */

    #if OPENSSL_VERSION_NUMBER >= 0x10000000L
    /* Set TLS SNI (Server Name Indication) */
    if (conn->sni && !SSL_set_tlsext_host_name(conn->ssl, conn->sni)) {
        fprintf(stderr, "%s Unable to set TLS servername extension (SNI).\n", MSG_WARNING);
    }
    #endif

    /* Connecting the Socket to the SSL layer */
    conn->bio = BIO_new_socket (conn->sock, BIO_NOCLOSE);
    if (!conn->bio) {
        if (!conn->quiet) fprintf(stderr, "%s Error: Failed to tie the socket to a SSL BIO\n", MSG_ERROR);
        SSL_free(conn->ssl);
        return -3;
    }
    if (!conn->quiet) fprintf(stderr, "%s (%s) BIO created from socket\n", MSG_DEBUG, __func__);

    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
    if (SSL_connect(conn->ssl) <= 0) {
        if (!conn->quiet) fprintf(stderr, "%s (%s) Error connecting SSL\n", MSG_ERROR, __func__);
        SSL_free(conn->ssl);
        return -4;
    }

    return 0;
}

/* <0: error, 0: No SAN found, 1: SAN found */
int
extract_subjectaltnames(struct sslconn *conn, struct certinfo *certinfo) {
    int i, j, extcount;
    unsigned short found_san = 0;
    X509_EXTENSION          *ext;
    int                     NID_from_ext = NID_undef; /* Initialize with undefined NID
                                                         (Numerical ID of a
                                                         type of ASN1 object)
                                                         */
    const unsigned char     *data;
    STACK_OF(CONF_VALUE)    *val;
    CONF_VALUE              *nval;
    X509V3_EXT_METHOD       *meth;
    void                    *ext_str = NULL;
    struct subjectaltname   *p_san;

    if (!conn->quiet) fprintf(stderr, "%s (%s) Extract and register Subject Alt Names.\n", MSG_DEBUG, __func__);

    if (!certinfo || !certinfo->cert)
        return -1;

    /* Compare the subjectAltName DNS value with the host value */
    if ((extcount = X509_get_ext_count(certinfo->cert)) > 0) {
        /* Run through all the extensions */
        for (i = 0; i < extcount; i++) {
            ext = X509_get_ext(certinfo->cert, i);
            NID_from_ext = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

            /* Subject Alt Name? */
            if (NID_from_ext == NID_subject_alt_name) {
                found_san = 1;

                meth = (X509V3_EXT_METHOD *)X509V3_EXT_get(ext);
                if (!meth)
                    break;

                data = ext->value->data;

#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
                if (meth->it)
                    ext_str = ASN1_item_d2i(NULL, &data,
                                            ext->value->length,
                                            ASN1_ITEM_ptr(meth->it));
                else
                    ext_str = meth->d2i(NULL, &data, ext->value->length);
#else
                ext_str = meth->d2i(NULL, &data, ext->value->length);
#endif
                val = meth->i2v(meth, ext_str, NULL);
                for (j = 0;  j < sk_CONF_VALUE_num(val);  j++) {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!nval) {
                        return -9;
                    }

                    /* Register the SAN */
                    p_san = malloc(sizeof(struct subjectaltname));
                    if (!p_san) {
                        if (!conn->quiet) fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
                        return -10;
                    }

                    if (!strcasecmp(nval->name, "DNS")) {
                        p_san->type = DNS;
                    } else if (!strcasecmp(nval->name, "iPAddress")) {
                        p_san->type = IP;
                    } else if (!strcasecmp(nval->name, "email")) {
                        p_san->type = EMAIL;
                    } else {
                        /* TODO */
                        /* printf("Unknown : %s, %s\n", nval->name, nval->value); */
                        p_san->type = UNKNOWN;
                    }

                    p_san->value = strdup(nval->value);
                    if (!p_san->value) {
                        if (!conn->quiet) fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
                        return -11;
                    }

                    TAILQ_INSERT_TAIL(&(certinfo->san_head), p_san, entries);
                }
            }
        }
    }

    if (!found_san)
        return 0;

    return 1;
}

int
extract_commonname(struct sslconn *conn, struct certinfo *certinfo) {
    X509_NAME *subj;
    int cnt;
    char *cn;

    if (!conn->quiet) fprintf(stderr, "%s (%s) Extract and register the Common Name\n", MSG_DEBUG, __func__);

    if (!certinfo || !certinfo->cert)
        return -1;

    subj = X509_get_subject_name(certinfo->cert);
    if (!subj) {
        if (!conn->quiet) fprintf(stderr, "%s could not extract the Subject DN\n", MSG_ERROR);
        return -2;
    }

    cnt = X509_NAME_get_text_by_NID(subj, NID_commonName, NULL, 0);
    cn = malloc(cnt + 1);
    if (!cn) {
        if (!conn->quiet) fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
        return -3;
    }
    cnt = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, cnt + 1);

    certinfo->commonname = cn;
    return 0;
}

char *
extract_certinfo_fingerprint(struct certinfo *certinfo, const EVP_MD *digest_method) {
    int j;
    unsigned int n;
    int len = 0;
    unsigned char md[EVP_MAX_MD_SIZE];
    char *fingerprint = NULL;

    if (!X509_digest(certinfo->cert, digest_method, md, &n)) {
        return NULL;
    }

    for (j = 0; j < (int)n; j++) {
        len += snprintf(NULL, 0, "%s%02X", (j == 0) ? "" : ":", md[j]);
    }
    len++;
    fingerprint = malloc(len);
    if (!fingerprint)
        return NULL;

    for (j = 0; j < (int)n; j++) {
        snprintf(fingerprint, len, "%s%s%02X", fingerprint ? fingerprint : NULL, (j == 0) ? "" : ":", md[j]);
    }
    return fingerprint;
}

int
extract_certinfo_details(struct sslconn *conn,
                         struct certinfo *certinfo) {
    EVP_PKEY *pktmp;

    if (!certinfo)
        return -1;

    /* List and register the SubjectAltNames */
    if (extract_subjectaltnames(conn, certinfo) < 0) {
        return -2;
    }

    /* Extract and register the Common Name */
    if (extract_commonname(conn, certinfo) < 0) {
        return -3;
    }

    /* Check if peer cert is a CA, or something */
    certinfo->ca         = x509IsCA(certinfo->cert);
    certinfo->selfsigned = (X509_NAME_cmp(X509_get_subject_name(certinfo->cert),
                                          X509_get_issuer_name (certinfo->cert)) == 0);

    pktmp = X509_get_pubkey(certinfo->cert);
    certinfo->bits = EVP_PKEY_bits(pktmp);
    EVP_PKEY_free(pktmp);

    certinfo->serial = ASN1_INTEGER_to_str(X509_get_serialNumber(certinfo->cert));
    certinfo->valid_notbefore = ASN1_TIME_to_str(X509_get_notBefore(certinfo->cert));
    certinfo->valid_notafter  = ASN1_TIME_to_str(X509_get_notAfter(certinfo->cert));

    certinfo->subject_dn = X509_NAME_oneline(X509_get_subject_name(certinfo->cert), NULL, 0);
    certinfo->issuer_dn  = X509_NAME_oneline(X509_get_issuer_name(certinfo->cert), NULL, 0);

    certinfo->fingerprint_md4    = extract_certinfo_fingerprint(certinfo, EVP_md4());
    certinfo->fingerprint_md5    = extract_certinfo_fingerprint(certinfo, EVP_md5());
    certinfo->fingerprint_sha1   = extract_certinfo_fingerprint(certinfo, EVP_sha1());
    certinfo->fingerprint_sha256 = extract_certinfo_fingerprint(certinfo, EVP_sha256());
    certinfo->fingerprint_sha512 = extract_certinfo_fingerprint(certinfo, EVP_sha512());

    return 0;
}

unsigned short
compare_certinfo_to_X509(struct certinfo *certinfo, X509 *cert) {
    return !X509_NAME_cmp(X509_get_subject_name(certinfo->cert), X509_get_subject_name(cert)) &&
           !X509_issuer_and_serial_cmp(certinfo->cert, cert);
}

unsigned short
find_X509_in_certinfo_tail(struct sslconn *conn, X509 *cert) {
    struct certinfo *certinfo, *tmp_certinfo;

    if (!cert)
        return 0;

    for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
        if (compare_certinfo_to_X509(certinfo, cert)) {
            return 1;
        }
        tmp_certinfo = TAILQ_NEXT(certinfo, entries); /* Next */
    }
    return 0;
}

int
extract_peer_certinfo(struct sslconn *conn) {
    struct certinfo *certinfo, *tmp_certinfo;
    int depth, i;
    X509 *peer;
    STACK_OF(X509) *stack;

    if (!conn || !conn->ssl)
        return -1;

    if (!conn->quiet)
        fprintf(stderr, "%s (%s) Extract the certificates and register their information\n", MSG_DEBUG, __func__);

    /* Record peer certificate */
    peer = SSL_get_peer_certificate(conn->ssl);
    if (!peer) {
        if (!conn->quiet)fprintf(stderr, "%s No peer certificate found in SSL.\n", MSG_ERROR);
        conn->diagnostics->has_peer = 0;
        return -2;
    } else {
        conn->diagnostics->has_peer = 1;
        certinfo = create_certinfo();
        if (!certinfo) {
            if (!conn->quiet)fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
            return -3;
        }
        certinfo->cert = peer;
        certinfo->at_depth = 0;
        TAILQ_INSERT_TAIL(&(conn->certinfo_head), certinfo, entries);
    }

    /* Record stack of certificates */

    /* On the client side, the peer_cert is included. On the server side it is
     * not. Assume client side for now */
    stack = SSL_get_peer_cert_chain(conn->ssl);
    if (!stack) {
        if (!conn->quiet) fprintf(stderr, "%s No peer certificate stack found in SSL\n", MSG_WARNING);
        conn->diagnostics->has_stack = 0;
    } else {
        conn->diagnostics->has_stack = 1;
        depth = sk_X509_num(stack);
        for (i = 0; i < depth; i++) {
            /* De-dup */
            if (find_X509_in_certinfo_tail(conn, sk_X509_value(stack, i))) {
                if (!conn->quiet) fprintf(stderr, "%s (%s) Discard certificate already captured\n",
                                          MSG_WARNING, __func__);
                continue;
            }

            certinfo = create_certinfo();
            if (!certinfo) {
                if (!conn->quiet) fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
                return -5;
            }
            certinfo->at_depth = i;
            certinfo->cert = sk_X509_value(stack, i);

            TAILQ_INSERT_TAIL(&(conn->certinfo_head), certinfo, entries);
        }

        /* Loop over found certinfo structs to extract certificate details per certificate */
        for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
            extract_certinfo_details(conn, certinfo);
            tmp_certinfo = TAILQ_NEXT(certinfo, entries); /* Next */
        }
    }

    /* Carry on */
    return 0;
}

static int
ocsp_certid_print(BIO *bp, OCSP_CERTID* a, int indent)
        {
    BIO_printf(bp, "%*sCertificate ID:\n", indent, "");
    indent += 2;
    BIO_printf(bp, "%*sHash Algorithm: ", indent, "");
    i2a_ASN1_OBJECT(bp, a->hashAlgorithm->algorithm);
    BIO_printf(bp, "\n%*sIssuer Name Hash: ", indent, "");
    i2a_ASN1_STRING(bp, a->issuerNameHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\n%*sIssuer Key Hash: ", indent, "");
    i2a_ASN1_STRING(bp, a->issuerKeyHash, V_ASN1_OCTET_STRING);
    BIO_printf(bp, "\n%*sSerial Number: ", indent, "");
    i2a_ASN1_INTEGER(bp, a->serialNumber);
    BIO_printf(bp, "\n");
    return 1;
    }

int
extract_OCSP_RESPONSE_data(OCSP_RESPONSE* o, unsigned long flags) {
    int i, ret = 0;
    long l;
    OCSP_CERTID *cid = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPID *rid = NULL;
    OCSP_RESPDATA  *rd = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_REVOKEDINFO *rev = NULL;
    OCSP_SINGLERESP *single = NULL;
    OCSP_RESPBYTES *rb = o->responseBytes;

    BIO *bp;
    bp = BIO_new_fp(stderr,BIO_NOCLOSE);

    l=ASN1_ENUMERATED_get(o->responseStatus);
    if (BIO_printf(bp,"    OCSP Response Status: %s (0x%lx)\n", OCSP_response_status_str(l), l) <= 0) goto err;

    if (rb == NULL) return 1;
    if (BIO_puts(bp,"    Response Type: ") <= 0)
        goto err;
    if(i2a_ASN1_OBJECT(bp, rb->responseType) <= 0)
        goto err;
    if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
        BIO_puts(bp," (unknown response type)\n");
        return 1;
    }

    i = ASN1_STRING_length(rb->response);
    if (!(br = OCSP_response_get1_basic(o))) goto err;
    rd = br->tbsResponseData;
    l=ASN1_INTEGER_get(rd->version);
    if (BIO_printf(bp,"\n    Version: %lu (0x%lx)\n",
                l+1,l) <= 0) goto err;
    if (BIO_puts(bp,"    Responder Id: ") <= 0) goto err;

    rid =  rd->responderId;
    switch (rid->type) {
        case V_OCSP_RESPID_NAME:
            X509_NAME_print_ex(bp, rid->value.byName, 0, XN_FLAG_ONELINE);
            break;
        case V_OCSP_RESPID_KEY:
            i2a_ASN1_STRING(bp, rid->value.byKey, V_ASN1_OCTET_STRING);
            break;
    }

    if (BIO_printf(bp,"\n    Produced At: ")<=0) goto err;
    if (!ASN1_GENERALIZEDTIME_print(bp, rd->producedAt)) goto err;
    if (BIO_printf(bp,"\n    Responses:\n") <= 0) goto err;
    for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++) {
        if (! sk_OCSP_SINGLERESP_value(rd->responses, i)) continue;
        single = sk_OCSP_SINGLERESP_value(rd->responses, i);
        cid = single->certId;
        if(ocsp_certid_print(bp, cid, 4) <= 0) goto err;
        cst = single->certStatus;
        if (BIO_printf(bp,"    Cert Status: %s",
                    OCSP_cert_status_str(cst->type)) <= 0)
            goto err;
        if (cst->type == V_OCSP_CERTSTATUS_REVOKED) {
            rev = cst->value.revoked;
            if (BIO_printf(bp, "\n    Revocation Time: ") <= 0)
                goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp,
                        rev->revocationTime))
                goto err;
            if (rev->revocationReason) {
                l=ASN1_ENUMERATED_get(rev->revocationReason);
                if (BIO_printf(bp,
                            "\n    Revocation Reason: %s (0x%lx)",
                            OCSP_crl_reason_str(l), l) <= 0)
                    goto err;
            }
        }
        if (BIO_printf(bp,"\n    This Update: ") <= 0) goto err;
        if (!ASN1_GENERALIZEDTIME_print(bp, single->thisUpdate))
            goto err;
        if (single->nextUpdate) {
            if (BIO_printf(bp,"\n    Next Update: ") <= 0)goto err;
            if (!ASN1_GENERALIZEDTIME_print(bp,single->nextUpdate))
                goto err;
        }
        if (BIO_write(bp,"\n",1) <= 0) goto err;
        if (!X509V3_extensions_print(bp,
                    "Response Single Extensions",
                    single->singleExtensions, flags, 8))
            goto err;
        if (BIO_write(bp,"\n",1) <= 0) goto err;
    }
    if (!X509V3_extensions_print(bp, "Response Extensions", rd->responseExtensions, flags, 4))
        goto err;
#if 0
    if(X509_signature_print(bp, br->signatureAlgorithm, br->signature) <= 0)
        goto err;
#endif

    BIO_printf(bp, "\nResponse contains %d certificates\n", sk_X509_num(br->certs));
#if 0
    for (i=0; i<sk_X509_num(br->certs); i++) {
        X509_print(bp, sk_X509_value(br->certs,i));
        PEM_write_bio_X509(bp,sk_X509_value(br->certs,i));
    }
#endif

    ret = 1;
    BIO_puts(bp, "\n");
err:
    OCSP_BASICRESP_free(br);
    BIO_puts(bp, "\n");
    return ret;
}

void
display_certinfo(struct certinfo *certinfo) {
    char *tmp;
    struct subjectaltname *p_san, *tmp_p_san;

    if (!certinfo || !certinfo->cert)
        return;

    tmp = X509_NAME_oneline(X509_get_subject_name(certinfo->cert), NULL, 0);
    fprintf(stdout, ": Subject DN        : %s\n", tmp);
    free(tmp);
    tmp = X509_NAME_oneline(X509_get_issuer_name(certinfo->cert), NULL, 0);
    fprintf(stdout, ": Issuer DN         : %s\n", tmp);
    free(tmp);

    fprintf(stdout, ": Depth             : %u\n", certinfo->at_depth);
    fprintf(stdout, ": Public key bits(p): %d\n", certinfo->bits);
    fprintf(stdout, ": Serial number     : %s\n", certinfo->serial);
    fprintf(stdout, ": Valid not before  : %s\n", certinfo->valid_notbefore);
    fprintf(stdout, ": Valid not after   : %s\n", certinfo->valid_notafter);

    for (p_san = TAILQ_FIRST(&(certinfo->san_head)); p_san != NULL; p_san = tmp_p_san) {
        fprintf(stdout, ": Subject Alt Name  : %s\n", p_san->value);
        tmp_p_san = TAILQ_NEXT(p_san, entries);
    }
    fprintf(stdout, ": Common name       : %s\n", certinfo->commonname);
    fprintf(stdout, ": Fingerprint MD4   : %s\n", certinfo->fingerprint_md4);
    fprintf(stdout, ": Fingerprint MD5   : %s\n", certinfo->fingerprint_md5);
    fprintf(stdout, ": Fingerprint SHA1  : %s\n", certinfo->fingerprint_sha1);
    fprintf(stdout, ": Fingerprint SHA256: %s\n", certinfo->fingerprint_sha256);
    fprintf(stdout, ": Fingerprint SHA512: %s\n", certinfo->fingerprint_sha512);

    return;
}

void
display_conn_info(struct sslconn *conn) {
    struct certinfo       *certinfo, *tmp_certinfo;
    uint32_t               random_time;
    time_t                 server_time_s;
    char                  *buf;
    const SSL_CIPHER      *c;
    const COMP_METHOD     *comp, *expansion;

    fprintf(stdout, MAKE_LIGHT_BLUE "=== Report ===" RESET_COLOR "\n");

    fprintf(stdout, ": Host/IP           : %s\n", conn->host_ip);
    fprintf(stdout, ": Port              : %s\n", conn->port);
    fprintf(stdout, ": IP version        : %s\n", conn->ipversion == PF_UNSPEC ?
                                                      "Unspecified, up to system defaults" :
                                                      conn->ipversion == AF_INET6 ?
                                                        "IPv6" :
                                                        conn->ipversion == AF_INET ?
                                                            "IPv4" :
                                                            MAKE_I_RED "Unknown" RESET_COLOR);
    fprintf(stdout, ": TLS ext SNI       : %s\n", conn->sni ? conn->sni : "not set");
    fprintf(stdout, ": Socket number     : %d\n", conn->sock);
    switch (conn->sslversion) {
        case  0: fprintf(stdout, ": Wished SSL version: NONE\n"); break;
        case  2: fprintf(stdout, ": Wished SSL version: SSLv2\n"); break;
        case  3: fprintf(stdout, ": Wished SSL version: SSLv3\n"); break;
        case 10: fprintf(stdout, ": Wished SSL version: TLS1.0\n"); break;
        case 11: fprintf(stdout, ": Wished SSL version: TLS1.1\n"); break;
        case 12: fprintf(stdout, ": Wished SSL version: TLS1.2\n"); break;
        default: fprintf(stdout, ": Wished SSL version: UNKNOWN\n"); break;
    }
    /* int SSL_version(conn->ssl); */
    /* DTLS1_VERSION */

    c = SSL_get_current_cipher(conn->ssl);
    fprintf(stdout, ": SSL Ciphers used  : %s / %s\n",
                    SSL_CIPHER_get_name(c), SSL_CIPHER_get_version(c));

    comp = SSL_get_current_compression(conn->ssl);
    fprintf(stdout, ": SSL Compression   : %s\n",
                    comp ? SSL_COMP_get_name(comp) : "NONE");

    expansion = SSL_get_current_expansion(conn->ssl);
    fprintf(stdout, ": SSL Expansion     : %s\n",
                    expansion ? SSL_COMP_get_name(expansion) : "NONE");

    /* Print the time from the random info */
    memcpy(&random_time, conn->ssl->s3->server_random, sizeof(uint32_t));
    server_time_s = ntohl(random_time);

    buf = convert_time_t_to_utc_time_string(server_time_s);
    if (!buf) {
        fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
        return;
    }
    fprintf(stdout, ": random->unix_time : %lu, %s (utc/zulu)\n",
                    server_time_s, buf);
    free(buf);

    fprintf(stdout, ": Certificate?      : %s\n", conn->diagnostics->has_peer ? "Yes" : "No");
    fprintf(stdout, ": Stack?            : %s\n", conn->diagnostics->has_stack ? "Yes" : "No");

    /* Got certificate related information? */
    if (!(TAILQ_EMPTY(&(conn->certinfo_head)))) {
        for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
            fprintf(stdout, ": " MAKE_GREEN "---" RESET_COLOR "\n");
            display_certinfo(certinfo);
            tmp_certinfo = TAILQ_NEXT(certinfo, entries); /* Next */
        }
        fprintf(stdout, ": " MAKE_GREEN "---" RESET_COLOR "\n");

        fprintf(stdout, ": OCSP Stapling     : %s\n", conn->ocsp_stapling ? "Yes" : "No");
        if (conn->ocsp_stapling) {
            fprintf(stdout, ": OCSP Stapled Resp.: Temporarily disabled\n");
            /* fprintf(stdout, ": OCSP Stapled Resp.:\n"); */
            /* extract_OCSP_RESPONSE_data(conn->ocsp_stapling, 0); */
        }

    } else {
        fprintf(stdout, ": No Certificate info from.\n");
    }

    return;
}

char *
ASN1_OBJECT_to_buffer(ASN1_OBJECT *a) {
    char *buf;
    int i, size = 64;

    /* Create buffer */
    if ((a == NULL) || (a->data == NULL))
        return NULL;

    buf = calloc(size, 1);
    if (!buf)
        return NULL;

    /* Try to place the ASN1_OBJECT in buffer, i is total required write size */
    i = i2t_ASN1_OBJECT(buf, size, a);
    if (i > size - 1) {
        free(buf);
        size = i + 1;
        buf = calloc(size, 1);
        if (!buf)
            return NULL;

        i = i2t_ASN1_OBJECT(buf, size, a);
    }
    if (i <= 0) {
        strncpy(buf,
                MALFORMED_ASN1_OBJECT,
                strlen(MALFORMED_ASN1_OBJECT));
        return buf;
    }
    return buf;
}

void
display_error_trace(struct sslconn *conn) {
    struct error_trace *error_trace, *tmp_error_trace;
    int i = 0;

    fprintf(stdout, MAKE_LIGHT_BLUE "=== Error trace ===" RESET_COLOR "\n");

    if (TAILQ_EMPTY(&(conn->diagnostics->error_trace_head))) {
        fprintf(stderr, "%s No error traces recorded.\n", MSG_DEBUG);
    } else {
        for (error_trace = TAILQ_FIRST(&(conn->diagnostics->error_trace_head));
             error_trace != NULL; error_trace = tmp_error_trace) {

            fprintf(stdout, ": " MAKE_GREEN "--- %d" RESET_COLOR "\n", i);
            fprintf(stdout, ": Have a cert       : %s\n", error_trace->cert ? "Yes" : "No");
            if (error_trace->issuer_dn)
                fprintf(stdout, ": Issuer DN         : %s\n", error_trace->issuer_dn);
            if (error_trace->subject_dn)
                fprintf(stdout, ": Subject DN        : %s\n", error_trace->subject_dn);

            fprintf(stdout, ": Pre-verify        : %s\n",
                            error_trace->pre_ok ? MAKE_GREEN "OK" RESET_COLOR : MAKE_RED "BAD" RESET_COLOR);
            fprintf(stdout, ": Post-verify       : %s\n",
                            error_trace->post_ok ? MAKE_GREEN "OK" RESET_COLOR : MAKE_RED "BAD" RESET_COLOR);
            fprintf(stdout, ": Error number      : %d - \"%s\"\n",
                            error_trace->errnum, X509_verify_cert_error_string(error_trace->errnum));
            fprintf(stdout, ": Error depth       : %d\n", error_trace->errdepth);

            /* Next */
            tmp_error_trace = TAILQ_NEXT(error_trace, entries);
            i++;
        }
    }
    return;
}

void
diagnose_ocsp(struct sslconn *conn, OCSP_RESPONSE *ocsp, X509 *origincert, unsigned short stapled) {
    int i;
    /* int flags = 0; */
    long l;
    char *tmp;
    time_t produced_at = 0, revoked_at = 0, t = 0;
    unsigned char *u_tmp;
    OCSP_CERTID *cid = NULL;
    OCSP_BASICRESP *br = NULL;
    OCSP_RESPID *rid = NULL;
    OCSP_RESPDATA  *rd = NULL;
    OCSP_CERTSTATUS *cst = NULL;
    OCSP_REVOKEDINFO *rev = NULL;
    OCSP_SINGLERESP *single = NULL;
    OCSP_RESPBYTES *rb = NULL;

    if (!ocsp)
        return;

    /* init */
    rb = ocsp->responseBytes;

    fprintf(stdout, MAKE_LIGHT_BLUE "=== Diagnose OCSP ===" RESET_COLOR "\n");
    fprintf(stdout, "%s OCSP Source %s\n", MSG_BLANK, stapled ? "OCSP Stapling" : "AIA record on certificate");

    /* OCSP Response status */
    l = ASN1_ENUMERATED_get(ocsp->responseStatus);
    if (l == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        fprintf(stdout, "%s OCSP Response Status is successful (generic OCSP answer)\n", MSG_OK);
    } else {
        fprintf(stdout, "%s OCSP Response Status is %s\n", MSG_ERROR, OCSP_response_status_str(l));
    }

    /* Actual bytes */
    if (!rb) {
        fprintf(stdout, "%s OCSP Response data is malformed or non-existant.\n", MSG_ERROR);
        return;
    }

    /* Only accept OCSP Basic response */
    if (OBJ_obj2nid(rb->responseType) == NID_id_pkix_OCSP_basic) {
        fprintf(stdout, "%s OCSP Response Type: Basic OCSP Response\n", MSG_OK);
    } else {
        fprintf(stdout, "%s OCSP Response Type: unknown response type\n", MSG_ERROR);
        return;
    }

    /* Get OCSP Response Basic */
    br = OCSP_response_get1_basic(ocsp);
    if (!br) {
        fprintf(stdout, "%s Malformed Response: Basic OCSP Response got not be retrieved\n", MSG_ERROR);
        return;
    }

    /* Get Raw RespData */
    rd = br->tbsResponseData;
    if (!rd) {
        fprintf(stdout, "%s Malformed Response: Raw Response data was not retrieved\n", MSG_ERROR);
        return;
    }

    /* OCSP Response Version */
    l = ASN1_INTEGER_get(rd->version);
    if (l != 0) {
        fprintf(stdout, "%s Unsupported OCSP Response version: %lu\n", MSG_ERROR, l + 1);
        return;
    }

    /* Responder ID */
    rid = rd->responderId;
    if (!rid) {
        fprintf(stdout, "%s Malformed Response: No Responder ID found\n", MSG_ERROR);
        return;
    }
    switch (rid->type) {
        case V_OCSP_RESPID_NAME:
            tmp = X509_NAME_oneline(rid->value.byName, NULL, 0);
            fprintf(stdout, "%s Responder ID (byName): \"%s\"\n", MSG_BLANK, tmp);
            free(tmp);
            break;
        case V_OCSP_RESPID_KEY:
            u_tmp = ASN1_STRING_data(rid->value.byKey);
            fprintf(stdout, "%s Responder ID (byKey): \'%s\'\n", MSG_BLANK, u_tmp);
            free(u_tmp);
            break;
    }

    /* Check, and if so convert, the producedAt time */
    if (rd->producedAt &&
        (u_tmp = ASN1_STRING_data(rd->producedAt)) &&
        u_tmp) {
        produced_at = grid_asn1TimeToTimeT(u_tmp, strlen((char *)u_tmp));
        free(u_tmp);
        tmp = convert_time_t_to_utc_time_string(produced_at);
        if (!tmp) {
            fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
            return;
        }
        if (produced_at < (time(NULL) - (3600 * 24 * 14))) {
            fprintf(stdout, "%s The OCSP Response indicates to be produced more then 2 weeks ago on: %s UTC/Zulu\n",
                            MSG_ERROR, convert_time_t_to_utc_time_string(produced_at));
        } else if (produced_at < (time(NULL) - (3600 * 24 * 4))) {
            fprintf(stdout, "%s The OCSP Response indicates to be produced more then 4 days ago on: %s UTC/Zulu\n",
                            MSG_WARNING, convert_time_t_to_utc_time_string(produced_at));
        } else {
            fprintf(stdout, "%s The OCSP Response indicates to be newer then 4 days on: %s UTC/Zulu\n",
                            MSG_OK, convert_time_t_to_utc_time_string(produced_at));
        }
        free(tmp);
    }

    for (i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++) {
        /* Single response? */
        single = sk_OCSP_SINGLERESP_value(rd->responses, i);
        if (!single) {
            /* Or not really...? */
            fprintf(stdout, "%s OCSP Single Response %d of %d is empty/non-existent. Trying next (if available)\n",
                            MSG_WARNING, i, sk_OCSP_SINGLERESP_num(rd->responses));
        }

        /* TODO : fix leaks ! */
        cid = single->certId;
        if (!cid) {
            fprintf(stdout, "%s Malformed Response: No Certificate ID found\n", MSG_ERROR);
            return;
        }

        tmp = ASN1_OBJECT_to_buffer(cid->hashAlgorithm->algorithm);
        fprintf(stdout, "%s Cert ID: Hash Algorithm: %s, Issuer Name Hash: %s, Issuer Key Hash: %s, Serial Number: %s\n",
                        MSG_BLANK,
                        tmp,
                        ASN1_STRING_data(cid->issuerNameHash),
                        ASN1_STRING_data(cid->issuerKeyHash),
                        ASN1_STRING_data(cid->serialNumber));
        free(tmp);

        cst = single->certStatus;
        if (!cst) {
            fprintf(stdout, "%s Malformed Response: No Certificate Status found\n", MSG_ERROR);
            return;
        }
        switch (cst->type) {
            case V_OCSP_CERTSTATUS_GOOD :
                fprintf(stdout, "%s Certificate Status: %s\n", MSG_OK, COLOR(MAKE_GREEN, "good"));
                break;
            case V_OCSP_CERTSTATUS_REVOKED :
                fprintf(stdout, "%s Certificate Status: %s\n", MSG_ERROR, COLOR(MAKE_I_RED, "revoked"));

                rev = cst->value.revoked;
                if (rev) {
                    u_tmp = ASN1_STRING_data(rev->revocationTime);
                    revoked_at = grid_asn1TimeToTimeT(u_tmp, strlen((char *)u_tmp));
                    free(u_tmp);
                    tmp = convert_time_t_to_utc_time_string(revoked_at);
                    fprintf(stdout, "%s Revocation time: %s\n", MSG_BLANK, tmp);
                    free(tmp);

                    if (rev->revocationReason) {
                        l = ASN1_ENUMERATED_get(rev->revocationReason);
                        fprintf(stdout, "%s Revocation reason: %s\n", MSG_BLANK, OCSP_crl_reason_str(l));
                    }
                }
                break;
            case V_OCSP_CERTSTATUS_UNKNOWN :
                fprintf(stdout, "%s Certificate Status: %s\n", MSG_ERROR, COLOR(MAKE_RED, "unknown"));
                break;
            default:
                fprintf(stdout, "%s Malformed certificate status found of value: %d\n", MSG_ERROR, cst->type);
                break;

        }

        if (!single->thisUpdate) {
            fprintf(stdout, "%s Malformed OSCP Response, no This Update field found\n", MSG_ERROR);
        } else {
            u_tmp = ASN1_STRING_data(single->thisUpdate);
            t = grid_asn1TimeToTimeT(u_tmp, strlen((char *)u_tmp));
            free(u_tmp);
            tmp = convert_time_t_to_utc_time_string(t);
            fprintf(stdout, "%s This update: %s\n", MSG_BLANK, tmp);
            free(tmp);
        }

        if (!single->thisUpdate) {
            fprintf(stdout, "%s No Next Update field found\n", MSG_WARNING);
        } else {
            u_tmp = ASN1_STRING_data(single->nextUpdate);
            t = grid_asn1TimeToTimeT(u_tmp, strlen((char *)u_tmp));
            free(u_tmp);
            tmp = convert_time_t_to_utc_time_string(t);
            fprintf(stdout, "%s Next update: %s\n", MSG_BLANK, tmp);
            free(tmp);
        }
#if 0

        if (BIO_write(bp,"\n",1) <= 0) goto err;
        if (!X509V3_extensions_print(bp, "Response Single Extensions", single->singleExtensions, flags, 8))
            goto err;
        if (BIO_write(bp,"\n",1) <= 0) goto err;
#endif
    }

    /* Debug cut off hack */
    fprintf(stdout, "%s Response contains %d certificates\n", MSG_BLANK, sk_X509_num(br->certs));
    /* OCSP_BASICRESP_free(br); */
    return;
#if 0
    if (!X509V3_extensions_print(bp, "Response Extensions", rd->responseExtensions, flags, 4))
        goto err;
    if(X509_signature_print(bp, br->signatureAlgorithm, br->signature) <= 0)
        goto err;
#endif

#if 0
    for (i=0; i<sk_X509_num(br->certs); i++) {
        X509_print(bp, sk_X509_value(br->certs,i));
        PEM_write_bio_X509(bp,sk_X509_value(br->certs,i));
    }
#endif
}

void
diagnose_conn_info(struct sslconn *conn) {
    struct certinfo       *certinfo = NULL, *tmp_certinfo = NULL, *peer_certinfo = NULL;
    struct subjectaltname *p_san, *tmp_p_san;
    /* uint32_t               random_time; */
    /* time_t                 server_time_s; */
    /* struct tm              result; */
    /* const SSL_CIPHER      *c; */
    unsigned short         found_san = 0;
    int                    ssl_verify_result;

    if (!conn)
        return;

    if (!conn->quiet) fprintf(stdout, MAKE_LIGHT_BLUE "=== Diagnoses ===" RESET_COLOR "\n");

    /* TODO: Get a chain/stack of errors */
    ssl_verify_result = SSL_get_verify_result(conn->ssl);
    switch (ssl_verify_result) {
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            fprintf(stdout, "%s SSL certificate is self signed\n", MSG_ERROR);
            break;
        case X509_V_OK:
            fprintf(stdout, "%s SSL certificate verification passed\n", MSG_OK);
            break;
        default:
            fprintf(stdout, "%s SSL certification verification error: %d\n",
                            MSG_ERROR,
                            ssl_verify_result);
    }

    /* TODO: Time on server, random or a big deviation */

    /* Got certificate related information? */
    if (TAILQ_EMPTY(&(conn->certinfo_head))) {
        fprintf(stderr, "Error: No peer certificate received\n");
    } else {
        for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
            /* Record the peer certificate */
            if (certinfo->at_depth == 0) {
                peer_certinfo = certinfo;

                /* Peer certificate uses self-signed? */
                if (certinfo->selfsigned) {
                    conn->diagnostics->peer_uses_selfsigned = 1;
                }
                /* Peer certificate has CA:True flag */
                if (certinfo->ca) {
                    conn->diagnostics->peer_has_ca_true = 1;
                }
            } else {
                /* Self-signed in the stack? */
                if (certinfo->selfsigned) {
                    conn->diagnostics->found_root_ca_in_stack = 1;
                }
            }
            /* Next */
            tmp_certinfo = TAILQ_NEXT(certinfo, entries);
        }
    }

    /* Certificate stack diagnostics */
    if (conn->diagnostics) {
        /* Certificate stack details */
        if (conn->diagnostics->found_root_ca_in_stack) {
            fprintf(stdout, "%s Server configuration error, a Root CA was "\
                            "sent by the service. SSL stack must ignore this certificate.\n",
                            MSG_WARNING);
        }
        if (conn->diagnostics->peer_has_ca_true) {
            fprintf(stdout, "%s The peer/host certificate has the CA:True setting in "\
                            "the certificate. This makes no sense.\n",
                            MSG_ERROR);
        }
        if (conn->diagnostics->peer_uses_selfsigned) {
            fprintf(stdout, "%s The peer/host certificate uses a self-signed certificate. "\
                            "Establishing trust is impossible\n",
                            MSG_ERROR);
        }
    }

    /* RFC2818 compliance, i.e. Got SAN?->Check SAN, leave CN. No SAN?
     * (seriously...)->Check CN.
     * Or bypass all and check something else known. (Not implemented yet) */
    if (peer_certinfo) {
        if (TAILQ_EMPTY(&(peer_certinfo->san_head))) {
            fprintf(stdout, "%s RFC2818 check: Peer certificate is a legacy "\
                            "certificate as it features no Subject Alt Names\n",
                            MSG_WARNING);

            /* Check Common Name */
            if (!strcasecmp(peer_certinfo->commonname, conn->host_ip)) {
                fprintf(stdout, "%s RFC2818 check: legacy peer certificate "\
                                "matched most significant Common Name.\n",
                                MSG_OK);
            } else {
                fprintf(stdout, "%s RFC2818 check failed: legacy peer certificate's "\
                                "most significant Common Name did not match the "\
                                "Hostname or IP address of the server.\n",
                                MSG_ERROR);
            }
        } else {
            /* Check SAN */
            for (p_san = TAILQ_FIRST(&(peer_certinfo->san_head)); p_san != NULL; p_san = tmp_p_san) {
                if (!strcasecmp(p_san->value, conn->host_ip)) {
                    fprintf(stdout, "%s RFC2818 check: peer certificate matched "\
                                    "Subject Alt Name\n",
                                    MSG_OK);
                    found_san = 1;
                }
                tmp_p_san = TAILQ_NEXT(p_san, entries);
            }
            if (!found_san) {
                fprintf(stdout, "%s RFC2818 check failed: Peer certificate has "\
                                "Subject Alt Names, but none match the "\
                                "Hostname or IP address of the server. "\
                                "Untrusted connection.\n",
                                MSG_ERROR);
            }
        }
    }

    /* Lower then 1024 is low-bit count aka failure, 1024 is a warning */
    if (TAILQ_EMPTY(&(conn->certinfo_head))) {
        fprintf(stderr, "%s No peer certificate received\n", MSG_ERROR);
    } else {
        for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
            if (certinfo->bits < 1024) {
                fprintf(stdout, "%s The certificate with Subject DN \"%s\" is a small and weak "\
                                "public key length of \'%d\' bits. This is really really bad. "\
                                "This means the security of the certificate can be easily "\
                                "broken with a fast enough computer. Advise: replace it NOW "\
                                "with a new certificate of at least 1024 bits, preferable "\
                                "2048 bits or more.\n",
                                MSG_ERROR,
                                certinfo->subject_dn ? certinfo->subject_dn : "<No Subject DN>",
                                certinfo->bits);
            } else if (certinfo->bits < 1400) {
                fprintf(stdout, "%s The certificate with Subject DN \"%s\" has a weak public "\
                                "key length of \'%d\' bits. This means the security of the "\
                                "certificate can be broken with a fast enough computer. "\
                                "Advise: replace it with a higher quality certificate of at "\
                                "least 2048 bits.\n",
                                MSG_WARNING,
                                certinfo->subject_dn ? certinfo->subject_dn : "<No Subject DN>",
                                certinfo->bits);
            } else if (certinfo->bits >= 1400) {
                fprintf(stdout, "%s The certificate with Subject DN \"%s\" has a strong public "\
                                "key length of \'%d\' bits.\n",
                                MSG_OK,
                                certinfo->subject_dn ? certinfo->subject_dn : "<No Subject DN>",
                                certinfo->bits);
            }

            /* Next */
            tmp_certinfo = TAILQ_NEXT(certinfo, entries);
        }
    }

    /* OCSP check, stapled, non-stapled (could use libcurl here) */
    diagnose_ocsp(conn, conn->ocsp_stapling, NULL, 1);

    /* TODO: CRL and OCSP check, (could use libcurl here) */
    return;
}

/**
 * Author/source: Mischa Salle, gLExec (Apache2 Licence)
 *
 * Behaviour as mkdir -p: create parents where needed.
 * Return values:
 *  0: success
 *  -1: I/O error, e.g. a component is not a dir, not accessible, etc.
 *  -3: absolutedir is not absolute (does not start with '/')
 *  -4: out of memory
 */
int cgul_mkdir_with_parents(const char *absolutedir, mode_t mode)  {
    int rc;
    mode_t oldumask;
    char *dir,*pos;
    struct stat dir_stat;

    if (absolutedir[0]!='/') /* need absolute path */
        return -3;
    /* make copy for local usage */
    if ( (dir=strdup(absolutedir))==NULL )
        return -4; /* out of memory */

    /* pos will 'loop' over all the '/' except the leading one */
    pos=dir;
    /* Enforce mode as the creation mode, even when umask is more permissive */
    oldumask=umask(~mode);
    do {
        /* Setup the next path component */
        pos=strchr(&(pos[1]),'/');
        if (pos!=NULL) pos[0]='\0';
        /* First check if dir exists: needed for automount */
        if ((rc=stat(dir,&dir_stat)))    { /* stat failed: rc now -1 */
            /* Check if it is due to non-existing component */
            if (errno==ENOENT)  { /* means doesn't exist (since dir!="") */
                if ((rc=mkdir(dir,mode)))
                    break;  /* rc==-1 from mkdir */
            } else /* stat failed for other reason: error */
                break;
        } else { /* Check if existing component is a directory */
            if (!S_ISDIR(dir_stat.st_mode)) {
                rc=-1;
                break;
            }
        }
        if (pos==NULL) /* This was the last path component */
            break;
        /* Put the / back */
        pos[0]='/';
    } while ( 1 );
    /* reset umask */
    umask(oldumask);
    /* Free memory and return */
    free(dir);
    return rc;
}

void
dump_to_disk(struct sslconn *conn) {
    struct stat      st;
    struct certinfo *certinfo, *tmp_certinfo;
    char            *path = NULL;
    int              i = 0;
    FILE            *fp;

    /* Got certificate related information? */
    if (TAILQ_EMPTY(&(conn->certinfo_head))) {
        fprintf(stderr, "Error: No peer certificate received\n");
        return;
    }

    /* Stat() dumpdir */
    if (stat(conn->dumpdir, &st) < 0) {
        if (!conn->forcedumpdir) {
            fprintf(stderr, "Error: can't stat() the dumpdir \"%s\", error: %s\n",
                            conn->dumpdir,
                            strerror(errno));
            return;
        } else {
            /* Create the directory like mkdir -p */
            if (cgul_mkdir_with_parents(conn->dumpdir, 0755) < 0) {
                fprintf(stderr, "Error: cgul_mkdir_with_parents() failed to create the directory \"%s\"\n",
                                conn->dumpdir);
                return;
            }
            if (stat(conn->dumpdir, &st) < 0) {
                fprintf(stderr, "Error: can't stat() the dumpdir \"%s\", error: %s\n",
                                conn->dumpdir,
                                strerror(errno));
                return;
            }
        }
    }

    /* Must be a directory */
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: dumpdir value \"%s\" is not a directory\n",
                        conn->dumpdir);
        return;
    }

    path = malloc(PATH_MAX);
    if (!path) {
        fprintf(stderr, "%s (%s) Out of memory\n", MSG_ERROR, __func__);
        return;
    }

    for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
        snprintf(path, PATH_MAX, "%s/cert.pem.%d", conn->dumpdir, i);

        fp = fopen(path, "w");
        if (!fp) {
            fprintf(stderr, "Error: can't fopen() file \"%s\", error: %s\n",
                            path,
                            strerror(errno));
            goto final;
        }

        /* Record the peer certificate */
        if (PEM_write_X509(fp, certinfo->cert) != 1) {
            fprintf(stderr, "Error: failed to write data with PEM_write_X509() to file \"%s\", error: %s\n",
                            path,
                            strerror(errno));
            fclose(fp);
            goto final;
        }
        fclose(fp);

        /* Next */
        i++;
        tmp_certinfo = TAILQ_NEXT(certinfo, entries);
    }

final:
    free(path);
    return;
}

int
append_to_csvfile(struct sslconn *conn) {
    /* echo "\"${HOST}\",\"${PORT}\",\"$SUBJECT\",\"$ISSUER\",\"$KEYSIZE\",\"$SERIAL\",\"$START_DT\",\"$END_DT\",\"$SELF_SIGNED\",\"$SANS\"" >> "$OUTPUT_FILE" */
    struct certinfo       *certinfo = NULL, *tmp_certinfo = NULL;
    struct subjectaltname *p_san, *tmp_p_san;
    char *tmp;
    int i;
    FILE *f;

    if (!conn->csvfile)
        return 1;

    f = fopen(conn->csvfile, "a");
    if (!f) {
        fprintf(stderr, "Error: CSV file \"%s\" could not be opened: %s\n", conn->csvfile, strerror(errno));
        return 1;
    }

    for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
        /* Only the peer cert, skip the rest */
        if (certinfo->at_depth != 0) {
            continue;
        }

        fprintf(f, "\"%s\",", conn->host_ip);
        fprintf(f, "\"%s\",", conn->port);

        tmp = X509_NAME_oneline(X509_get_subject_name(certinfo->cert), NULL, 0);
        fprintf(f, "\"%s\",", tmp ? tmp : "");
        free(tmp);
        tmp = X509_NAME_oneline(X509_get_issuer_name(certinfo->cert), NULL, 0);
        fprintf(f, "\"%s\",", tmp ? tmp : "");
        free(tmp);

        fprintf(f, "\"%d\",", certinfo->bits);

        /* Get serial number */
        fprintf(f, "\"%s\",", certinfo->serial ? certinfo->serial : "");

        fprintf(f, "\"%s\",", certinfo->valid_notbefore ? certinfo->valid_notbefore : "");
        fprintf(f, "\"%s\",", certinfo->valid_notafter ? certinfo->valid_notafter : "");

        if (certinfo->selfsigned) {
            fprintf(f, "\"CA\",");
        } else {
            fprintf(f, "\"EEC\",");
        }

        if (!(TAILQ_EMPTY(&(certinfo->san_head)))) {
            fprintf(f, "\"");
            i = 0;
            for (p_san = TAILQ_FIRST(&(certinfo->san_head)); p_san != NULL; p_san = tmp_p_san) {
                if (i > 0)
                    fprintf(f, ",");

                fprintf(f, "%s", p_san->value);
                i++;
                tmp_p_san = TAILQ_NEXT(p_san, entries);
            }
            fprintf(f, "\",");
        } else {
            fprintf(f, "\"\",");
        }

        fprintf(f, "\"%s\",", certinfo->commonname);


        if (conn->diagnostics->found_root_ca_in_stack) {
            fprintf(f, "\"yes\"");
        } else {
            fprintf(f, "\"no\"");
        }

        fprintf(f, "\n");
        fflush(f);
        tmp_certinfo = TAILQ_NEXT(certinfo, entries); /* Next */

        break;
    }

    fclose(f);

    return 0;
}

int
connect_to_serv_port(struct sslconn *conn) {
    if (!conn->quiet) fprintf(stderr, "%s (%s) Start sequence\n", MSG_DEBUG, __func__);

    if (!conn->host_ip) {
        fprintf(stderr, "Error: no host specified\n");
        return -1;
    }

    /* Early setup warnings */
    if (!conn->cafile && !conn->capath) {
        if (!conn->quiet) fprintf(stdout, "%s No --cafile or --capath was set. DrSSL has no way "\
                                          "of verifying the certificate chain. Unless OpenSSL is "\
                                          "patched to lookup in a default location, e.g. OSX' "\
                                          "KeyChain.app\n",
                                          MSG_WARNING);
    }

    /* Create SSL context */
    if (setup_client_ctx(conn) < 0) {
        return -2;
    }

    /* TCP/IP connect */
    if (connect_bio_to_serv_port(conn) < 0) {
        return -3;
    }

    /* SSL connect */
    if (connect_ssl_over_socket(conn) < 0) {
        return -4;
    }
    if (!conn->quiet) fprintf(stderr, "%s (%s) SSL Connection opened\n", MSG_DEBUG, __func__);

    /* Extract peer cert */
    if (extract_peer_certinfo(conn) < 0) {
        return -5;
    }

    /* No need to write and do stuff if the output is not desired */
    if (!conn->quiet) {
        /* Display / Show the information we gathered */
        display_conn_info(conn);
        display_error_trace(conn);
        diagnose_conn_info(conn);
    }
    if (!conn->quiet) fprintf(stdout, MAKE_LIGHT_BLUE "===" RESET_COLOR "\n");

    if (conn->dumpdir) {
        /* Dump all information as files into a directory */
        dump_to_disk(conn);
    }

    if (conn->csvfile) {
        /* Add a line to the listed the CSV file */
        append_to_csvfile(conn);
    }

    if (!conn->quiet) fprintf(stderr, "%s (%s) SSL Shutting down.\n", MSG_DEBUG, __func__);
    SSL_shutdown(conn->ssl);
    if (!conn->quiet) fprintf(stderr, "%s (%s) SSL Connection closed\n", MSG_DEBUG, __func__);

    SSL_clear(conn->ssl);
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ctx);
    return 0;
}


void
usage(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, "DrSSL - diagnose your SSL\n");
    fprintf(stderr, "\t--help\n");
    fprintf(stderr, "\t--host <host or IP>\n");
    fprintf(stderr, "\t--port <port> - default is: 443\n");
    fprintf(stderr, "\t--4 (force IPv4 - default is system specific)\n");
    fprintf(stderr, "\t--6 (force IPv6 - default is system specific)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "\t--2 (use SSLv2)\n");
    fprintf(stderr, "\t--3 (use SSLv3)\n");
    fprintf(stderr, "\t--10 (use TLSv1.0) - the default\n");
    fprintf(stderr, "\t--11 (use TLSv1.1)\n");
    fprintf(stderr, "\t--12 (use TLSv1.2)\n");
    fprintf(stderr, "\t--cafile <path to CA (bundle) file>\n");
    fprintf(stderr, "\t--capath <path to CA directory>\n");
    fprintf(stderr, "\t--cert <path to client certificate>\n");
    fprintf(stderr, "\t--key <path to client private key file>\n");
    fprintf(stderr, "\t--passphrase <passphrase to unlock the client private key file>\n");
    fprintf(stderr, "\t--cipherlist <cipher list>\n");
    fprintf(stderr, "\t--sni <TLS SNI (Server Name Indication) hostname>\n");
    fprintf(stderr, "\t--dumpdir <dir where all certs and info will be dumped>\n");
    fprintf(stderr, "\t--noverify (mute the verification callback, always 'ok')\n");
    fprintf(stderr, "\t--quiet (just mute)\n");
    fprintf(stderr, "\t--timeout <seconds> (max time to setup the TCP/IP connection)\n");
    fprintf(stderr, "\t--force-dump (creates dump directory if it doesn't exist yet)\n");
    fprintf(stderr, "\t--csvfile <path to output CSV file>\n");
    fprintf(stderr, "\n");

    exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]) {
    int option_index = 0, c = 0;    /* getopt */
    char *timeout_s = NULL;
    struct sslconn *conn; /* The Brain */

    static struct option long_options[] = /* options */
    {
        {"4",           no_argument,       0, '4'},
        {"6",           no_argument,       0, '6'},
        {"2",           no_argument,       0, '2'},
        {"3",           no_argument,       0, '3'},
        {"10",          no_argument,       0, 'A'},
        {"11",          no_argument,       0, 'B'},
        {"12",          no_argument,       0, 'C'},
        {"help",        no_argument,       0, 'h'},
        {"host",        required_argument, 0, 'o'},
        {"port",        required_argument, 0, 'p'},
        {"sni",         required_argument, 0, 's'},
        {"cafile",      required_argument, 0, 'F'},
        {"capath" ,     required_argument, 0, 'P'},
        {"cert",        required_argument, 0, 'c'},
        {"key",         required_argument, 0, 'k'},
        {"passphrase",  required_argument, 0, 'w'},
        {"cipherlist",  required_argument, 0, 'L'},
        {"dumpdir",     required_argument, 0, 'q'},
        {"force-dump",  no_argument,       0, 'r'},
        {"timeout",     required_argument, 0, 't'},
        {"noverify",    no_argument,       0, 'N'},
        {"csvfile",     required_argument, 0, 'V'},
        {"quiet",       no_argument,       0, 'Q'}
    };

    /* Create the Brain */
    conn = create_sslconn();
    if (conn == NULL)
        return -1;

    /* Defaults */
    conn->ipversion = PF_UNSPEC;
    conn->cipherlist = CIPHER_LIST;
    conn->port = "https";
    conn->sslversion = 10;
    conn->noverify = 0;
    conn->quiet = 0;
    conn->timeout = 30;
    conn->forcedumpdir = 0;

    opterr = 0;
    optind = 0;

    /* parse options */
    while(1){
        c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if(c == -1){
            break;
        }
        switch(c){
            case 'h':
                usage();
                /* NOTREACHED */
            case '2':
                conn->sslversion = 2;
                break;
            case '3':
                conn->sslversion = 3;
                break;
            case '4':
                conn->ipversion = AF_INET;
                break;
            case '6':
                conn->ipversion = AF_INET6;
                break;
            case 'A':
                conn->sslversion = 10;
                break;
            case 'B':
                conn->sslversion = 11;
                break;
            case 'C':
                conn->sslversion = 12;
                break;
            case 'N':
                conn->noverify = 1;
                break;
            case 'Q':
                conn->quiet = 1;
                break;
            case 'r':
                conn->forcedumpdir = 1;
                break;
            case 's':
                if (optarg)
                    conn->sni = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'o':
                if (optarg)
                    conn->host_ip = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'p':
                if (optarg) {
                    conn->port = optarg;
                } else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'F':
                if (optarg)
                    conn->cafile = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'P':
                if (optarg)
                    conn->capath = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'c':
                if (optarg)
                    conn->clientcert = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'k':
                if (optarg)
                    conn->clientkey = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'L':
                if (optarg)
                    conn->cipherlist = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'w':
                if (optarg)
                    conn->clientpass = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'q':
                if (optarg)
                    conn->dumpdir = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 't':
                if (optarg) {
                    timeout_s = optarg;
                    conn->timeout = strtol(timeout_s, NULL, 10);
                    if (conn->timeout == 0) {
                        fprintf(stderr, "Error: can't convert input\n");
                        usage();
                    }
                } else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'V':
                if (optarg)
                    conn->csvfile = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case '?':
                fprintf(stderr, "Unknown option %s", optarg);
                break;
            case ':':
                fprintf(stderr, "Missing argument for %s", optarg);
                break;
        }
    }

    if (!conn->host_ip) {
        fprintf(stderr, "Error: Please specify a hostname/IP with the option --host\n");
        usage();
    }

    /* If only one is provided, use one or the other for the one or the other */
    if (!conn->clientcert && conn->clientkey) conn->clientcert = conn->clientkey;
    if (conn->clientcert && !conn->clientkey) conn->clientkey = conn->clientcert;

    /* OpenSSL init */
    if (global_ssl_init() == -1)
        exit(EXIT_FAILURE);

    return connect_to_serv_port(conn);
}

