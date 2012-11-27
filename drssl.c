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

#define CIPHER_LIST "ALL"

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
#define MSG_BLANK   ":                   :"


/* Types */
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
};


struct sslconn {
    SSL_CTX *ctx;
    BIO *bio;
    int sock;
    SSL *ssl;
    OCSP_RESPONSE *ocsp_stapling;
    char *cafile;
    char *capath;
    unsigned short sslversion;
    char *host_ip;
    char *sni;
    unsigned short port;
    int ipversion;

    /* struct certinfo *certinfo; */
    struct diagnostics *diagnostics;
    TAILQ_HEAD(, certinfo) certinfo_head;
};

/* Prototypes */
struct certinfo *create_certinfo(void);
struct sslconn *create_sslconn(void);
void global_ssl_init(void);
int x509IsCA(X509 *cert);
static int ocsp_resp_cb(SSL *s, void *arg);
static int verify_callback(int ok, X509_STORE_CTX *store_ctx);
int setup_client_ctx(struct sslconn *conn, unsigned short type);
int create_client_socket (int * client_socket, const char * server,
                          int port, int ipversion,
                          int time_out_milliseconds);
int connect_bio_to_serv_port(struct sslconn *conn);
int connect_ssl_over_socket(struct sslconn *conn);
int extract_subjectaltnames(struct certinfo *certinfo);
int extract_commonname(struct certinfo *certinfo);
int extract_certinfo_details(struct certinfo *certinfo);
int extract_peer_certinfo(struct sslconn *conn);
static int ocsp_certid_print(BIO *bp, OCSP_CERTID* a, int indent);
int extract_OCSP_RESPONSE_data(OCSP_RESPONSE* o, unsigned long flags);
void display_certinfo(struct certinfo *certinfo);
void display_conn_info(struct sslconn *conn);
void diagnose_conn_info(struct sslconn *conn);
int connect_to_serv_port (char *servername, unsigned short servport,
                          int ipversion,
                          unsigned short sslversion, char *cafile,
                          char *capath, char *sni);
void usage(void);
unsigned short compare_certinfo_to_X509(struct certinfo *certinfo, X509 *cert);
unsigned short find_X509_in_certinfo_tail(struct sslconn *conn, X509 *cert);
void diagnose_ocsp(struct sslconn *conn, OCSP_RESPONSE *ocsp,
                   X509 *origincert, unsigned short stapled);
time_t grid_asn1TimeToTimeT(unsigned char *asn1time, size_t len);
time_t my_timegm(struct tm *tm);
char *convert_time_t_to_utc_time_string(time_t t);


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
    if (!conn->diagnostics)
        goto fail;

    TAILQ_INIT(&(conn->certinfo_head));
    return conn;
fail:
    return NULL;
}

void
global_ssl_init(void) {
    SSL_library_init();
    SSL_load_error_strings();

    RAND_load_file("/dev/urandom", 1024);
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
        fprintf(stderr, "Error: Out of memory\n");
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

/* OCSP callback */
static int
ocsp_resp_cb(SSL *s, void *arg) {
    struct sslconn *conn = (struct sslconn *)arg;
    OCSP_RESPONSE *rsp;
    const unsigned char *p;
    int len;

    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    fprintf(stderr, "OCSP response: ");
    if (!p) {
        fprintf(stderr, "no response sent\n");
        return 1;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        fprintf(stderr, "response parse error\n");
        return 1;
    }
    fprintf(stderr, "got stapled response\n");

    /* Record stapled response */
    if (conn) {
        conn->ocsp_stapling = rsp;
    }

    return 1;
}

/* Custom verification callback */
static int
verify_callback(int ok, X509_STORE_CTX *store_ctx) {
    unsigned long   errnum   = X509_STORE_CTX_get_error(store_ctx);
    int             errdepth = X509_STORE_CTX_get_error_depth(store_ctx);
    const char *    logstr = "verify_callback";
    char            subject[256];
    char            issuer[256];

    X509 *curr_cert = X509_STORE_CTX_get_current_cert(store_ctx);

    fprintf(stderr, "%s: - Re-Verify certificate at depth: %i, pre-OK is: %d\n",
                    logstr, errdepth, ok);
    X509_NAME_oneline(X509_get_issuer_name(curr_cert), issuer, 256);
    fprintf(stderr, "%s:   issuer   = %s\n", logstr, issuer);
    X509_NAME_oneline(X509_get_subject_name(curr_cert), subject, 256);
    fprintf(stderr, "%s:   subject  = %s\n", logstr, subject);

    if (ok != 1) {
        switch (errnum) {
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                fprintf(stderr, "%s: Override Self-Signed certificate error.\n",
                                __func__);
                ok = 1;
                break;
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                fprintf(stderr, "%s: Unable to find the issuer (locally on disk) of the certificate now in evaluation.\n"\
                                "\tOptions: 1. Certificate was signed by an unknown CA, see the --capath and --cafile options to solve this perhaps.\n"\
                                "\t         2. The server didn't send an intermediate CA certificate to complete the certificate chain\n", __func__);
                break;
            default:
                fprintf(stderr, "%s:  errnum %d: %s\n",
                                logstr, (int) errnum, X509_verify_cert_error_string(errnum));
                break;
        }
    }

    return ok;
}


/* Use: 2(SSLv2), 3(SSLv3), 10(TLS1.0), 11(TLS1.1), 12(TLS1.2) */
int
setup_client_ctx(struct sslconn *conn, unsigned short type) {
    if (!conn)
        return -1;

    switch (type) {
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
            fprintf(stderr, "Wrong SSL version/type provided to %s()\n",
                    __func__);
            return -2;
    }
    conn->sslversion = type;

    SSL_CTX_set_verify_depth(conn->ctx, 20);
    if (SSL_CTX_set_cipher_list(conn->ctx, CIPHER_LIST) != 1) {
        fprintf(stderr, "Error in setting cipher list, " \
                        "no valid ciphers provided in \"%s\"\n",
                        CIPHER_LIST);
        return -3;
    }

    /* Add CA dir info */
    if ((conn->capath || conn->cafile) &&
        (1 != SSL_CTX_load_verify_locations(conn->ctx,
                                            conn->cafile,
                                            conn->capath))) {
        fprintf(stderr, "SSL_CTX_load_verify_locations failed\n");
    }

    /* Set custom callback */
    SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, verify_callback);

    /* Set up OCSP Stapling callback setup */
    SSL_CTX_set_tlsext_status_cb(conn->ctx, ocsp_resp_cb);
    SSL_CTX_set_tlsext_status_arg(conn->ctx, conn);

    return 0;
}


int
create_client_socket (int * client_socket,
                      const char * server,
                      int port,
                      int ipversion,
                      int time_out_milliseconds) {
    struct addrinfo  hints;
    struct addrinfo *res;
    int              rc;
    int              mysock = -1;
    char             portstr[24];

    struct timeval  *wait_tv = NULL;
    struct timeval   preset_tv;
    unsigned int     preset_tvlen = sizeof preset_tv;


    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = ipversion;

    /* Get addrinfo */
    snprintf(portstr, 24, "%d", port);
    rc = getaddrinfo(server, &portstr[0], &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to getaddrinfo (%s, %s, *, *)\n",
                server, portstr);
        return 1;
    }


    /* Create new socket */
    if ((mysock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        fprintf(stderr, "Error: Failed to create socket\n");
        return 1;
    }


    /* Grab timeout setting */
    if (getsockopt(mysock, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&preset_tv, &preset_tvlen) < 0) {
        fprintf(stderr, "Error: Failed to get the timeout setting\n");
        return 1;
    }


    /* Set connection timeout on the socket */
    wait_tv = (struct timeval *) malloc (sizeof (struct timeval));
    wait_tv->tv_sec = (time_out_milliseconds - (time_out_milliseconds % 1000)) / 1000;
    wait_tv->tv_usec = (time_out_milliseconds % 1000) * 1000;
    if (setsockopt(mysock, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)wait_tv, sizeof *wait_tv) < 0) {
        fprintf(stderr, "Error: Failed to set the timeout setting\n");
        return 1;
    }
    free (wait_tv);
    wait_tv = NULL;


    /* Connecting socket to host on port with timeout */
    if (connect(mysock, res -> ai_addr, res -> ai_addrlen) < 0) {
        fprintf(stderr, "Failed to connect\n");
        return 1;
    } else {
        /* Socket is succesfuly connected */
        setsockopt (mysock, SOL_SOCKET, SO_KEEPALIVE, 0, 0);

        *client_socket = mysock;
        return 0;
    }

    /* Failure */
    return 1;
}



/* Connect the struct sslconn object using a BIO */
int
connect_bio_to_serv_port(struct sslconn *conn) {
    int sock;

    fprintf(stderr, "%s\n", __func__);

    if (!conn || !conn->host_ip)
        return -1;

    if (create_client_socket (&sock, conn->host_ip, conn->port, conn->ipversion, 30*1000) != 0) {
        fprintf(stderr, "Error: failed to connect to \"%s\" on port \'%d\'\n",
                        conn->host_ip, conn->port);
        return -2;
    }
    fprintf(stderr, "Connected to \"%s\" on port \'%d\'\n",
            conn->host_ip, conn->port);
    conn->sock = sock;
    return 0;
}

/* Connect struct sslconn object using SSL over an existing BIO */
int
connect_ssl_over_socket(struct sslconn *conn) {
    fprintf(stderr, "%s\n", __func__);

    if (!conn || !conn->host_ip || !conn->sock)
        return -1;

    conn->ssl = SSL_new(conn->ctx);
    if (!conn->ssl) {
        return -2;
    }

    /* Setup OCSP stapling on the SSL object */
    SSL_set_tlsext_status_type(conn->ssl, TLSEXT_STATUSTYPE_ocsp);

    /* Set TLS SNI (Server Name Indication) */
    if (conn->sni && !SSL_set_tlsext_host_name(conn->ssl, conn->sni)) {
        fprintf(stderr, "Unable to set TLS servername extension (SNI).\n");
    }

    /* Connecting the Socket to the SSL layer */
    conn->bio = BIO_new_socket (conn->sock, BIO_NOCLOSE);
    if (!conn->bio) {
        fprintf(stderr, "Error: Failed to tie the socket to a SSL BIO\n");
        SSL_free(conn->ssl);
        return -3;
    }
    fprintf(stderr, "BIO created from socket\n");

    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
    if (SSL_connect(conn->ssl) <= 0) {
        fprintf(stderr, "Error connecting SSL\n");
        return -4;
    }



    return 0;
}

/* <0: error, 0: No SAN found, 1: SAN found */
int
extract_subjectaltnames(struct certinfo *certinfo) {
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

    fprintf(stderr, "%s\n", __func__);

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
                        fprintf(stderr, "Error: out of memory\n");
                        return -10;
                    }

                    if (!strcasecmp(nval->name, "DNS")) {
                        p_san->type = DNS;
                    } else if (!strcasecmp(nval->name, "iPAddress")) {
                        p_san->type = IP;
                    } else if (!strcasecmp(nval->name, "email")) {
                        p_san->type = EMAIL;
                    } else {
                        p_san->type = UNKNOWN;
                    }

                    p_san->value = strdup(nval->value);
                    if (!p_san->value) {
                        fprintf(stderr, "Error: out of memory\n");
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
extract_commonname(struct certinfo *certinfo) {
    X509_NAME *subj;
    int cnt;
    char *cn;

    fprintf(stderr, "%s\n", __func__);

    if (!certinfo || !certinfo->cert)
        return -1;

    subj = X509_get_subject_name(certinfo->cert);
    if (!subj) {
        fprintf(stderr, "Error: could not extract the Subject DN\n");
        return -2;
    }

    cnt = X509_NAME_get_text_by_NID(subj, NID_commonName, NULL, 0);
    cn = malloc(cnt + 1);
    if (!cn) {
        fprintf(stderr, "Error: out of memory\n");
        return -3;
    }
    cnt = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, cnt + 1);

    certinfo->commonname = cn;
    return 0;
}

int
extract_certinfo_details(struct certinfo *certinfo) {
    EVP_PKEY *pktmp;

    if (!certinfo)
        return -1;

    /* List and register the SubjectAltNames */
    if (extract_subjectaltnames(certinfo) < 0) {
        return -2;
    }

    /* Extract and register the Common Name */
    if (extract_commonname(certinfo) < 0) {
        return -3;
    }

    /* Check if peer cert is a CA, or something */
    certinfo->ca         = x509IsCA(certinfo->cert);
    certinfo->selfsigned = (X509_NAME_cmp(X509_get_subject_name(certinfo->cert),
                                          X509_get_issuer_name (certinfo->cert)) == 0);

    pktmp = X509_get_pubkey(certinfo->cert);
    certinfo->bits = EVP_PKEY_bits(pktmp);
    EVP_PKEY_free(pktmp);

    certinfo->subject_dn = X509_NAME_oneline(X509_get_subject_name(certinfo->cert), NULL, 0);
    certinfo->issuer_dn  = X509_NAME_oneline(X509_get_issuer_name(certinfo->cert), NULL, 0);

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

    fprintf(stderr, "%s\n", __func__);

    /* Record peer certificate */
    peer = SSL_get_peer_certificate(conn->ssl);
    if (!peer) {
        fprintf(stderr, "Error: No peer certificate found in SSL.\n");
        conn->diagnostics->has_peer = 0;
        return -2;
    } else {
        conn->diagnostics->has_peer = 1;
        certinfo = create_certinfo();
        if (!certinfo) {
            fprintf(stderr, "Error: Out of memory\n");
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
        fprintf(stderr, "Error: No peer certificate stack found in SSL\n");
        conn->diagnostics->has_stack = 0;
    } else {
        conn->diagnostics->has_stack = 1;
        depth = sk_X509_num(stack);
        for (i = 0; i < depth; i++) {
            /* De-dup */
            if (find_X509_in_certinfo_tail(conn, sk_X509_value(stack, i))) {
                fprintf(stderr, "Discard certificate alrady captured\n");
                continue;
            }

            certinfo = create_certinfo();
            if (!certinfo) {
                fprintf(stderr, "Error: Out of memory\n");
                return -5;
            }
            certinfo->at_depth = i;
            certinfo->cert = sk_X509_value(stack, i);

            TAILQ_INSERT_TAIL(&(conn->certinfo_head), certinfo, entries);
        }

        /* Loop over found certinfo structs to extract certificate details per certificate */
        for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
            extract_certinfo_details(certinfo);
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
    fprintf(stderr, ": Subject DN        : %s\n", tmp);
    free(tmp);
    tmp = X509_NAME_oneline(X509_get_issuer_name(certinfo->cert), NULL, 0);
    fprintf(stderr, ": Issuer DN         : %s\n", tmp);
    free(tmp);

    fprintf(stderr, ": Depth             : %u\n", certinfo->at_depth);
    fprintf(stderr, ": Public key bits(p): %d\n", certinfo->bits);

    for (p_san = TAILQ_FIRST(&(certinfo->san_head)); p_san != NULL; p_san = tmp_p_san) {
        fprintf(stderr, ": Subject Alt Name  : %s\n", p_san->value);
        tmp_p_san = TAILQ_NEXT(p_san, entries);
    }
    fprintf(stderr, ": Common name       : %s\n", certinfo->commonname);

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

    fprintf(stderr, MAKE_LIGHT_BLUE "=== Report ===" RESET_COLOR "\n");

    fprintf(stderr, ": Host/IP           : %s\n", conn->host_ip);
    fprintf(stderr, ": Port              : %d\n", conn->port);
    fprintf(stderr, ": IP version        : %s\n", conn->ipversion == PF_UNSPEC ?
                                                      "Unspecified, up to system defaults" :
                                                      conn->ipversion == AF_INET6 ?
                                                        "IPv6" :
                                                        conn->ipversion == AF_INET ?
                                                            "IPv4" :
                                                            MAKE_I_RED "Unknown" RESET_COLOR);
    fprintf(stderr, ": TLS ext SNI       : %s\n", conn->sni ? conn->sni : "not set");
    fprintf(stderr, ": Socket number     : %d\n", conn->sock);
    switch (conn->sslversion) {
        case  0: fprintf(stderr, ": Wished SSL version: NONE\n"); break;
        case  2: fprintf(stderr, ": Wished SSL version: SSLv2\n"); break;
        case  3: fprintf(stderr, ": Wished SSL version: SSLv3\n"); break;
        case 10: fprintf(stderr, ": Wished SSL version: TLS1.0\n"); break;
        case 11: fprintf(stderr, ": Wished SSL version: TLS1.1\n"); break;
        case 12: fprintf(stderr, ": Wished SSL version: TLS1.2\n"); break;
        default: fprintf(stderr, ": Wished SSL version: UNKNOWN\n"); break;
    }
    /* int SSL_version(conn->ssl); */
    /* DTLS1_VERSION */

    c = SSL_get_current_cipher(conn->ssl);
    fprintf(stderr, ": SSL Ciphers used  : %s / %s\n",
                    SSL_CIPHER_get_name(c), SSL_CIPHER_get_version(c));

    comp = SSL_get_current_compression(conn->ssl);
    fprintf(stderr, ": SSL Compression   : %s\n",
                    comp ? SSL_COMP_get_name(comp) : "NONE");

    expansion = SSL_get_current_expansion(conn->ssl);
    fprintf(stderr, ": SSL Expansion     : %s\n",
                    expansion ? SSL_COMP_get_name(expansion) : "NONE");

    /* Print the time from the random info */
    memcpy(&random_time, conn->ssl->s3->server_random, sizeof(uint32_t));
    server_time_s = ntohl(random_time);

    buf = convert_time_t_to_utc_time_string(server_time_s);
    if (!buf) {
        fprintf(stderr, "Error: Out of memory\n");
        return;
    }
    fprintf(stderr, ": random->unix_time : %lu, %s (utc/zulu)\n",
                    server_time_s, buf);
    free(buf);

    fprintf(stderr, ": Certificate?      : %s\n", conn->diagnostics->has_peer ? "Yes" : "No");
    fprintf(stderr, ": Stack?            : %s\n", conn->diagnostics->has_stack ? "Yes" : "No");

    /* Got certificate related information? */
    if (!(TAILQ_EMPTY(&(conn->certinfo_head)))) {
        for (certinfo = TAILQ_FIRST(&(conn->certinfo_head)); certinfo != NULL; certinfo = tmp_certinfo) {
            fprintf(stderr, ": " MAKE_GREEN "---" RESET_COLOR "\n");
            display_certinfo(certinfo);
            tmp_certinfo = TAILQ_NEXT(certinfo, entries); /* Next */
        }
        fprintf(stderr, ": " MAKE_GREEN "---" RESET_COLOR "\n");

        fprintf(stderr, ": OCSP Stapling     : %s\n", conn->ocsp_stapling ? "Yes" : "No");
        if (conn->ocsp_stapling) {
            fprintf(stderr, ": OCSP Stapled Resp.:\n");
            extract_OCSP_RESPONSE_data(conn->ocsp_stapling, 0);
        }

    } else {
        fprintf(stderr, ": No Certificate info from.\n");
    }

    return;
}


void
diagnose_ocsp(struct sslconn *conn, OCSP_RESPONSE *ocsp, X509 *origincert, unsigned short stapled) {
    int i, ret = 0, flags = 0;
    long l;
    char *tmp;
    time_t producedAt = 0;
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

    fprintf(stderr, MAKE_LIGHT_BLUE "=== Diagnose OCSP ===" RESET_COLOR "\n");
    fprintf(stderr, "%s OCSP Source %s\n", MSG_BLANK, stapled ? "OCSP Stapling" : "AIA record on certificate");

    /* OCSP Response status */
    l = ASN1_ENUMERATED_get(ocsp->responseStatus);
    if (l == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        fprintf(stderr, "%s OCSP Response Status is successful (generic OCSP answer)\n", MSG_OK);
    } else {
        fprintf(stderr, "%s OCSP Response Status is %s\n", MSG_ERROR, OCSP_response_status_str(l));
    }

    /* Actual bytes */
    if (!rb) {
        fprintf(stderr, "%s OCSP Response data is malformed or non-existant.\n", MSG_ERROR);
        return;
    }

    /* Only accept OCSP Basic response */
    if (OBJ_obj2nid(rb->responseType) == NID_id_pkix_OCSP_basic) {
        fprintf(stderr, "%s OCSP Response Type: Basic OCSP Response\n", MSG_OK);
    } else {
        fprintf(stderr, "%s OCSP Response Type: unknown response type\n", MSG_ERROR);
        return;
    }

    /* Get OCSP Response Basic */
    br = OCSP_response_get1_basic(ocsp);
    if (!br) {
        fprintf(stderr, "%s Malformed Response: Basic OCSP Response got not be retrieved\n", MSG_ERROR);
        return;
    }

    /* Get Raw RespData */
    rd = br->tbsResponseData;
    if (!rd) {
        fprintf(stderr, "%s Malformed Response: Raw Response data was not retrieved\n", MSG_ERROR);
        return;
    }

    /* OCSP Response Version */
    l = ASN1_INTEGER_get(rd->version);
    if (l != 0) {
        fprintf(stderr, "%s Unsupported OCSP Response version: %lu\n", MSG_ERROR, l + 1);
        return;
    }

    /* Responder ID */
    rid = rd->responderId;
    if (!rid) {
        fprintf(stderr, "%s Malformed Response: No Responder ID found\n", MSG_ERROR);
        return;
    }
    switch (rid->type) {
        case V_OCSP_RESPID_NAME:
            tmp = X509_NAME_oneline(rid->value.byName, NULL, 0);
            fprintf(stderr, "%s Responder ID (byName): \"%s\"\n", MSG_BLANK, tmp);
            free(tmp);
            break;
        case V_OCSP_RESPID_KEY:
            u_tmp = ASN1_STRING_data(rid->value.byKey);
            fprintf(stderr, "%s Responder ID (byKey): \'%s\'\n", MSG_BLANK, u_tmp);
            free(u_tmp);
            break;
    }

    /* Check, and if so convert, the producedAt time */
    if (rd->producedAt &&
        (u_tmp = ASN1_STRING_data(rd->producedAt)) &&
        u_tmp) {
        producedAt = grid_asn1TimeToTimeT(u_tmp, strlen((char *)u_tmp));
        tmp = convert_time_t_to_utc_time_string(producedAt);
        if (!tmp) {
            fprintf(stderr, "Error: Out of memory\n");
            return;
        }
        if (producedAt < (time(NULL) - (3600 * 24 * 14))) {
            fprintf(stderr, "%s The OCSP Response indicates to be produced more then 2 weeks ago on: %s UTC/Zulu\n", MSG_ERROR, convert_time_t_to_utc_time_string(producedAt));
        } else if (producedAt < (time(NULL) - (3600 * 24 * 4))) {
            fprintf(stderr, "%s The OCSP Response indicates to be produced more then 4 days ago on: %s UTC/Zulu\n", MSG_WARNING, convert_time_t_to_utc_time_string(producedAt));
        } else {
            fprintf(stderr, "%s The OCSP Response indicates to be newer then 4 days on: %s UTC/Zulu\n", MSG_OK, convert_time_t_to_utc_time_string(producedAt));
        }
        free(tmp);
    }


    /* Debug cut off hack */
    return;


    BIO *bp;
    bp = BIO_new_fp(stderr,BIO_NOCLOSE);

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
    return;
}

void
diagnose_conn_info(struct sslconn *conn) {
    struct certinfo       *certinfo, *tmp_certinfo;
    struct certinfo       *peer_certinfo;
    struct subjectaltname *p_san, *tmp_p_san;
    /* uint32_t               random_time; */
    /* time_t                 server_time_s; */
    /* struct tm              result; */
    /* const SSL_CIPHER      *c; */
    unsigned short         found_san = 0;
    int                    ssl_verify_result;

    if (!conn)
        return;

    fprintf(stderr, MAKE_LIGHT_BLUE "=== Diagnoses ===" RESET_COLOR "\n");

    ssl_verify_result = SSL_get_verify_result(conn->ssl);
    switch (ssl_verify_result) {
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            fprintf(stderr, "%s SSL certificate is self signed\n", MSG_ERROR);
            break;
        case X509_V_OK:
            fprintf(stderr, "%s SSL certificate verification passed\n", MSG_OK);
            break;
        default:
            fprintf(stderr, "%s SSL certification verification error: %d\n",
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
            fprintf(stderr, "%s Server configuration error, a Root CA was "\
                            "sent by the service. SSL stack must ignore this certificate.\n",
                            MSG_WARNING);
        }
        if (conn->diagnostics->peer_has_ca_true) {
            fprintf(stderr, "%s The peer/host certificate has the CA:True setting in "\
                            "the certificate. This makes no sense.\n",
                            MSG_ERROR);
        }
        if (conn->diagnostics->peer_uses_selfsigned) {
            fprintf(stderr, "%s The peer/host certificate uses a self-signed certificate. "\
                            "Establishing trust is impossible\n",
                            MSG_ERROR);
        }
    }

    /* RFC2818 compliance, i.e. Got SAN?->Check SAN, leave CN. No SAN?
     * (seriously...)->Check CN.
     * Or bypass all and check something else known. (Not implemented yet) */
    if (peer_certinfo) {
        if (TAILQ_EMPTY(&(peer_certinfo->san_head))) {
            fprintf(stderr, "%s RFC2818 check: Peer certificate is a legacy "\
                            "certificate as it features no Subject Alt Names\n",
                            MSG_WARNING);

            /* Check Common Name */
            if (!strcasecmp(peer_certinfo->commonname, conn->host_ip)) {
                fprintf(stderr, "%s RFC2818 check: legacy peer certificate "\
                                "matched most significant Common Name.\n",
                                MSG_OK);
            } else {
                fprintf(stderr, "%s RFC2818 check failed: legacy peer certificate's "\
                                "most significant Common Name did not match the "\
                                "Hostname or IP address of the server. Untrusted "\
                                "connection.\n",
                                MSG_ERROR);
            }
        } else {
            /* Check SAN */
            for (p_san = TAILQ_FIRST(&(peer_certinfo->san_head)); p_san != NULL; p_san = tmp_p_san) {
                if (!strcasecmp(p_san->value, conn->host_ip)) {
                    fprintf(stderr, "%s RFC2818 check: peer certificate matched "\
                                    "Subject Alt Name\n",
                                    MSG_OK);
                    found_san = 1;
                }
                tmp_p_san = TAILQ_NEXT(p_san, entries);
            }
            if (!found_san) {
                fprintf(stderr, "%s RFC2818 check failed: Peer certificate has "\
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
                fprintf(stderr, "%s The certificate with Subject DN \"%s\" is a small and weak "\
                                "public key length of \'%d\' bits. This is really really bad. "\
                                "This means the security of the certificate can be easily "\
                                "broken with a fast enough computer. Advise: replace it NOW "\
                                "with a new certificate of at least 1024 bits, preferable "\
                                "2048 bits or more.\n",
                                MSG_ERROR,
                                certinfo->subject_dn ? certinfo->subject_dn : "<No Subject DN>",
                                certinfo->bits);
            } else if (certinfo->bits < 1400) {
                fprintf(stderr, "%s The certificate with Subject DN \"%s\" has a weak public "\
                                "key length of \'%d\' bits. This means the security of the "\
                                "certificate can be broken with a fast enough computer. "\
                                "Advise: replace it with a higher quality certificate of at "\
                                "least 2048 bits.\n",
                                MSG_WARNING,
                                certinfo->subject_dn ? certinfo->subject_dn : "<No Subject DN>",
                                certinfo->bits);
            } else if (certinfo->bits >= 1400) {
                fprintf(stderr, "%s The certificate with Subject DN \"%s\" has a strong public "\
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


    /* CRL check, (could use libcurl here) */
    return;
}

int
connect_to_serv_port(char *servername,
                     unsigned short servport,
                     int ipversion,
                     unsigned short sslversion,
                     char *cafile,
                     char *capath,
                     char *sni) {
    struct sslconn *conn;

    fprintf(stderr, "%s\n", __func__);

    if (!servername) {
        fprintf(stderr, "Error: no host specified\n");
        return -1;
    }

    /* conn = calloc(sizeof(struct sslconn), 1); */
    conn = create_sslconn();
    if (conn == NULL)
        return -1;

    conn->host_ip   = servername;
    conn->port      = servport;
    conn->ipversion = ipversion;
    conn->cafile    = cafile;
    conn->capath    = capath;
    conn->sni       = sni;

    /* Create SSL context */
    if (setup_client_ctx(conn, sslversion) < 0) {
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
    fprintf(stderr, "SSL Connection opened\n");

    /* Extract peer cert */
    if (extract_peer_certinfo(conn) < 0) {
        return -5;
    }

    /* Display / Show the information we gathered */
    display_conn_info(conn);

    /* Display / Show the information we gathered */
    diagnose_conn_info(conn);

    fprintf(stderr, "SSL Shutting down.\n");
    SSL_shutdown(conn->ssl);
    fprintf(stderr, "SSL Connection closed\n");

    SSL_clear(conn->ssl);
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ctx);
    return 0;
}


void
usage(void) {
    printf("\n");
    printf("DrSSL - diagnose your SSL\n");
    printf("\t--help\n");
    printf("\t--host <host or IP>\n");
    printf("\t--port <port> - default is: 443\n");
    printf("\t--4 (force IPv4 - default is system specific)\n");
    printf("\t--6 (force IPv6 - default is system specific)\n");
    printf("\n");
    printf("\t--2 (use SSLv2)\n");
    printf("\t--3 (use SSLv3)\n");
    printf("\t--10 (use TLSv1.0) - the default\n");
    printf("\t--11 (use TLSv1.1)\n");
    printf("\t--12 (use TLSv1.2)\n");
    printf("\t--cafile <path to CA (bundle) file>\n");
    printf("\t--capath <path to CA directory>\n");
    printf("\t--sni <TLS SNI (Server Name Indication) hostname>\n");
    printf("\n");

    return;
}


int main(int argc, char *argv[]) {
    int option_index = 0, c = 0;    /* getopt */
    int sslversion = 10;
    int ipversion = PF_UNSPEC; /* System preference is leading */
    char *servername = NULL;
    char *cafile = NULL;
    char *capath = NULL;
    char *sni = NULL;
    unsigned short port = 443;
    long port_l = 0;

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
        {"capath" ,     required_argument, 0, 'P'}
    };

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
                return 0;
            case '2':
                sslversion = 2;
                break;
            case '3':
                sslversion = 3;
                break;
            case '4':
                ipversion = AF_INET;
                break;
            case '6':
                ipversion = AF_INET6;
                break;
            case 'A':
                sslversion = 10;
                break;
            case 'B':
                sslversion = 11;
                break;
            case 'C':
                sslversion = 12;
                break;
            case 's':
                if (optarg)
                    sni = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'o':
                if (optarg)
                    servername = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'p':
                if (optarg) {
                    port_l = strtol(optarg, NULL, 10);
                    if ((port_l < 0) || (port_l > 65535)) {
                        fprintf(stderr, "Error: value for port is larger then "\
                                        "an unsigned 2^16 integer (or short)\n");
                        return 1;
                    }
                    port = port_l;
                } else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'F':
                if (optarg)
                    cafile = optarg;
                else {
                    fprintf(stderr, "Error: expecting a parameter.\n");
                    usage();
                }
                break;
            case 'P':
                if (optarg)
                    capath = optarg;
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

    /* OpenSSL init */
    global_ssl_init();

    return connect_to_serv_port(servername, port, ipversion, sslversion, cafile, capath, sni);
}

