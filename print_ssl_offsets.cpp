#include <cinttypes>
#include <cstddef>
#include <cstdlib>
#include <cstdio>

// # define OPENSSL_NO_CT
// # define OPENSSL_NO_ENGINE
// # define OPENSSL_NO_EC
// # define OPENSSL_NO_NEXTPROTONEG
// # define OPENSSL_NO_PSK
// # define OPENSSL_NO_SRP
// # define OPENSSL_NO_SRTP

# define STACK_OF(type) struct stack_st_##type
# define LHASH_OF(type) struct lhash_st_##type
# define TSAN_QUALIFIER volatile
# define SSL_MAX_SID_CTX_LENGTH                  32
# define TLSEXT_KEYNAME_LENGTH  16
# define TLSEXT_TICK_KEY_LENGTH 32
# define SHA256_DIGEST_LENGTH    32
# define EVP_MAX_MD_SIZE                 64
# define EVP_MAX_IV_LENGTH               16
# define SSL_MAX_SSL_SESSION_ID_LENGTH           32

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_session_st SSL_SESSION;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_st X509;
typedef int CRYPTO_REF_COUNT;
struct crypto_ex_data_st {
    STACK_OF(void) *sk;
};
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
typedef struct evp_md_st EVP_MD;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct comp_ctx_st COMP_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);
typedef int (*GEN_SESSION_CB) (SSL *ssl, unsigned char *id, unsigned int *id_len);
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
typedef struct ctlog_store_st CTLOG_STORE;
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;
typedef int (*ssl_ct_validation_cb)(const CT_POLICY_EVAL_CTX *ctx, const STACK_OF(SCT) *scts, void *arg);
typedef int (*SSL_client_hello_cb_fn) (SSL *s, int *al, void *arg);
typedef struct engine_st ENGINE;
typedef struct hmac_ctx_st HMAC_CTX;
typedef struct ssl_ctx_ext_secure_st SSL_CTX_EXT_SECURE;
typedef int (*SSL_CTX_npn_advertised_cb_func)(SSL *ssl,
                                              const unsigned char **out,
                                              unsigned int *outlen,
                                              void *arg);
typedef int (*SSL_CTX_npn_select_cb_func)(SSL *s,
                                          unsigned char **out,
                                          unsigned char *outlen,
                                          const unsigned char *in,
                                          unsigned int inlen,
                                          void *arg);
typedef unsigned int (*SSL_psk_client_cb_func)(SSL *ssl,
                                               const char *hint,
                                               char *identity,
                                               unsigned int max_identity_len,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);
typedef unsigned int (*SSL_psk_server_cb_func)(SSL *ssl,
                                               const char *identity,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);
typedef int (*SSL_psk_find_session_cb_func)(SSL *ssl,
                                            const unsigned char *identity,
                                            size_t identity_len,
                                            SSL_SESSION **sess);
typedef int (*SSL_psk_use_session_cb_func)(SSL *ssl, const EVP_MD *md,
                                           const unsigned char **id,
                                           size_t *idlen,
                                           SSL_SESSION **sess);
typedef struct bignum_st BIGNUM;
typedef struct srp_ctx_st {
    /* param for all the callbacks */
    void *SRP_cb_arg;
    /* set client Hello login callback */
    int (*TLS_ext_srp_username_callback) (SSL *, int *, void *);
    /* set SRP N/g param callback for verification */
    int (*SRP_verify_param_callback) (SSL *, void *);
    /* set SRP client passwd callback */
    char *(*SRP_give_srp_client_pwd_callback) (SSL *, void *);
    char *login;
    BIGNUM *N, *g, *s, *B, *A;
    BIGNUM *a, *b, *v;
    char *info;
    int strength;
    unsigned long srp_Mask;
} SRP_CTX;
typedef struct danetls_record_st danetls_record;
struct dane_ctx_st {
    const EVP_MD  **mdevp;      /* mtype -> digest */
    uint8_t        *mdord;      /* mtype -> preference */
    uint8_t         mdmax;      /* highest supported mtype */
    unsigned long   flags;      /* feature bitmask */
};
struct ssl_dane_st {
    struct dane_ctx_st *dctx;
    STACK_OF(danetls_record) *trecs;
    STACK_OF(X509) *certs;      /* DANE-TA(2) Cert(0) Full(0) certs */
    danetls_record *mtlsa;      /* Matching TLSA record */
    X509           *mcert;      /* DANE matched cert */
    uint32_t        umask;      /* Usages present */
    int             mdpth;      /* Depth of matched cert */
    int             pdpth;      /* Depth of PKIX trust */
    unsigned long   flags;      /* feature bitmask */
};
typedef struct ssl_dane_st SSL_DANE;
typedef void CRYPTO_RWLOCK;
typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);
typedef int (*SSL_CTX_generate_session_ticket_fn)(SSL *s, void *arg);
typedef int SSL_TICKET_STATUS;
typedef int SSL_TICKET_RETURN;
typedef SSL_TICKET_RETURN (*SSL_CTX_decrypt_session_ticket_fn)(SSL *s, SSL_SESSION *ss,
                                                               const unsigned char *keyname,
                                                               size_t keyname_length,
                                                               SSL_TICKET_STATUS status,
                                                               void *arg);
typedef int (*SSL_allow_early_data_cb_fn)(SSL *s, void *arg);
typedef struct bio_st BIO;

typedef enum {} WORK_STATE;
typedef enum {} WRITE_TRAN;
typedef enum {} MSG_FLOW_STATE;
typedef enum {} READ_STATE;
typedef enum {} WRITE_STATE;
typedef enum {} ENC_WRITE_STATES;
typedef enum {} ENC_READ_STATES;
typedef enum {} OSSL_HANDSHAKE_STATE;
typedef enum {} SSL_EARLY_DATA_STATE;
struct ossl_statem_st {
    MSG_FLOW_STATE state;
    WRITE_STATE write_state;
    WORK_STATE write_state_work;
    READ_STATE read_state;
    WORK_STATE read_state_work;
    OSSL_HANDSHAKE_STATE hand_state;
    /* The handshake state requested by an API call (e.g. HelloRequest) */
    OSSL_HANDSHAKE_STATE request_state;
    int in_init;
    int read_state_first_init;
    /* true when we are actually in SSL_accept() or SSL_connect() */
    int in_handshake;
    /*
     * True when are processing a "real" handshake that needs cleaning up (not
     * just a HelloRequest or similar).
     */
    int cleanuphand;
    /* Should we skip the CertificateVerify message? */
    unsigned int no_cert_verify;
    int use_timer;
    ENC_WRITE_STATES enc_write_state;
    ENC_READ_STATES enc_read_state;
};
typedef struct ossl_statem_st OSSL_STATEM;
typedef struct buf_mem_st BUF_MEM;

// Version: OpenSSL 1.1.1b

struct ssl_ctx_st {
    const SSL_METHOD *method;
    STACK_OF(SSL_CIPHER) *cipher_list;
    /* same as above but sorted for lookup */
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /* TLSv1.3 specific ciphersuites */
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
    struct x509_store_st /* X509_STORE */ *cert_store;
    LHASH_OF(SSL_SESSION) *sessions;
    /*
     * Most session-ids that will be cached, default is
     * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
     */
    size_t session_cache_size;
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
    /*
     * This can have one of 2 values, ored together, SSL_SESS_CACHE_CLIENT,
     * SSL_SESS_CACHE_SERVER, Default is SSL_SESSION_CACHE_SERVER, which
     * means only SSL_accept will cache SSL_SESSIONS.
     */
    uint32_t session_cache_mode;
    /*
     * If timeout is not 0, it is the default timeout value set when
     * SSL_new() is called.  This has been put in to make life easier to set
     * things up
     */
    long session_timeout;
    /*
     * If this callback is not null, it will be called each time a session id
     * is added to the cache.  If this function returns 1, it means that the
     * callback will do a SSL_SESSION_free() when it has finished using it.
     * Otherwise, on 0, it means the callback has finished with it. If
     * remove_session_cb is not null, it will be called when a session-id is
     * removed from the cache.  After the call, OpenSSL will
     * SSL_SESSION_free() it.
     */
    int (*new_session_cb) (struct ssl_st *ssl, SSL_SESSION *sess);
    void (*remove_session_cb) (struct ssl_ctx_st *ctx, SSL_SESSION *sess);
    SSL_SESSION *(*get_session_cb) (struct ssl_st *ssl,
                                    const unsigned char *data, int len,
                                    int *copy);
    struct {
        TSAN_QUALIFIER int sess_connect;       /* SSL new conn - started */
        TSAN_QUALIFIER int sess_connect_renegotiate; /* SSL reneg - requested */
        TSAN_QUALIFIER int sess_connect_good;  /* SSL new conne/reneg - finished */
        TSAN_QUALIFIER int sess_accept;        /* SSL new accept - started */
        TSAN_QUALIFIER int sess_accept_renegotiate; /* SSL reneg - requested */
        TSAN_QUALIFIER int sess_accept_good;   /* SSL accept/reneg - finished */
        TSAN_QUALIFIER int sess_miss;          /* session lookup misses */
        TSAN_QUALIFIER int sess_timeout;       /* reuse attempt on timeouted session */
        TSAN_QUALIFIER int sess_cache_full;    /* session removed due to full cache */
        TSAN_QUALIFIER int sess_hit;           /* session reuse actually done */
        TSAN_QUALIFIER int sess_cb_hit;        /* session-id that was not in
                                                * the cache was passed back via
                                                * the callback. This indicates
                                                * that the application is
                                                * supplying session-id's from
                                                * other processes - spooky
                                                * :-) */
    } stats;

    CRYPTO_REF_COUNT references;

    /* if defined, these override the X509_verify_cert() calls */
    int (*app_verify_callback) (X509_STORE_CTX *, void *);
    void *app_verify_arg;
    /*
     * before OpenSSL 0.9.7, 'app_verify_arg' was ignored
     * ('app_verify_callback' was called with just one argument)
     */

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;

    /* Default password callback user data. */
    void *default_passwd_callback_userdata;

    /* get client cert callback */
    int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey);

    /* cookie generate callback */
    int (*app_gen_cookie_cb) (SSL *ssl, unsigned char *cookie,
                              unsigned int *cookie_len);

    /* verify cookie callback */
    int (*app_verify_cookie_cb) (SSL *ssl, const unsigned char *cookie,
                                 unsigned int cookie_len);

    /* TLS1.3 app-controlled cookie generate callback */
    int (*gen_stateless_cookie_cb) (SSL *ssl, unsigned char *cookie,
                                    size_t *cookie_len);

    /* TLS1.3 verify app-controlled cookie callback */
    int (*verify_stateless_cookie_cb) (SSL *ssl, const unsigned char *cookie,
                                       size_t cookie_len);

    CRYPTO_EX_DATA ex_data;

    const EVP_MD *md5;          /* For SSLv3/TLSv1 'ssl3-md5' */
    const EVP_MD *sha1;         /* For SSLv3/TLSv1 'ssl3->sha1' */

    STACK_OF(X509) *extra_certs;
    STACK_OF(SSL_COMP) *comp_methods; /* stack of SSL_COMP, SSLv3/TLSv1 */

    /* Default values used when no per-SSL value is defined follow */

    /* used if SSL's info_callback is NULL */
    void (*info_callback) (const SSL *ssl, int type, int val);

    /*
     * What we put in certificate_authorities extension for TLS 1.3
     * (ClientHello and CertificateRequest) or just client cert requests for
     * earlier versions. If client_ca_names is populated then it is only used
     * for client cert requests, and in preference to ca_names.
     */
    STACK_OF(X509_NAME) *ca_names;
    STACK_OF(X509_NAME) *client_ca_names;

    /*
     * Default values to use in SSL structures follow (these are copied by
     * SSL_new)
     */

    uint32_t options;
    uint32_t mode;
    int min_proto_version;
    int max_proto_version;
    size_t max_cert_list;

    struct cert_st /* CERT */ *cert;
    int read_ahead;

    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;

    uint32_t verify_mode;
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* called 'verify_callback' in the SSL */
    int (*default_verify_callback) (int ok, X509_STORE_CTX *ctx);

    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;

    X509_VERIFY_PARAM *param;

    int quiet_shutdown;

# ifndef OPENSSL_NO_CT
    CTLOG_STORE *ctlog_store;   /* CT Log Store */
    /*
     * Validates that the SCTs (Signed Certificate Timestamps) are sufficient.
     * If they are not, the connection should be aborted.
     */
    ssl_ct_validation_cb ct_validation_callback;
    void *ct_validation_callback_arg;
# endif

    /*
     * If we're using more than one pipeline how should we divide the data
     * up between the pipes?
     */
    size_t split_send_fragment;
    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    size_t max_send_fragment;

    /* Up to how many pipelines should we use? If 0 then 1 is assumed */
    size_t max_pipelines;

    /* The default read buffer length to use (0 means not set) */
    size_t default_read_buf_len;

# ifndef OPENSSL_NO_ENGINE
    /*
     * Engine to pass requests for client certs to
     */
    ENGINE *client_cert_engine;
# endif

    /* ClientHello callback.  Mostly for extensions, but not entirely. */
    SSL_client_hello_cb_fn client_hello_cb;
    void *client_hello_cb_arg;

    /* TLS extensions. */
    struct {
        /* TLS extensions servername callback */
        int (*servername_cb) (SSL *, int *, void *);
        void *servername_arg;
        /* RFC 4507 session ticket keys */
        unsigned char tick_key_name[TLSEXT_KEYNAME_LENGTH];
        SSL_CTX_EXT_SECURE *secure;
        /* Callback to support customisation of ticket key setting */
        int (*ticket_key_cb) (SSL *ssl,
                              unsigned char *name, unsigned char *iv,
                              EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

        /* certificate status request info */
        /* Callback for status request */
        int (*status_cb) (SSL *ssl, void *arg);
        void *status_arg;
        /* ext status type used for CSR extension (OCSP Stapling) */
        int status_type;
        /* RFC 4366 Maximum Fragment Length Negotiation */
        uint8_t max_fragment_len_mode;

# ifndef OPENSSL_NO_EC
        /* EC extension values inherited by SSL structure */
        size_t ecpointformats_len;
        unsigned char *ecpointformats;
        size_t supportedgroups_len;
        uint16_t *supportedgroups;
# endif                         /* OPENSSL_NO_EC */

        /*
         * ALPN information (we are in the process of transitioning from NPN to
         * ALPN.)
         */

        /*-
         * For a server, this contains a callback function that allows the
         * server to select the protocol for the connection.
         *   out: on successful return, this must point to the raw protocol
         *        name (without the length prefix).
         *   outlen: on successful return, this contains the length of |*out|.
         *   in: points to the client's list of supported protocols in
         *       wire-format.
         *   inlen: the length of |in|.
         */
        int (*alpn_select_cb) (SSL *s,
                               const unsigned char **out,
                               unsigned char *outlen,
                               const unsigned char *in,
                               unsigned int inlen, void *arg);
        void *alpn_select_cb_arg;

        /*
         * For a client, this contains the list of supported protocols in wire
         * format.
         */
        unsigned char *alpn;
        size_t alpn_len;

# ifndef OPENSSL_NO_NEXTPROTONEG
        /* Next protocol negotiation information */

        /*
         * For a server, this contains a callback function by which the set of
         * advertised protocols can be provided.
         */
        SSL_CTX_npn_advertised_cb_func npn_advertised_cb;
        void *npn_advertised_cb_arg;
        /*
         * For a client, this contains a callback function that selects the next
         * protocol from the list provided by the server.
         */
        SSL_CTX_npn_select_cb_func npn_select_cb;
        void *npn_select_cb_arg;
# endif

        unsigned char cookie_hmac_key[SHA256_DIGEST_LENGTH];
    } ext;

# ifndef OPENSSL_NO_PSK
    SSL_psk_client_cb_func psk_client_callback;
    SSL_psk_server_cb_func psk_server_callback;
# endif
    SSL_psk_find_session_cb_func psk_find_session_cb;
    SSL_psk_use_session_cb_func psk_use_session_cb;

# ifndef OPENSSL_NO_SRP
    SRP_CTX srp_ctx;            /* ctx for SRP authentication */
# endif

    /* Shared DANE context */
    struct dane_ctx_st dane;

# ifndef OPENSSL_NO_SRTP
    /* SRTP profiles we are willing to do from RFC 5764 */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
# endif
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);

    CRYPTO_RWLOCK *lock;

    /*
     * Callback for logging key material for use with debugging tools like
     * Wireshark. The callback should log `line` followed by a newline.
     */
    SSL_CTX_keylog_cb_func keylog_callback;

    /*
     * The maximum number of bytes advertised in session tickets that can be
     * sent as early data.
     */
    uint32_t max_early_data;

    /*
     * The maximum number of bytes of early data that a server will tolerate
     * (which should be at least as much as max_early_data).
     */
    uint32_t recv_max_early_data;

    /* TLS1.3 padding callback */
    size_t (*record_padding_cb)(SSL *s, int type, size_t len, void *arg);
    void *record_padding_arg;
    size_t block_padding;

    /* Session ticket appdata */
    SSL_CTX_generate_session_ticket_fn generate_ticket_cb;
    SSL_CTX_decrypt_session_ticket_fn decrypt_ticket_cb;
    void *ticket_cb_data;

    /* The number of TLS1.3 tickets to automatically send */
    size_t num_tickets;

    /* Callback to determine if early_data is acceptable or not */
    SSL_allow_early_data_cb_fn allow_early_data_cb;
    void *allow_early_data_cb_data;

    /* Do we advertise Post-handshake auth support? */
    int pha_enabled;
};


struct ssl_st {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
    /*
     * This holds a variable that indicates what we were doing when a 0 or -1
     * is returned.  This is needed for non-blocking IO so we know what
     * request needs re-doing when in SSL_accept or SSL_connect
     */
    int rwstate;
    int (*handshake_func) (SSL *);
    /*
     * Imagine that here's a boolean member "init" that is switched as soon
     * as SSL_set_{accept/connect}_state is called for the first time, so
     * that "state" and "handshake_func" are properly initialized.  But as
     * handshake_func is == 0 until then, we use this test instead of an
     * "init" member.
     */
    /* are we the server side? */
    int server;
    /*
     * Generate a new session or reuse an old one.
     * NB: For servers, the 'new' session may actually be a previously
     * cached session or even the previous session unless
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
     */
    int new_session;
    /* don't send shutdown packets */
    int quiet_shutdown;
    /* we have shut things down, 0x01 sent, 0x02 for received */
    int shutdown;
    /* where we are */
    OSSL_STATEM statem;
    SSL_EARLY_DATA_STATE early_data_state;
    BUF_MEM *init_buf;          /* buffer used during init */
    void *init_msg;             /* pointer to handshake message body, set by
                                 * ssl3_get_message() */
    size_t init_num;               /* amount read/written */
    size_t init_off;               /* amount read/written */
    struct ssl3_state_st *s3;   /* SSLv3 variables */
    struct dtls1_state_st *d1;  /* DTLSv1 variables */
    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;
    int hit;                    /* reusing a previous session */
    X509_VERIFY_PARAM *param;
    /* Per connection DANE state */
    SSL_DANE dane;
    /* crypto */
    STACK_OF(SSL_CIPHER) *cipher_list;
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /* TLSv1.3 specific ciphersuites */
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
    /*
     * These are the ones being used, the ones in SSL_SESSION are the ones to
     * be 'copied' into these ones
     */
    uint32_t mac_flags;
    /*
     * The TLS1.3 secrets.
     */
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    unsigned char handshake_secret[EVP_MAX_MD_SIZE];
    unsigned char master_secret[EVP_MAX_MD_SIZE];
    unsigned char resumption_master_secret[EVP_MAX_MD_SIZE];
    unsigned char client_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_hash[EVP_MAX_MD_SIZE];
    unsigned char handshake_traffic_hash[EVP_MAX_MD_SIZE];
    unsigned char client_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char server_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char exporter_master_secret[EVP_MAX_MD_SIZE];
    unsigned char early_exporter_master_secret[EVP_MAX_MD_SIZE];
    EVP_CIPHER_CTX *enc_read_ctx; /* cryptographic state */
    unsigned char read_iv[EVP_MAX_IV_LENGTH]; /* TLSv1.3 static read IV */
    EVP_MD_CTX *read_hash;      /* used for mac generation */
    COMP_CTX *compress;         /* compression */
    COMP_CTX *expand;           /* uncompress */
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    unsigned char write_iv[EVP_MAX_IV_LENGTH]; /* TLSv1.3 static write IV */
    EVP_MD_CTX *write_hash;     /* used for mac generation */
    /* session info */
    /* client cert? */
    /* This is used to hold the server certificate used */
    struct cert_st /* CERT */ *cert;

    /*
     * The hash of all messages prior to the CertificateVerify, and the length
     * of that hash.
     */
    unsigned char cert_verify_hash[EVP_MAX_MD_SIZE];
    size_t cert_verify_hash_len;

    /* Flag to indicate whether we should send a HelloRetryRequest or not */
    enum {SSL_HRR_NONE = 0, SSL_HRR_PENDING, SSL_HRR_COMPLETE}
        hello_retry_request;

    /*
     * the session_id_context is used to ensure sessions are only reused in
     * the appropriate context
     */
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* This can also be in the session once a session is established */
    SSL_SESSION *session;
    /* TLSv1.3 PSK session */
    SSL_SESSION *psksession;
    unsigned char *psksession_id;
    size_t psksession_id_len;
    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;
    /*
     * The temporary TLSv1.3 session id. This isn't really a session id at all
     * but is a random value sent in the legacy session id field.
     */
    unsigned char tmp_session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    size_t tmp_session_id_len;
    /* Used in SSL3 */
    /*
     * 0 don't care about verify failure.
     * 1 fail if verify fails
     */
    uint32_t verify_mode;
    /* fail if callback returns 0 */
    int (*verify_callback) (int ok, X509_STORE_CTX *ctx);
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);
    /* error bytes to be written */
    int error;
    /* actual code */
    int error_code;
# ifndef OPENSSL_NO_PSK
    SSL_psk_client_cb_func psk_client_callback;
    SSL_psk_server_cb_func psk_server_callback;
# endif
    SSL_psk_find_session_cb_func psk_find_session_cb;
    SSL_psk_use_session_cb_func psk_use_session_cb;

    SSL_CTX *ctx;
};

int main() {
    printf("offsetof(SSL, ctx) = %u\n", (uint32_t)offsetof(SSL, ctx));
    printf("offsetof(SSL_CTX, keylog_callback) = %u\n", (uint32_t)offsetof(SSL_CTX, keylog_callback));
}
