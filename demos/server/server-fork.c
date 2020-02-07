/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/cipher.h"

#define HTTP_RESPONSE \
  "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
  "<h2>mbed TLS Test Server</h2>\r\n" \
  "<p>Successful connection using: %s</p>\r\n"

int SGX_DEBUG = 0;
int g_fd;

int customized_net_recv(void *ctx, unsigned char *buf, size_t len )
{
  int ret;
  //int fd = g_fd;
  int fd = *(int *)ctx;

  if (fd < 0)
    return 0;

  ret = (int) read( fd, buf, len );

  printf("read: %d\n", ret);
  if (ret < 0) {
    return( MBEDTLS_ERR_SSL_WANT_READ );
  }

  return( ret );
}

int customized_net_send( void *ctx, const unsigned char *buf, size_t len )
{
  int ret;
  //int fd = g_fd;
  int fd = *(int *)ctx;

  if (fd < 0)
    return 0;

  ret = (int) write( fd, buf, len );

  printf("write: %d\n", ret);
  if( ret < 0 ) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  return( ret );
}

void main()
{
  int listenfd = 0;
  int connfd = 0;
  struct sockaddr_in serv_addr;
  int pid;

  int ret, len;
  unsigned char buf[1024];
  const char *pers = "ssl_server";
  unsigned char target_list[1] = { 1 };
  unsigned char supported_list[1] = { 1 };
  unsigned char *cursor;

  // Client connection
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;

  // Proxy connection
  mbedtls_entropy_context entropy_proxy;
  mbedtls_ctr_drbg_context ctr_drbg_proxy;
  mbedtls_ssl_context ssl_proxy;
  mbedtls_ssl_config conf_proxy;
  mbedtls_x509_crt srvcert_proxy;
  mbedtls_pk_context pkey_proxy;

  mbedtls_ssl_init( &ssl );
  mbedtls_ssl_config_init( &conf );
  mbedtls_x509_crt_init( &srvcert );
  mbedtls_pk_init( &pkey );
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_ssl_init( &ssl_proxy );
  mbedtls_ssl_config_init( &conf_proxy );
  mbedtls_x509_crt_init( &srvcert_proxy );
  mbedtls_pk_init( &pkey_proxy );
  mbedtls_entropy_init( &entropy_proxy );
  mbedtls_ctr_drbg_init( &ctr_drbg_proxy );

  /*
   * Load the certificates and private RSA key
   */
  printf( "\n  . Loading the server cert. and key..." );

  /*
   * This demonstration program uses embedded test certificates.
   * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
   * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
   */

  ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                               mbedtls_test_srv_crt_len);

  if (ret != 0) {
    printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
    goto exit;
  }

  ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len);

  if (ret != 0) {
    printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
    goto exit;
  }

  ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                             mbedtls_test_srv_key_len, NULL, 0);

  if( ret != 0 ) {
    printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
    goto exit;
  }

  ret = mbedtls_x509_crt_parse(&srvcert_proxy, (const unsigned char *) mbedtls_test_srv_crt,
                               mbedtls_test_srv_crt_len);

  if (ret != 0) {
    printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
    goto exit;
  }

  ret = mbedtls_x509_crt_parse(&srvcert_proxy, (const unsigned char *) mbedtls_test_cas_pem,
                               mbedtls_test_cas_pem_len);

  if (ret != 0) {
    printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
    goto exit;
  }

  ret = mbedtls_pk_parse_key(&pkey_proxy, (const unsigned char *) mbedtls_test_srv_key,
                             mbedtls_test_srv_key_len, NULL, 0);

  if( ret != 0 ) {
    printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
    goto exit;
  }
  printf( " ok\n" );

  /*
   * Seed the RNG
   */
  printf( "  . Seeding the random number generator..." );

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *) pers,
                                   strlen(pers))) != 0) {
    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    goto exit;
  }

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg_proxy, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *) pers,
                                   strlen(pers))) != 0) {
    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    goto exit;
  }
  printf( " ok\n" );

  /*
   * Setup stuff
   */
  printf( "  . Setting up the SSL data...." );

  if ((ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
    printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);

  if ((ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0) {
    printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_remote_attestation_list(&conf, target_list, 1, supported_list, 1);

  if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
    goto exit;
  }

  if ((ret = mbedtls_ssl_config_defaults( &conf_proxy,
                      MBEDTLS_SSL_IS_SERVER,
                      MBEDTLS_SSL_TRANSPORT_STREAM,
                      MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
    printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_rng(&conf_proxy, mbedtls_ctr_drbg_random, &ctr_drbg_proxy);
  mbedtls_ssl_conf_ca_chain(&conf_proxy, srvcert_proxy.next, NULL);

  if ((ret = mbedtls_ssl_conf_own_cert( &conf_proxy, &srvcert_proxy, &pkey_proxy)) != 0) {
    printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
    goto exit;
  }

  /*if ((ret = mbedtls_ssl_setup(&ssl_proxy, &conf_proxy)) != 0) {
      printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
      goto exit;
  }*/
  printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C

  if( ret != 0 ) {
    printf("Last error was: %d\n\n", ret);
  }

#endif

  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(5566);

  bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

  listen(listenfd, 10);

  while (1) {
    printf("listen on fd: %d...\n", listenfd);
    connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

    printf("accept on fd: %d\n", connfd);
    pid = fork();

    if (pid < 0) {
        printf("Fork failed\n");
        goto exit;
    }

    if (pid != 0) {
        if( ( ret = mbedtls_ctr_drbg_reseed( &ctr_drbg_proxy,
                                     (const unsigned char *) "parent",
                                     6 ) ) != 0 )
        {
            printf( " failed\n  ! mbedtls_ctr_drbg_reseed returned %d\n", ret );
            goto exit;
        }

        close(connfd);
        continue;
    }

    printf("child process...%d\n", connfd);
    close(listenfd);
    if( ( ret = mbedtls_ctr_drbg_reseed( &ctr_drbg_proxy,
                                 (const unsigned char *) "child",
                                 5 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_reseed returned %d\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_setup( &ssl_proxy, &conf_proxy ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    //mbedtls_ssl_session_reset( &ssl_proxy );
    mbedtls_ssl_set_bio(&ssl_proxy, &connfd, customized_net_send, customized_net_recv, NULL);

    //mbedtls_ssl_session_reset(&ssl);
    //mbedtls_ssl_set_bio(&ssl, &ssl_proxy, sgx_ssl_send, sgx_ssl_recv, NULL);
    printf( " ok\n" );

    /*
     * 5. Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    ret = mbedtls_ssl_handshake(&ssl_proxy);
    if (ret != 0) {
      printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
      goto exit;
    }

    printf( " ok\n" );
#if 1
    len = 0;
    memset(buf, 0, sizeof(buf));
    cursor = buf;

    printf("Session information:\n");
    int x;
    mbedtls_cipher_info_t *cipher_info;
    mbedtls_ssl_ciphersuite_t *ciphersuite;
    mbedtls_md_info_t *md_info;
    ciphersuite = mbedtls_ssl_ciphersuite_from_id(ssl_proxy.session->ciphersuite);
    cursor[0] = ssl_proxy.session->ciphersuite;
    cursor++;
    len++;
    cursor[0] = ssl_proxy.session->ciphersuite >> 8;
    cursor++;
    len++;
    printf("ciphersuite id: %d\n", ssl_proxy.session->ciphersuite);
    cipher_info = mbedtls_cipher_info_from_type(ciphersuite->cipher);
    printf("cipher info:\n \
            cipher_type: %d\n \
            cipher_mode: %d\n \
        key_bitlen: %d\n \
        name: %s\n \
        iv_size: %d\n \
        flags: %d\n \
        block_size: %d\n \
        ", cipher_info->type,
           cipher_info->mode,
           cipher_info->key_bitlen,
           cipher_info->name,
           cipher_info->iv_size,
           cipher_info->flags,
           cipher_info->block_size);

    md_info = mbedtls_md_info_from_type(ciphersuite->mac);
    printf("md info:\n \
            mac_type: %d\n \
        name: %s\n \
        size: %d\n \
        block_size: %d\n \
        ", md_info->type,
           md_info->name,
           md_info->size,
           md_info->block_size);

    printf("key 1: ");
    for (x = 0; x < ssl_proxy.key1_len; x++) {
      printf("%X", ssl_proxy.key1[x]);
    }
    printf("\n");
    cursor[0] = ssl_proxy.key1_len;
    cursor++;
    memcpy(cursor, ssl_proxy.key1, ssl.key1_len);
    cursor += ssl_proxy.key1_len;
    len += ssl_proxy.key1_len + 1;

    printf("key 2: ");
    for (x = 0; x < ssl_proxy.key2_len; x++) {
      printf("%X", ssl_proxy.key2[x]);
    }
    printf("\n");
    cursor[0] = ssl_proxy.key2_len;
    cursor++;
    memcpy(cursor, ssl_proxy.key2, ssl_proxy.key2_len);
    cursor += ssl_proxy.key2_len;
    len += ssl_proxy.key2_len + 1;

    mbedtls_ssl_transform *transform;
    transform = ssl_proxy.transform_out;
    printf("transform:\n \
            minlen: %d\n \
            ivlen: %d\n \
            fixed_ivlen: %d\n \
            maclen: %d\n \
            ", transform->minlen,
               transform->ivlen,
               transform->fixed_ivlen,
               transform->maclen);

    cursor[0] = transform->minlen;
    cursor[1] = transform->ivlen;
    cursor[2] = transform->fixed_ivlen;
    cursor[3] = transform->maclen;
    cursor += 4;
    len += 4;
    memcpy(cursor, transform->iv_enc, 16);
    cursor += 16;
    len += 16;
    memcpy(cursor, transform->iv_dec, 16);
    cursor += 16;
    len += 16;
    memcpy(cursor, transform->mac_enc, 20);
    cursor += 20;
    len += 20;
    memcpy(cursor, transform->mac_dec, 20);
    cursor += 20;
    len += 20;
    printf("iv_enc: ");
    for (x = 0; x < 16; x++) {
      printf("%X", transform->iv_enc[x]);
    }
    printf("\n");
    printf("iv_dec: ");
    for (x = 0; x < 16; x++) {
      printf("%X", transform->iv_dec[x]);
    }
    printf("\n");
    printf("mac_enc: ");
    for (x = 0; x < 20; x++) {
      printf("%X", transform->mac_enc[x]);
    }
    printf("\n");
    printf("mac_dec: ");
    for (x = 0; x < 20; x++) {
      printf("%X", transform->mac_dec[x]);
    }
    printf("\n");

    cursor[0] = ssl_proxy.major_ver;
    cursor[1] = ssl_proxy.minor_ver;
    cursor += 2;
    len += 2;
    printf("ssl:\n \
            major_ver: %d\n \
            miner_ver: %d\n \
            ", ssl_proxy.major_ver,
               ssl_proxy.minor_ver);

    mbedtls_ssl_write(&ssl_proxy, buf, len);
#endif

    /*
     * 6. Read the HTTP Request
     */
    printf( "  < Read from client:" );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl_proxy, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf( " connection was closed gracefully\n" );
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    printf( " connection was reset by peer\n" );
                    break;

                default:
                    printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        printf( " %d bytes read\n\n%s", len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */

    printf( "  > Write to client:" );

    len = snprintf( (char *) buf, 1024, HTTP_RESPONSE,
                   mbedtls_ssl_get_ciphersuite( &ssl_proxy ) );

    while( ( ret = mbedtls_ssl_write( &ssl_proxy, buf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            printf( " failed\n  ! peer closed the connection\n\n" );
            goto reset;
        }

        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    printf( " %d bytes written\n\n%s\n", len, (char *) buf );
    printf( "  . Closing the connection..." );

    while( ( ret = mbedtls_ssl_close_notify( &ssl_proxy ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
            goto reset;
        }
    }
    printf( " ok\n" );
    ret = 0;
    goto exit;
  }

exit:

  printf("Forked exit!\n");
  close(connfd);

//  close(listenfd);

  mbedtls_x509_crt_free( &srvcert );
  mbedtls_pk_free( &pkey );
  mbedtls_ssl_free( &ssl );
  mbedtls_ssl_config_free( &conf );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );

  mbedtls_x509_crt_free( &srvcert_proxy );
  mbedtls_pk_free( &pkey_proxy );
  mbedtls_ssl_free( &ssl_proxy );
  mbedtls_ssl_config_free( &conf_proxy );
  mbedtls_ctr_drbg_free( &ctr_drbg_proxy );
  mbedtls_entropy_free( &entropy_proxy );
}
