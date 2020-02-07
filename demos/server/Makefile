all := server-fork

#server: server.c mbedtls-2.2.1/library/libmbedtls.a
#	gcc $< -Imbedtls-2.2.1/include -Lmbedtls-2.2.1/library -lmbedtls -lmbedx509 -lmbedcrypto -o $@

server-fork: server-fork.c ../3rdparty/mbedtls-2.2.1/library/libmbedtls.a
	gcc $< -I../3rdparty/mbedtls-2.2.1/include -L../3rdparty/mbedtls-2.2.1/library -lmbedtls -lmbedx509 -lmbedcrypto -o $@

clean:
	rm -f server-fork

.PHONY: all clean
