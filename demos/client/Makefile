all := client

client: client.c ../3rdparty/mbedtls-2.2.1/library/libmbedtls.a
	gcc $< -I../3rdparty/mbedtls-2.2.1/include -L../3rdparty/mbedtls-2.2.1/library -lmbedtls -lmbedx509 -lmbedcrypto -o $@

clean:
	rm client

.PHONY: all clean
