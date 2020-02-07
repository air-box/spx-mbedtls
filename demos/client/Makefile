all := client

client: client.c mbedtls-2.2.1/library/libmbedtls.a
	gcc $< -Imbedtls-2.2.1/include -Lmbedtls-2.2.1/library -lmbedtls -lmbedx509 -lmbedcrypto -o $@

clean:
	rm client

.PHONY: all clean
