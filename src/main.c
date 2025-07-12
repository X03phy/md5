#include "md5.h"
#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>

int main( int argc, char **argv )
{
	if ( argc != 2 )
	{
		printf( "Please, enter only 1 argument\n" );
		return ( 1 );
	}

	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char my_hash[SHA256_DIGEST_LENGTH];

	SHA256( ( const unsigned char * ) argv[1], strlen( argv[1] ), hash );
	printf( "openssl SHA256: " );
	for ( uint8_t i = 0; i < SHA256_DIGEST_LENGTH; ++i )
		printf( "%02x", hash[i] );
	printf( "\n" );

	sha256( ( const unsigned char * ) argv[1], strlen(argv[1]), my_hash );
	printf( "my SHA256:      " );
	for ( uint8_t i = 0; i < SHA256_DIGEST_LENGTH; ++i )
		printf( "%02x", my_hash[i] );
	printf("\n");

	if ( !memcmp( ( const char * ) hash, ( const char * ) my_hash, SHA256_DIGEST_LENGTH ) )
		printf( "OK\n" );
	else
		printf( "KO\n" );

	return ( 0 );
}
