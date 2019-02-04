/***********************************************************************

   File          : cse543-proto.c

   Description   : This is the network interfaces for the network protocol connection.

   Last Modified : 2018
   By            : Trent Jaeger

***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"
#include "cse543-proto.h"
#include "cse543-ssl.h"


/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Get message encrypted (by encrypt) and put ciphertext 
                   and metadata for decryption into buffer
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - place to put ciphertext and metadata for 
                   decryption on other end
                : len - length of the buffer after message is set 
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

/*** YOUR CODE ***/
int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
    /* Buffer for the ciphertext and the metadata (already alocated)*/
    //buffer = (unsigned char *) malloc( plaintext_len + TAGSIZE + 16=iv_len);

    /* Buffer for the tag */
    unsigned char *tag = NULL;
	tag = (unsigned char *)malloc( TAGSIZE );
    if(tag == NULL){
        printf("Malloc failed tag encrypt_message.\n");
        return -1;
    }
    
    /* A 128 bit = 16 bytes IV (Initialization Vector) TODO*/
    unsigned char *iv = NULL;
    iv = (unsigned char *)malloc(16);
    int exitCode = generate_pseudorandom_bytes(iv, 16);
    if (exitCode == -1){
        printf("generate_pseudorandom_bytes failed encrypt_message.\n");
        return -1;
    }

    /* perform encrypt */
    *len = encrypt( plaintext, plaintext_len, (unsigned char *)NULL, 0, key, iv, buffer, tag);
    if(*len == -1){
        printf("Function encrypt failed encrypt_message.\n");
        return -1;
    }

    /* Add the metadata to the buffer*/
    memcpy(buffer + *len, iv, 16);
    memcpy(buffer + *len + 16, tag, TAGSIZE);

    /* Change the len size to include the metadata*/
    *len += 16 + TAGSIZE;

    /* Free the tag & iv */
    free(tag);
    free(iv);
    
    return 0;
}



/**********************************************************************

    Function    : decrypt_message
    Description : Recover plaintext from ciphertext (by decrypt)
                   using metadata from buffer
    Inputs      : buffer - ciphertext and metadata - in format set by
                   encrypt_message
                : len - length of buffer containing ciphertext and metadata
                : key - symmetric key
                : plaintext - place to put decrypted message
                : plaintext_len - size of decrypted message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

/*** YOUR CODE ***/ 
int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
    /* Buffer for the tag */
    unsigned char *tag = NULL;
	tag = (unsigned char *)malloc( TAGSIZE );
    if(tag == NULL){
        printf("Malloc failed tag decrypt_message.\n");
        return -1;
    }
    /* A 128 bit = 16 bytes IV (Initialization Vector)*/
    unsigned char *iv = NULL;
	iv = (unsigned char *)malloc( 16 );
    if(iv == NULL){
        printf("Malloc failed iv decrypt_message.\n");
        return -1;
    }
    
    /* A buffer for the cipher text */
    unsigned char *ciphertext = NULL;
	ciphertext = (unsigned char *)malloc(len - 16 - TAGSIZE);
    if(ciphertext == NULL){
        printf("Malloc failed ciphertext decrypt_message.\n");
        return -1;
    }
    
    /* A buffer for the plain text (already alocated)*/
	//plaintext = (unsigned char *)malloc(len - 16=iv_len - TAGSIZE);
    
    /* Take the metadata & data from the buffer*/
    memcpy(tag, buffer + len - TAGSIZE, TAGSIZE);
    memcpy(iv, buffer + len - 16 - TAGSIZE, 16);
    memcpy(ciphertext, buffer, len - 16 - TAGSIZE);
    
    /* perform decrypt */
	*plaintext_len = decrypt( ciphertext, len - 16 - TAGSIZE, (unsigned char *) NULL, 0, tag, key, iv, plaintext );
    if (*plaintext_len == -1){
        printf("Function decrypt failed decrypt_message.\n");
        return -1;
    }

    /* Free the tag, ciphertext and IV*/
    free(tag);
    free(iv);
    free(ciphertext);
    
    return 0;
}


/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */
	fptr = fopen( PUBKEY_FILE, "w+" );

	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data.\n");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Client: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign_RSA(*pubkey, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudorandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

/*** YOUR CODE ***/
int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{
    /*
    RAND_bytes() puts num cryptographically strong pseudo-random bytes into buf.
    RAND_priv_bytes() has the same semantics as RAND_bytes(). It is intended to be used for generating values that should remain private.
    https://www.openssl.org/docs/manmaster/man3/RAND_bytes.html
    
    int RAND_bytes(unsigned char *buf, int num);
    RAND_bytes() return 1 on success, -1 if not supported by the current RAND method, or 0 on other failure.
    */
    int returnCode = 0;
    returnCode = RAND_bytes(buffer, (int) size);
    if (returnCode == 1){
        return 0;
    }
    else{
        printf("RAND_bytes failed in generate_pseudorandom_bytes.\n");
        return -1;
    }
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using OpenSSL public key (call rsa_encrypt)
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted key and 
                     and metadata for decrypting in unseal
    Outputs     : len if successful, -1 if failure

***********************************************************************/

/*** YOUR CODE ***/
int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	unsigned char *ek = NULL;
	unsigned int ekl; 
	unsigned char *iv = NULL;
	unsigned int ivl;
	unsigned char *ciphertext = NULL;
    unsigned int cipherlen = 0;
    
	cipherlen = rsa_encrypt( key, keylen, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );
    if(cipherlen == -1){
        printf("rsa_encrypt failed in seal_symmetric_key.\n");
        return -1;
    }

    /* Buffer for the ciphertext and the metadata (already alocated)*/
    //buffer = (unsigned char *) malloc(cipherlen + ekl + ivl + 2*sizeof(unsigned int)=ekl+ivl in the buffer);

    /* Add the metadata to the buffer*/
    memcpy(buffer, ciphertext, cipherlen); //1 - ciphertext
    memcpy(buffer + cipherlen, ek, ekl); //2 - ek
    memcpy(buffer + cipherlen + ekl, iv, ivl); //3 - iv
    memcpy(buffer + cipherlen + ekl + ivl, &ekl, sizeof(unsigned int)); //4 - ekl
    memcpy(buffer + cipherlen + ekl + ivl + sizeof(unsigned int), &ivl, sizeof(unsigned int)); //5 - ivl
    return cipherlen + ekl + ivl + 2*sizeof(unsigned int);
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Decrypt symmetric key using OpenSSL private key (call rsa_decrypt)
    Inputs      : buffer - buffer containing the encrypted key and 
                     and metadata for decrypting in format determined
                     in seal_symmetric_key
                  len - length of buffer
                  privkey - private key 
                  key - symmetric key (plaintext from rsa_decrypt)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

/*** YOUR CODE ***/
int unseal_symmetric_key( char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
    unsigned int keylen = 0;

    /* A 128 bit = 16 bytes IV (Initialization Vector)*/
    unsigned char *iv = NULL;
    unsigned int ivl = 0;
    
    /* Buffer for the ek */
    unsigned char *ek = NULL;
    unsigned int ekl = 0;
    
    /* A buffer for the cipher text */
    unsigned char *ciphertext;
    
    /* Take the metadata & data from the buffer*/
    memcpy(&ivl, buffer + len - sizeof(unsigned int), sizeof(unsigned int));//5 - ivl
    memcpy(&ekl, buffer + len - 2*sizeof(unsigned int), sizeof(unsigned int));//4 - ekl

    //IV
    iv = (unsigned char *)malloc( ivl );
    if(iv == NULL){
        printf("Malloc failed iv unseal_symmetric_key.\n");
        return -1;
    }
    memcpy(iv, buffer + len - 2*sizeof(unsigned int) - ivl, ivl);//3 - iv
    
    //EK
    ek = (unsigned char *)malloc( ekl );
    if(ek == NULL){
        printf("Malloc failed ek unseal_symmetric_key.\n");
        return -1;
    }
    memcpy(ek, buffer + len - 2*sizeof(unsigned int) - ivl - ekl, ekl); //2 - ek
    
    //Ciphertext    
    unsigned int cipherlen = len - ekl - ivl - 2*sizeof(unsigned int);
    ciphertext = (unsigned char *)malloc(cipherlen);
    if(ciphertext == NULL){
        printf("Malloc failed ciphertext unseal_symmetric_key.\n");
        return -1;
    }
    memcpy(ciphertext, buffer, cipherlen);
    
    /* perform decrypt */
	keylen = rsa_decrypt( ciphertext, cipherlen, ek, ekl, iv, ivl, key, privkey );
	if (keylen == -1){
        printf("Function rsa_decrypt failed unseal_symmetric_key.\n");
        return -1;
    }

	/* Free the tag, ciphertext and IV*/
    free(ek);
    free(iv);
    free(ciphertext);
    
    return 0;
}


/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of your authentication protocol
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

/*** YOUR CODE ***/
int client_authenticate( int sock, unsigned char **session_key )
{
    RAND_poll();//Initialize the random number generator
    int byte_read = 0;
    
    /* Message 1 - Open the connection with the server*/
    char* block1 = NULL;
    ProtoMessageHdr hdr1;
    hdr1.msgtype = CLIENT_INIT_EXCHANGE;
    hdr1.length = 0;
    if(send_message(sock, &hdr1, block1) == -1){
        printf("client_authenticate send_message CLIENT_INIT_EXCHANGE error.\n");
        return -1;
    }
    
    /*Message 2 - Wait to receive the RSA pub key of the server*/
    ProtoMessageHdr hdr2;
    char bloc2[MAX_BLOCK_SIZE]; // will contain the rsapublic key non-extracted
    bzero(bloc2, MAX_BLOCK_SIZE); //clear 
    if (wait_message( sock, &hdr2, bloc2, SERVER_INIT_RESPONSE ) == -1){
        printf("client_authenticate  wait_message SERVER_INIT_RESPONSE error.\n");
        return -1;
    }

    byte_read += hdr2.length;
    EVP_PKEY* pubkey = NULL;
    if(extract_public_key(bloc2, (unsigned int) MAX_BLOCK_SIZE, &pubkey) == -1){
        printf("client_authenticate failed to extract_public_key.\n");
        return -1;
    }

    printf("MESSAGE 2 RECEIVED.\n");

    /* Message 3 - Reply with the session key encrypted with the RSA server pub*/
    //-- generate the session key
    int session_key_length = 256;
    *session_key = (unsigned char *) malloc(session_key_length);
    if (session_key == NULL){
        printf("Couldn't allocate session_key, Message 3, client_authenticate.\n");
        return -1;
    }
    if(generate_pseudorandom_bytes(*session_key, session_key_length) == -1){
        printf("Failed to generate session key in client_authenticate.\n");
    }
    //-- encrypt the session key
    char *E_session_key; // the encrypted session key buffer
    int len_E_session_key = 0;
    
    E_session_key = (unsigned char *) malloc((session_key_length + EVP_MAX_IV_LENGTH) + EVP_PKEY_size(pubkey) + EVP_MAX_IV_LENGTH + 2*sizeof(unsigned int));
    if (E_session_key == NULL){
        printf("Couldn't allocate E_session_key, Message 3, client_authenticate.\n");
        return -1;
    }
    
    len_E_session_key = seal_symmetric_key(*session_key, session_key_length, pubkey, E_session_key);
    if(len_E_session_key == -1){
        printf("seal_symmetric_key failed in client_authenticate.\n");
        return -1;
    }
    
    //-- send the Encrypted session key: E_session_key
    ProtoMessageHdr hdr3;
    hdr3.msgtype = CLIENT_INIT_ACK;
    hdr3.length = len_E_session_key;
    if(send_message(sock, &hdr3, E_session_key) == -1){
        printf("client_authenticate send_message CLIENT_INIT_ACK error.\n");
        return -1;
    } 
    //-- free the malloc(s)...
    free(E_session_key);

    
    /*Message 4 - Wait to receive the RSA pub key of the server*/
    /* If the confirmation from the server takes more than 10s 
    we return -1 because of a timeout (avoid replay attacks). */
    ProtoMessageHdr hdr4;
    unsigned char E_epoch[MAX_BLOCK_SIZE]; // will contain the confirmation (encrypted epoch) if the protocol went well
    bzero(E_epoch, MAX_BLOCK_SIZE); //clear 
    if (wait_message( sock, &hdr4, E_epoch, SERVER_INIT_ACK ) == -1){
        printf("client_authenticate  wait_message SERVER_INIT_ACK error.\n");
        return -1;
    }
    byte_read += hdr4.length;
    
    //-- decrypt the E_epoch with the session key -> epoch_buffer -> epoch
    int len_epoch_buffer = 0;
    unsigned char *epoch_buffer = (unsigned char *)malloc(hdr4.length - 16 - TAGSIZE);
    bzero(epoch_buffer, hdr4.length - 16 - TAGSIZE);
    if (epoch_buffer == NULL){
        printf("Couldn't allocate epoch_buffer, Message 4, client_authenticate,\n");
        return -1;
    }
    
    int rc = decrypt_message(E_epoch, hdr4.length, (const char *) *session_key, epoch_buffer, &len_epoch_buffer);
    if(rc == -1){
        printf('decrypt_message failed in client_authenticate.\n');
        return -1;
    }
    
    unsigned long epoch = 0;
    memcpy((char*)&epoch, epoch_buffer, sizeof(unsigned long));
    
    //--compare the value received and the value on the client, the time need to be 10s close
    unsigned long real_epoch = (unsigned long)time(NULL);
    if (!(real_epoch - 10 <= epoch <= real_epoch)){
        printf("Confirmation timeout >= 10sec, client_authenticate. Synchronize time on the server and the client.\n");
        return -1;
    }
    free(epoch_buffer);

    printf("MESSAGE 4 RECEIVED.\n");
    
    return byte_read;
}

/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

/*** YOUR CODE ***/ 
int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
	/* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];

	/* Read the next block */
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt and send */
			/*** YOUR CODE - here ***/
            //-- Encryption
            unsigned char *E_block = (unsigned char *) malloc( readBytes + TAGSIZE + 16);
            if(E_block == NULL){
                printf("Counldn't assign E_block, transfer_file.\n");
                return -1;
            }
            unsigned int len_E_block;
            
            int rc = encrypt_message( block, readBytes, key, E_block, &len_E_block);
            if(rc == -1){
                printf("encrypt_message failed in transfer_file.\n");
                return -1;
            }

            
            //-- Sending...
            ProtoMessageHdr hdr;
            hdr.msgtype = FILE_XFER_BLOCK;
            hdr.length = len_E_block;
            if(send_message(sock, &hdr, E_block) == -1){
                printf("transfer_file send_message FILE_XFER_BLOCK error.\n");
                return -1;
            } 
            
            //-- free the malloc(s)...
            free(E_block);
        }
            
	}

    /* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/* Local variables */
	unsigned char *key;
	int sock;

	sock = connect_client( address );
	// crypto setup, authentication
	client_authenticate( sock, &key );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );
	/* Return successfully */
	return( 0 );
}

/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_rsa
    Description : test the rsa encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_rsa( EVP_PKEY *privkey, EVP_PKEY *pubkey )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Test RSA encrypt and decrypt. ***\n");

	len = rsa_encrypt( (unsigned char *)"help me, mr. wizard!", 20, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);
#endif

	len = rsa_decrypt( ciphertext, len, ek, ekl, iv, ivl, &plaintext, privkey );

	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	unsigned char msg[] = "Help me, Mr. Wizard!";
	unsigned int len = strlen(msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	/* demonstrate with fixed key - don't do this in real systems */
	memcpy( key, "ABCDEFGH_IJKLMNOabcdefgh_ijklmno", KEYSIZE );  
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( msg, len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= len ));

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if 0
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : server_protocol
    Description : server side of crypto protocol
    Inputs      : sock - server socket
                  pubfile - public key file name
                  privkey - private key value
                  enckey - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

/*** YOUR_CODE ***/
int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
    RAND_poll();//Initialize the random number generator
    int byte_read = 0;
    
    /* Message 1 - Wait patiently for the client to contact us*/
    ProtoMessageHdr hdr1;
    char block1[MAX_BLOCK_SIZE];
    bzero(block1, MAX_BLOCK_SIZE); //clear 
    if (wait_message( sock, &hdr1, block1, CLIENT_INIT_EXCHANGE ) == -1){
        printf("server_protocol wait_message CLIENT_INIT_EXCHANGE error.\n");
        return -1;
    }
    byte_read += hdr1.length;

    printf("MESSAGE 1 RECEIVED.\n");
    
    /* Message 2 - Send the RSA public key to the client*/
    //-- read public key file and extract the pubkey
    FILE *file = NULL;
    char *block2 = NULL;
    int num_bytes = 0;
    file = fopen(pubfile, "r");
    if(file == NULL){
        return -1;
    }
    
    fseek(file, 0L, SEEK_END);
    num_bytes = ftell(file) < MAX_BLOCK_SIZE ? ftell(file) : MAX_BLOCK_SIZE;
    fseek(file, 0L, SEEK_SET);
    block2 = (char*)malloc(num_bytes);
    bzero(block2, num_bytes);
    if(block2 == NULL){
        printf("Couldn't assign block2, Message 2, server_protocol.\n");
        return -1;
    }
    fread(block2, sizeof(char), num_bytes, file);//copy in block2 (num_bytes*sizeof(char))
    fclose(file);
    
    // send the block2 containing the content of the public key file
    ProtoMessageHdr hdr2;
    hdr2.msgtype = SERVER_INIT_RESPONSE;
    hdr2.length = num_bytes;
    if(send_message(sock, &hdr2, block2) == -1){
        printf("server_protocol send_message SERVER_INIT_RESPONSE error.\n");
        return -1;
    }
    free(block2);

    /* Message 3 - Wait for the client to send the encrypted session key */
    //-- wait for the message
    ProtoMessageHdr hdr3;
    char block3[MAX_BLOCK_SIZE];
    bzero(block3, MAX_BLOCK_SIZE); //clear 
    if (wait_message( sock, &hdr3, block3, CLIENT_INIT_ACK ) == -1){
        printf("server_protocol wait_message CLIENT_INIT_ACK error.\n");
        return -1;
    }
    byte_read += hdr3.length;
    
    //decrypt the session key
    int rc = unseal_symmetric_key(block3, hdr3.length, privkey, enckey);
    if(rc == -1){
        printf("unseal_symmetric_key failed in server_protocol.\n");
        return -1;
    }
    
    printf("MESSAGE 3 RECEIVED.\n");
    
    /* Message 4 - Send confirmation and end of the authentication */
    /*
    The confirmation is a timestamp (epoch). The client will validate it
    if it's been less than 10 seconds since sent.
    */
    ProtoMessageHdr hdr4;
    unsigned long epoch = (unsigned long)time(NULL); //epoch
    unsigned char *epoch_buffer = (unsigned char *) malloc(sizeof(epoch));
    if(epoch_buffer == NULL){
        printf("Couldn't assign epoch_buffer, Message 4, server_protocol.\n");
        return -1;
    }
    memcpy(epoch_buffer, (char *) &epoch, sizeof(epoch)); //copy epoch in the buffer

    int len_E_epoch = 0;
    unsigned char *E_epoch = (unsigned char *) malloc(sizeof(epoch) + TAGSIZE + 16); // the encrypted buffer containing epoch
    if(E_epoch == NULL){
        printf("Couldn't assign E_epoch, Message 4, server_protocol.\n");
        return -1;
    }
    
    rc = encrypt_message( (unsigned char *) epoch_buffer, sizeof(epoch), *enckey, E_epoch, &len_E_epoch); //encrypt epoch and place it in E_epoch
    if(rc == -1){
        printf("encrypt_message failed in server_protocol.\n");
        return -1;
    }
    
    hdr4.msgtype = SERVER_INIT_ACK;
    hdr4.length = len_E_epoch;
    if(send_message(sock, &hdr4, E_epoch) == -1){
        printf("server_protocol send_message SERVER_INIT_RESPONSE error.\n");
        return -1;
    }
    
    free(epoch_buffer);
    free(E_epoch);

    return byte_read;
}

/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the AES session key used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	char *fname = NULL;
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );

	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
		fname = (char *)malloc( size );
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
		if ( (fh=open( fname, O_WRONLY|O_CREAT|O_TRUNC, 0700)) > 0 );
		else assert( 0 );
	}
	else assert( 0 );

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );
				write( fh, plaintext, outbytes );

#if 1 
                printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign_RSA(privkey, rsa_privkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	// Test the RSA encryption and symmetric key encryption
	test_rsa( privkey, pubkey );
	test_aes();
    
	/* Repeat until the socket is closed */
    while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				server_protocol( newsock, pubfile, privkey, &key );
				receive_file( newsock, key );
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}

    /*--------------------TEST FOR AES-----------------------------*/
//    fprintf(stderr, "Encrypt_message.\n");
//    unsigned char *buffer = (unsigned char *) malloc( 20 + TAGSIZE + 16);
//    unsigned int clen;
//    unsigned int plaintext_len;
//
//    /* make key */
//	key= (unsigned char *)malloc( KEYSIZE );
//	/* demonstrate with fixed key - don't do this in real systems */
//	memcpy( key, "ABCDEFGH_IJKLMNOabcdefgh_ijklmno", KEYSIZE );
//    
//    encrypt_message( (unsigned char *)"Help me, Mr. Wizard!", 20, key, buffer, &clen);
//
//    printf("Ciphertext is: \n");
//    BIO_dump_fp (stdout, (const char *) buffer, clen);
//    
//    unsigned char *plaintext = (unsigned char *)malloc(clen - 16 - TAGSIZE);
//    decrypt_message( buffer, clen, key, plaintext, &plaintext_len );
//    printf("Decrypted text is: \n");
//    BIO_dump_fp (stdout, (const char *) plaintext, plaintext_len);

    /*--------------------TEST FOR RSA-----------------------------*/
//    fprintf(stderr, "Encrypt_message.\n");
//    char *buffer;
//    int len = 0;
//    unsigned char *plaintext;
//    
//    buffer = (unsigned char *) malloc((20 + EVP_MAX_IV_LENGTH) + EVP_PKEY_size(pubkey) + EVP_MAX_IV_LENGTH + 2*sizeof(unsigned int));
//    
//    len = seal_symmetric_key( (unsigned char *)"help me, mr. wizard!", 20, pubkey, buffer);
//    
//    printf("Ciphertext is:\n");
//	BIO_dump_fp (stdout, (const char *) buffer, len);    
//    
//    
//    unseal_symmetric_key(buffer, len, privkey, &plaintext);
//    printf("Msg: %s\n", plaintext );
    
    /*--------------------TEST FOR GENERATION-----------------------------*/
//    unsigned int length = 16;
//    unsigned char *buffer = (unsigned char *) malloc(length);
//    int exitCode;
//    exitCode = generate_pseudorandom_bytes(buffer, length);
//    printf("exitCode %d", exitCode);
//    BIO_dump_fp (stdout, (const char *) buffer, length);