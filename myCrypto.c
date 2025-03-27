/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c     SKELETON

Written By: 
     1- Mason Puckett
	 2- Stephen Ender
Submitted on: 
     Insert the date of Submission here
	 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}



//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
    int status;
    unsigned len = 0;
    unsigned encryptedLen = 0;

    // Initialize the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors("encrypt: failed to create CTX");
    
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1)
        handleErrors("encrypt: Failed to EncryptInit_ex");

    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if(status != 1)
        handleErrors("encrypt: Failed to EncryptUpdate");
    encryptedLen += len;
    pCipherText  += len;

    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if(status != 1)
        handleErrors("encrypt: Failed to EncryptFinal_ex");
    encryptedLen += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int status;
    unsigned len = 0;
    unsigned decryptedLen = 0;

    // Initialize Context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        handleErrors("decrypt: Failed to create ctx");
    
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1)
        handleErrors("decrypt: Failed to DecryptInit_ex");

    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status != 1)
        handleErrors("decrypt: Failed to DecryptUpdate");
    decryptedLen += len;
    pDecryptedText += len;

    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if(status != 1)
        handleErrors("decrypt: Failed to DecryptFinal_ex");
    decryptedLen += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return decryptedLen;
}


//-----------------------------------------------------------------------------


static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status;
    unsigned len = 0;
    unsigned encryptedLen = 0;
    ssize_t bytes_read = 0;

    // Initialize context 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        handleErrors("encryptFile: failed to intialize context");
    }

    // Setup encryption operation
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1){
        handleErrors("EncryptFile: failed EVP_EncryptInit_ex");
    }
    
    // Read chunks of plaintext in until there are no more bytes to be read
    while ((bytes_read = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0)
    {
        // Encrypt the chunk of plaintext and send out
        status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, bytes_read);
        if(status != 1)
            handleErrors("encrypt: Failed to EncryptUpdate");
        encryptedLen += len;

        // Send the ciphertext immediately to the file descriptor fd_out 
        status  = write(fd_out, ciphertext, len);
        if (status != len)
            fprintf(stderr, "EncryptFile failed to write ciphertext to pipe");
    }

    // Encrypt the final chunk and send out
    status = EVP_EncryptFinal_ex(ctx, ciphertext, &len);
    if(status != 1){
        handleErrors("failed: encryptFile could not encrypt_final");
    }
    encryptedLen += len;

    // Send the ciphertext immediately to the file descriptor fd_out 
    status = write(fd_out, ciphertext, len);
    if (status != len)
            fprintf(stderr, "EncryptFile failed to write FINAL ciphertext to pipe");

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;
}

//-----------------------------------------------------------------------------


int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status;
    unsigned len = 0;
    unsigned decryptedLen = 0;
    ssize_t bytes_read = 0;

    // Initialize Context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(! ctx){
        handleErrors("decryptFile failed to initialize ctx");
    }

    // Setup decryption operation
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if(status != 1){
        handleErrors("failed: decryptFile could not EVP_DecryptInit_ex");
    }

    // Read chunks of ciphertext in until there are no more bytes to be read
    while ((bytes_read = read(fd_in, ciphertext, CIPHER_LEN_MAX)) > 0)
    {
        // Decrypt the chunk of ciphertext and send out
        status = EVP_DecryptUpdate(ctx, decryptext, &len, ciphertext, bytes_read);
        if(status != 1)
            handleErrors("failed to decryptUpdate");
        decryptedLen += len;

        // Send the ciphertext immediately to the file descriptor fd_out 
        status = write(fd_out, decryptext, len);
        if (status != len)
            fprintf(stderr, "DecryptFile failed to write decryptext to file");
    }

    // Decrypt the final chunk and send out
    status = EVP_DecryptFinal_ex(ctx, decryptext, &len);
    if(status != 1){
        handleErrors("failed to decryptFinal");
    }
    decryptedLen += len;

    // Send the ciphertext immediately to the file descriptor fd_out 
    status = write(fd_out, decryptext, len);
    if (status != len)
            fprintf(stderr, "DecryptFile failed to write FINAL decryptext to file");

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return decryptedLen;

}

//***********************************************************************
// pLAB-02
//***********************************************************************

EVP_PKEY *getRSAfromFile(char * filename, int public){
    FILE *fp = fopen(filename, "rb");
    if(fp == NULL){
        fprintf(stderr, "getRSAfromFile: Unable to open RSA key file %s \n", filename);
        return NULL;
    }

    EVP_PKEY *key = EVP_PKEY_new();
    if(public){
        key = PEM_read_PUBKEY(fp, &key, NULL, NULL);
    }else{
        key = PEM_read_PrivateKey(fp, &key, NULL, NULL);
    }
    fclose(fp);

    return key;
}

//***********************************************************************
// PA-02
//***********************************************************************
// Sign the 'inData' array into the 'sig' array using the private 'privKey'
// 'inLen' is the size of the input array in bytes.
// the '*sig' pointer will be allocated memory large enough to store the signature
// report the actual length in bytes of the result in 'sigLen' 
//
// Returns: 
//    1 on success, or 0 on ANY REASON OF FAILURE

int privKeySign( uint8_t **sig , size_t *sigLen , EVP_PKEY  *privKey , 
                 uint8_t *inData , size_t inLen ) 
{
    // Guard against incoming NULL pointers
    if (sig == NULL || sigLen == NULL || privKey == NULL || inData == NULL) {
        handleErrors("privKeySign: NULL pointer passed to function.");
        return 0;
    }
    // Create and Initialize a context for RSA private-key signing
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new(privKey, NULL);
    if (!ctx) {
        handleErrors("privKeySign: Context creation failed.");
        return 0;
    }
    if(EVP_PKEY_sign_init(ctx) <= 0) {
        handleErrors("privKeySign: PKEY sign init failed.");
        EVP_PKEY_CTX_free( ctx );
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        handleErrors("privKeySign: Set padding failed.");
        EVP_PKEY_CTX_free( ctx );
        return 0;
    }

    // Determine how big the size of the signature could be
    if (EVP_PKEY_sign(ctx, NULL, sigLen, inData, inLen) <= 0) {
        handleErrors("privKeySign: Failed to determine signature size.");
        EVP_PKEY_CTX_free( ctx );
        return 0;
    }

    // Next allocate memory for the ciphertext
    *sig = calloc(1, *sigLen);

    // Now, actually sign the inData using EVP_PKEY_sign( )
    if (EVP_PKEY_sign(ctx, *sig, sigLen, inData, inLen) <= 0) {
        handleErrors("privKeySign: Failed to sign data.");
        EVP_PKEY_CTX_free( ctx );
        free(sig);
        return 0;
    }

    // All is good
    EVP_PKEY_CTX_free( ctx );     // remember to do this if any failure is encountered above

    return 1;
}

//-----------------------------------------------------------------------------
// Verify that the provided signature in 'sig' when decrypted using 'pubKey' 
// matches the data in 'data'
// Returns 1 if they match, 0 otherwise

int pubKeyVerify( uint8_t *sig , size_t sigLen , EVP_PKEY  *pubKey 
           , uint8_t *data , size_t dataLen ) 
{
    // Guard against incoming NULL pointers
    if ( !sig ||  !pubKey  ||  !data  )
    {
        printf(  "\n******* pkeySign received some NULL pointers\n" ); 
        return 0 ; 
    }

    // Create and Initialize a context for RSA public-key signature verification
    EVP_PKEY_CTX *ctx;

   ctx = EVP_PKEY_CTX_new(pubKey, NULL);
   if (!ctx) {
        handleErrors("pubKeyVerify: Context creation failed.");
        return 0;
   }
   if(EVP_PKEY_verify_init(ctx) <= 0) {
        handleErrors("pubKeyVerify: Pub key verify init. failed.");
        EVP_PKEY_CTX_free( ctx );
        return 0;
   }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        handleErrors("pubKeyVerify: Set padding failed.");
        EVP_PKEY_CTX_free( ctx );
        return 0;
    }

    // Verify the signature vs the incoming data using this context
    int decision = EVP_PKEY_verify(ctx, sig, sigLen, data, dataLen) ;
    if (decision <= -1) {
        handleErrors("pubKeyVerify: Verification failed.");
        EVP_PKEY_CTX_free( ctx );
        return 0;
    }

    //  free any dynamically-allocated objects 
    EVP_PKEY_CTX_free( ctx );
    free(sig);

    return decision ;

}

//-----------------------------------------------------------------------------


size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from the 'fd_in' file descriptor
// Apply the HASH_ALGORITHM() to compute the hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, also write a copy of the incoming data stream file to 'fd_out'
// Returns actual size in bytes of the computed digest
{
    EVP_MD_CTX *mdCtx ;
    size_t nBytes = 0;
    unsigned int  mdLen ;
    int status;

	// Use EVP_MD_CTX_new() to create new hashing context
    mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        handleErrors("fileDigest: Hashing context creation failed.");
    }
    
    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the HASH_ALGORITHM() hashing function 
    if (EVP_DigestInit(mdCtx, HASH_ALGORITHM()) <= 0) {
        handleErrors("fileDigest: Context init. failed.");
        EVP_MD_CTX_destroy(mdCtx);
    }

    // Read a chunk of input from fd_in. Exit the loop when End-of-File is reached
    while ((nBytes = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0)   // Loop until end-of input file
    {
        status = EVP_DigestUpdate(mdCtx, plaintext, nBytes);
        if (status != 1) {
            handleErrors("fileDigest: Context init. failed.");
            EVP_MD_CTX_destroy(mdCtx);
        }
        
        // if ( fd_out > 0 ) send the above chunk of data to fd_out
        status = write(fd_out, plaintext, nBytes);
        if (status != nBytes)
            fprintf(stderr, "fileDigest failed to write digest to fd_out");
    }


    status = EVP_DigestFinal(mdCtx, digest, &mdLen); 
    if(status != 1){
        handleErrors("failed: fileDigest could not EVP_DigestFinal");
    }

    // Send the digest immediately to the file descriptor fd_out 
   /* status = write(fd_out, digest, EVP_MAX_MD_SIZE);
    if (status != EVP_MAX_MD_SIZE){
        fprintf(stderr, "fileDigest failed to write FINAL digest to fd_out");
        EVP_MD_CTX_destroy(mdCtx);
    }*/

    return mdLen ;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are size_t integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

size_t MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check against any NULL pointers in the arguments
        //  Check agains any NULL pointers in the arguments
    if (log == NULL || IDa == NULL || IDb == NULL || msg1 == NULL || Na == NULL) {
        fprintf(log, "There was a NULL value passed in the arguments ... EXITING\n");
        fflush(log);
        fclose(log);
        exitError( "Null value passed in args" );
    }

    size_t  LenA    = strlen(IDa) + 1;
    size_t  LenB    = strlen(IDb) + 1;
    size_t  LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN;
    size_t *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = malloc(LenMsg1);
    if (*msg1 == NULL){
        handleErrors("Failed to malloc space for message");
    }

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;
    
	// use the pointer p to traverse through msg1 and fill the successive parts of the msg 
    memcpy(p, &LenA, LENSIZE);
    p += LENSIZE;
    memcpy(p, IDa, LenA);
    p += LenA;
    memcpy(p, &LenB, LENSIZE);
    p += LENSIZE;
    memcpy(p, IDb, LenB);
    p += LenB;
    memcpy(p, Na, NONCELEN);

    fprintf( log , "The following new MSG1 ( %lu bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    BIO_dump_indent_fp(log, *msg1, LenMsg1, 4);
    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check agains any NULL pointers in the arguments
    if (log == NULL || IDa == NULL || IDb == NULL) {
        fprintf(log, "There was a NULL value passed in the arguments ... EXITING\n");
        fflush(log);
        fclose(log);
        exitError( "Null value passed in args" );
    }

    size_t LenMsg1 = 0;
    size_t LenA;
    size_t lenB;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na
    
    // 1) Read Len(ID_A)  from the pipe ... But on failure to read Len(IDa): 
    size_t length = read(fd, &LenA, LENSIZE);
    if (length < 0) {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }
    LenMsg1 += length;
    
    // 2) Allocate memory for ID_A ... But on failure to allocate memory:
    *IDa = (char*) calloc(1, LenA);

    if (IDa == NULL){
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    length = read(fd, *IDa, LenA);
    if (length < 0) {
        fprintf( log , "Out of Memory allocating %lu bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }
    LenMsg1 += length;

    // 3) Read Len( ID_B )  from the pipe    But on failure to read Len( ID_B ):
    length = read(fd, &lenB, LENSIZE);
    if (length <= 0) {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }
    LenMsg1 += length;

    // 4) Allocate memory for ID_B    But on failure to allocate memory:
    *IDb = (char*) calloc(1, lenB);
    if (IDb == NULL) {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// Now, read IDb ... But on failure to read ID_B from the pipe
    length = read(fd, *IDb, lenB);
    if (length < 0) {
        fprintf( log , "Unable to receive all %lu bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    LenMsg1 += length;
    
    // 5) Read Na   But on failure to read Na from the pipe
    length = read(fd, Na, NONCELEN);
    if (length < 0) {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
    LenMsg1 += length;
 
    fprintf( log , "MSG1 ( %lu bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;
}


//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************
/*  Use these static arrays from PA-01 earlier

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

*/

// Also, use this new one for your convenience
static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are size_t integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

size_t MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{

    size_t LenMsg2  ;

    if (Ka == NULL || Kb == NULL || Ks == NULL || 
            IDa == NULL || IDb == NULL || Na == NULL || log == NULL) {
        
        fprintf(log, "There was a null argument in the paramters ...EXITING\n");
        fflush(log);
        fclose(log);
        exitError( "Null value passed in args" );
    }
    
    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in the global scratch buffer plaintext[]

    size_t LenA = strlen(IDa) + 1;
    size_t LenPT = KEYSIZE + LENSIZE + LenA;
    memcpy(plaintext, Ks, KEYSIZE);
    memcpy(plaintext + KEYSIZE, &LenA, LENSIZE);
    memcpy(plaintext + KEYSIZE + LENSIZE, IDa, LenA);

    fprintf(log, "Plaintext Ticket (%lu Bytes) is\n", LenPT);
    BIO_dump_indent_fp(log, plaintext, LenPT, 4);
    fprintf(log, "\n");

    // Use that global array as a scratch buffer for building the plaintext of the ticket
    // Compute its encrypted version in the global scratch buffer ciphertext[]

    // Now, set TktCipher = encrypt( Kb , plaintext );
    // Store the result in the global scratch buffer ciphertext[]

    size_t LenTC = encrypt(plaintext, LenPT, Kb->key, Kb->iv, ciphertext);

    //---------------------------------------------------------------------------------------
    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || L(Na) || Na || lenTktCipher) || TktCipher
    // Reuse that global array plaintext[] as a scratch buffer for building the plaintext of the MSG2
    size_t LenB = strlen(IDb) + 1;
    LenPT = KEYSIZE + LENSIZE + LenB + NONCELEN + LENSIZE + LenTC;

    uint8_t *p;
    p = plaintext;

    memcpy(p, Ks, KEYSIZE);
    p += KEYSIZE;
    memcpy(p, &LenB, LENSIZE);
    p += LENSIZE;
    memcpy(p, IDb, LenB);
    p += LenB;
    memcpy(p, Na, NONCELEN);
    p += NONCELEN;
    memcpy(p, &LenTC, LENSIZE);
    p += LENSIZE;
    memcpy(p, ciphertext, LenTC);

    // Now, encrypt Message 2 using Ka. 
    // Use the global scratch buffer ciphertext2[] to collect the results
    LenMsg2 = encrypt(plaintext, LenPT, Ka->key, Ka->iv, ciphertext2);

    // allocate memory on behalf of the caller for a copy of MSG2 ciphertext
    *msg2 = malloc(LenMsg2);
    if (*msg2 == NULL){
        handleErrors("Could not malloc space for msg2");
    }
    // Copy the encrypted ciphertext to Caller's msg2 buffer.

    memcpy(*msg2, ciphertext2, LenMsg2);

    fprintf( log , "The following Encrypted MSG2 ( %lu bytes ) has been"
                   " created by MSG2_new():  \n" , LenMsg2) ;
    BIO_dump_indent_fp( log , *msg2, LenMsg2, 4 ) ;    fprintf( log , "\n" ) ;    

    fprintf( log ,"This is the content of MSG2 ( %lu Bytes ) before Encryption:\n" ,  LenPT);  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp(log, Ks, KEYSIZE, 4);
    fprintf(log, "\n");

    fprintf( log ,"    IDb (%lu Bytes) is:\n" , LenB);
    BIO_dump_indent_fp ( log , IDb, LenB, 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log , Na, NONCELEN, 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%lu Bytes) is\n" , LenTC);
    BIO_dump_indent_fp ( log , ciphertext, LenTC, 4 ) ;  fprintf( log , "\n") ; 

    fflush( log ) ;    
    
    return LenMsg2 ;    

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , size_t *lenTktCipher , uint8_t **tktCipher )
{
    // Check for NULL arguments
    if (log == NULL || Ka == NULL || *IDb == NULL || *Na == NULL) {
        fprintf(log, "Null inputs for MSG2_receive()\n");
        fflush(log);
        fclose(log);
        exitError("Something is null in the input to MSG2_receive()");
    }

    // Read in the length of msg2
    size_t lenMsg2;
    size_t length = read(fd, &lenMsg2, LENSIZE);
    if (length < 0) {
        fprintf( log , "Unable to receive all %lu bytes of Len(Msg2) "
                       "in MSG2_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes in MSG2_receive()" );
    }

    // Read in the entire msg2 into the global scratch buffer; decrypt with Ka and store plaintex in scratch buffer
    length = read(fd, ciphertext, lenMsg2);
    if (length < 0) {
        fprintf( log , "Unable to receive all %lu bytes of Msg2 "
                       "in MSG2_receive() ... EXITING\n" , lenMsg2 );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes in MSG2_receive()" );
    }

    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %lu bytes ) Successfully\n" 
                 , lenMsg2 );
    BIO_dump_indent_fp(log, ciphertext, lenMsg2, 4);
    fprintf(log, "\n");

    decrypt(ciphertext, lenMsg2, Ka->key, Ka->iv, plaintext);

    uint8_t *p;
    p = plaintext;

    // Parse Ks
    memcpy(Ks->key, p, SYMMETRIC_KEY_LEN);
    p += SYMMETRIC_KEY_LEN;
    memcpy(Ks->iv, p, INITVECTOR_LEN);
    p += INITVECTOR_LEN;

    fprintf(log, "Amal decrypted message 2 from the KDC into the following:\n");
    fprintf(log, "    Ks { Key , IV } (%lu Bytes ) is:\n", KEYSIZE);
    BIO_dump_indent_fp(log, Ks, KEYSIZE, 4);
    fprintf(log, "\n");

    // Parse length of IDb

    size_t LenB;
    char *copy_IDb, *id_check;
    memcpy(&LenB, p, LENSIZE);
    p += LENSIZE;

    // Parse IDb and store on heap

    copy_IDb = (char *)malloc(LenB);
    if (IDb == NULL) {
        fprintf( log , "Out of Memory allocating %lu bytes for IDB in MSG2_receive() "
                       "... EXITING\n" , LenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG2_receive()" );
    }
    memcpy(copy_IDb, p, LenB);
    p += LenB;

    if (strcmp(*IDb, copy_IDb) == 0) {
        id_check = "MATCH";
    }else {
        id_check = "NO MATCH";
    }

    
    fprintf(log, "    IDb (%lu Bytes):   ..... %s\n", LenB, id_check);
    BIO_dump_indent_fp(log, copy_IDb, LenB, 4);
    fprintf(log, "\n");

    // Parse Na- does this also get passed back via heap?
    Nonce_t copy_Na;
    char *na_check;

    memcpy(&copy_Na, p, NONCELEN);
    p += NONCELEN;

    if(*Na[0] == copy_Na[0]){
        na_check = "VALID";
    } else {
        na_check = "INVALID";
    }

    fprintf(log, "    Received Copy of Na (%lu bytes):    >>>> %s\n", NONCELEN, na_check);
    BIO_dump_indent_fp(log, &copy_Na, NONCELEN, 4);
    fprintf(log, "\n");

    // Parse length of Tkt
    memcpy(lenTktCipher, p, LENSIZE);
    p += LENSIZE;

    // Parse Tkt and store on heap
    *tktCipher = malloc(*lenTktCipher);
    if(tktCipher == NULL) {
        fprintf(log, "Out of memory allocating %lu bytes for tktCipher in MSG2_receive() ...EXITING\n", LenB);
        fflush(log);
        fclose(log);
        exitError("Out of memory allocating tktCipher in MSG2_receive()");
    }

    memcpy(*tktCipher, p, *lenTktCipher);
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

size_t MSG3_new( FILE *log , uint8_t **msg3 , const size_t lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{
    if (tktCipher == NULL || Na2 == NULL) {
        
        fprintf(log, "There was a null argument in the paramters ...EXITING\n");
        fflush(log);
        fclose(log);
        exitError( "Null value passed in args" );
    }

    size_t    LenMsg3 = LENSIZE + lenTktCipher + NONCELEN;
    *msg3 = malloc(LenMsg3);
    if (*msg3 == NULL){
        handleErrors("Failed to malloc space for message");
    }
    uint8_t *p;
    p = *msg3;

    memcpy(p, &lenTktCipher, LENSIZE);
    p += LENSIZE;

    memcpy(p, tktCipher, lenTktCipher);
    p += lenTktCipher;

    memcpy(p, Na2, NONCELEN);

    fprintf( log , "The following MSG3 ( %lu bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return( LenMsg3 ) ;

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{
    size_t lenTktCipher;
    size_t length;

    length = read(fd, &lenTktCipher, LENSIZE);
    if(length < 0){
        fprintf(log, "Failed to read length of message from pipe in msg3_receive\n");
        fprintf(stderr, "Failed to read length of message from pipe in msg3_receive\n");
        exitError("Couldn't read length of MSG3\n");
    }

    memset(ciphertext, 0, CIPHER_LEN_MAX);
    length = read(fd, ciphertext, lenTktCipher);
    if(length < 0){
        fprintf(log, "Failed to read tktcipher in MSG3\n");
        fprintf(stderr, "Failed to read tktCipher in MSG3\n");
        exitError("Failed to read tktCipher in MSG3");
    }

    fprintf( log ,"The following Encrypted TktCipher ( %lu bytes ) was received by MSG3_receive()\n" 
                 , lenTktCipher  );
    BIO_dump_indent_fp( log , ciphertext , lenTktCipher , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;

    memset(plaintext, 0, PLAINTEXT_LEN_MAX);
    size_t lenTktPlain;
    lenTktPlain = decrypt(ciphertext, lenTktCipher, Kb->key, Kb->iv, plaintext);

    fprintf( log ,"Here is the Decrypted Ticket ( %lu bytes ) in MSG3_receive():\n" , lenTktPlain ) ;
    BIO_dump_indent_fp( log , plaintext , lenTktPlain , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;

    uint8_t *p;
    p = plaintext;

    memcpy(Ks, p, KEYSIZE);
    p += KEYSIZE;

    size_t LenA;
    memcpy(&LenA, p, LENSIZE);
    p += LENSIZE;

    *IDa = malloc(LenA);
    if (*IDa == NULL){
        fprintf(log, "Failed to allocate space for IDa in MSG3_receive()\n");
        fprintf(stderr, "Failed to allocate space for IDa in MSG3_receive()\n");
        exitError("Failed to allocate space for IDa in MSG3_receive\n");
    }
    
    memcpy(*IDa, p, LenA);
    p += LenA;

    length = read(fd, Na2, NONCELEN);
    if(length < 0) {
        fprintf(log, "failed to read in na2 in msg3\n");
        fprintf(stderr, "Failed to read in Na2 in MSG3\n");
        exitError("Failed to read in Na2 in MSG3_receive()\n");
    }
}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

size_t  MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{

    size_t LenMsg4 ;

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values
    memset(plaintext, 0, PLAINTEXT_LEN_MAX);

    uint8_t *p;
    p = plaintext;

    fprintf(log, "Basim is sending this f( Na2 ) in MSG4:\n");
    BIO_dump_indent_fp(log, fNa2, NONCELEN, 4);
    fprintf(log, "\n");

    memcpy(p, fNa2, NONCELEN);
    p += NONCELEN;

    fprintf(log, "Basim is sending this nonce Nb in MSG4:\n");
    BIO_dump_indent_fp(log, Nb, NONCELEN, 4);
    fprintf(log, "\n");

    memcpy(p, Nb, NONCELEN);

    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.
    memset(ciphertext, 0, CIPHER_LEN_MAX);

    LenMsg4 = encrypt(plaintext, NONCELEN + NONCELEN, Ks->key, Ks->iv, ciphertext);

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    *msg4 = malloc( LenMsg4 ) ;
    if (msg4 == NULL){
        fprintf(log, "Failed to allocate space for msg4 in msg4_new\n");
        fflush(log);
        exitError("Failed to allcoate space in msg4_new for msg4\n");
    }
    p = *msg4;

    memcpy(p, &LenMsg4, LENSIZE);
    p += LENSIZE;

    memcpy(p, ciphertext, LenMsg4);
    
    fprintf( log , "The following Encrypted MSG4 ( %lu bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMsg4 ) ;
    BIO_dump_indent_fp( log , ciphertext , LenMsg4,  4) ;
    fprintf(log, "\n");

    LenMsg4 += LENSIZE;

    return LenMsg4 ;
    
}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{
    size_t  lenMsg4; 
    size_t length = read(fd, &lenMsg4, LENSIZE);
    if (length < 0) {
        fprintf(log, "Failed to read length of message 4 in receive\n");
        fprintf(stderr, "Failed to read length of message 4 in receive\n");
        exitError("Failed to read length of msg4 in receive\n");
    }

    memset(ciphertext, 0, CIPHER_LEN_MAX);

    length = read(fd, ciphertext, lenMsg4);
        if (length < 0) {
        fprintf(log, "Failed to read message 4 in receive\n");
        fprintf(stderr, "Failed to read message 4 in receive\n");
        exitError("Failed to read msg4 in receive\n");
    }
    fprintf(log, "The following Encrypted MSG4 ( %lu bytes ) was received:\n", lenMsg4);
    BIO_dump_indent_fp(log, ciphertext, lenMsg4, 4);
    fprintf(log, "\n");


    memset(plaintext, 0, PLAINTEXT_LEN_MAX);

    decrypt(ciphertext, lenMsg4, Ks->key, Ks->iv, plaintext);

    uint8_t *p;
    p = plaintext;

    memcpy(rcvd_fNa2, p, NONCELEN);
    p += NONCELEN;

    memcpy(Nb, p, NONCELEN);

}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

size_t  MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    size_t  LenMSG5cipher  ;

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 
    memset(plaintext, 0, PLAINTEXT_LEN_MAX);

    memcpy(plaintext, fNb, NONCELEN);

    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.
    memset(ciphertext, 0, CIPHER_LEN_MAX);
    LenMSG5cipher = encrypt(plaintext, NONCELEN, Ks->key, Ks->iv, ciphertext);

    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    *msg5 = malloc( LenMSG5cipher ) ;
    if(*msg5 == NULL){
        fprintf(log, "Failed to allocate space for msg5 new");
        fprintf(stderr, "Failed to allocate space for msg5 new");
        exitError("Failed to allocate space for msg5 new");
    }
    uint8_t *p;
    p = *msg5;

    memcpy(p, ciphertext, LenMSG5cipher);

    fprintf( log , "The following Encrypted MSG5 ( %lu bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return LenMSG5cipher ;

}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    size_t    LenMSG5cipher ;
    
    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.
    memset(ciphertext, 0, CIPHER_LEN_MAX);

    size_t length = read(fd, &LenMSG5cipher, LENSIZE);
    if (length < 0) {
        fprintf(log, "Failed to read len of msg5");
        fprintf(stderr, "Failed to read len of msg5");
        exitError("Failed to read len of message 5");
    }

    length = read(fd, ciphertext, LenMSG5cipher);
    if (length < 0) {
        fprintf(log, "Failed to read msg5");
        fprintf(stderr, "Failed to read msg5");
        exitError("Failed to read message 5");
    }

    fprintf( log ,"The following Encrypted MSG5 ( %lu bytes ) has been received:\n" , LenMSG5cipher );
    BIO_dump_indent_fp(log, ciphertext, LenMSG5cipher, 4);
    fprintf(log, "\n");

    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits

    memset(plaintext, 0, PLAINTEXT_LEN_MAX);
    
    decrypt(ciphertext, LenMSG5cipher, Ks->key, Ks->iv, plaintext);

    // Parse MSG5 into its components f( Nb )
    memcpy(fNb, plaintext, NONCELEN);
}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    // Note that the nonces are store in Big-Endian byte order
    // This affects how you do arithmetice on the noces, e.g. when you add 1

    uint32_t n_1 = ntohl(*n)+ 1;
    //this needs to include the mod
    uint32_t m = 1 << NONCELEN;
    *r = htonl(n_1);
}
