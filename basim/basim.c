/*----------------------------------------------------------------------------
pa-04_PartTwo:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c     SKELETON

Written By: 
     1- Mason Puckett 
	 2- Stephen Ender
Submitted on: 
     Insert the date of Submission here
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;

    char *developerName = "Code by Mason Puckett and Stephen Ender" ;

    fprintf( stdout , "Starting Basim's     %s\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2B    = atoi(argv[1]) ;  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]) ;  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Basim\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    

    // Use  getKeyFromFile( "basim/basimKey.bin" , .... ) )
    if (getKeyFromFile("basim/basimKey.bin", &Kb) == 0) {
        fprintf(stderr, "\nCould not get Basim's Masker key & IV.\n");
        fprintf( log , "\nCould not get Basim's Masker key & IV.\n");
        exit(-1);
    }
    fprintf( log , "Basim has this Master Kb { key , IV }\n");
    BIO_dump_indent_fp(log, Kb.key, SYMMETRIC_KEY_LEN, 4);
    fprintf( log , "\n" );
    BIO_dump_indent_fp(log, Kb.iv, INITVECTOR_LEN, 4);
    fprintf(log, "\n");
    fflush( log ) ;

    // Get Basim's pre-created Nonces: Nb
	Nonce_t   Nb;  
    getNonce4Basim(1, Nb);
	// Use getNonce4Basim () to get Basim's 1st and only nonce into Nb
    fprintf( log , "Basim will use this Nonce:  Nb\n"  ) ;
	// BIO_dump Nb indented 4 spaces to the righ
    BIO_dump_indent_fp(log, Nb, sizeof(Nonce_t), 4);
    fprintf( log , "\n" );

    fflush( log ) ;
    
    
    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 Receive\n");
    BANNER( log ) ;

    myKey_t Ks;
    char *IDa;
    Nonce_t Na2;

    MSG3_receive(log, fd_A2B, &Kb, &Ks, &IDa, &Na2);
    
    fprintf(log, "Basim received Message 3 from Amal with the following content:\n");
    fprintf(log, "    Ks { Key , IV } (%lu Bytes ) is:\n", KEYSIZE);
    BIO_dump_indent_fp(log, &Ks, KEYSIZE, 4);
    fprintf(log, "\n");

    fprintf(log, "    IDa = '%s'\n", IDa);
    fprintf(log, "    Na2 ( %lu Bytes ) is:\n", NONCELEN);
    BIO_dump_indent_fp(log, &Na2, NONCELEN, 4);
    fprintf(log, "\n");

    //*************************************
    // Construct & Send    Message 4
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 New\n");
    BANNER( log ) ;

    Nonce_t fNa2;
    fNonce(fNa2, Na2);
    uint8_t *msg4;
    size_t LenMsg4;

    LenMsg4 = MSG4_new(log, &msg4, &Ks, &fNa2, &Nb);

    write(fd_B2A, msg4, LenMsg4);

    fprintf(log, "Basim Sent the above MSG4 to Amal\n\n");
    //*************************************
    // Receive   & Process Message 5
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 Receive\n");
    BANNER( log ) ;

    Nonce_t rcvd_fNb;
    Nonce_t fNb;
    fNonce(fNb, Nb);

    fprintf(log, "Basim is expecting back this f( Nb ) in MSG5:\n");
    BIO_dump_indent_fp(log, &fNb, NONCELEN, 4);
    fprintf(log, "\n");

    MSG5_receive(log, fd_A2B, &Ks, &rcvd_fNb);

    char *na_check;
    if(fNb[0] == rcvd_fNb[0]){
        na_check = "VALID";
    }else {
        na_check = "INVALID";
    }

    fprintf(log, "Basim received Message 5 from Amal with this f( Nb ): >>>> %s\n", na_check);
    BIO_dump_indent_fp(log, &rcvd_fNb, NONCELEN, 4);
    fprintf(log, "\n");

    //*************************************   
    // Final Clean-Up
    //*************************************
end_:
    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
