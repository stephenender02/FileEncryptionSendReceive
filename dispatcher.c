/*-------------------------------------------------------------------------------

FILE:   dispatcher.c

Written By: 
     1- Dr. Mohamed Aboutabl
     2- Stephen Ender
     3- Mason Puckett
Submitted on: 10/28/2024
-------------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>

#include "wrappers.h"

#define   READ_END	0
#define   WRITE_END	1
#define   STDIN  0
#define   STDOUT 1
//--------------------------------------------------------------------------
int main( int argc , char *argv[] )
{
    pid_t  kcdPID, amalPID , basimPID ;

    int    KtoA[2], AtoK[2]; // KDC Amal communication pipes 

    int    AtoB[2], BtoA[2] ;  // Amal Basim communication pipes
    char   arg1[20] , arg2[20] , arg3[20] , arg4[20];
    
    Pipe (AtoK); // Create pipe for Amal to KDC
    Pipe (KtoA); // Create pipe for KDC to Amal
    Pipe( AtoB ) ;  // create pipe for Amal-to-Basim
    Pipe( BtoA ) ;  // create pipe for Basim-to-Amal

    printf("\nDispatcher started ... ") ;
    char myUserName[30] ;
    getlogin_r ( myUserName , 30 ) ;
    time_t  now;
    time( &now ) ;
    fprintf( stdout , "Logged in as user '%s' on %s\n\n" , myUserName ,  ctime( &now)  ) ;
    printf("\tDispatcher started and created these pipes\n") ;
    printf("\tAmal to KDC pipe: read=%d  write=%d\n", AtoK[ READ_END ] , AtoK[ WRITE_END ] ) ;
    printf("\tKDC to Amal pipe: read=%d  write=%d\n", KtoA[ READ_END ] , KtoA[ WRITE_END ] ) ;
    printf("\tAmal-to-Basim pipe: read=%d  write=%d\n", AtoB[ READ_END ] , AtoB[ WRITE_END ] ) ;
    printf("\tBasim-to-Amal pipe: read=%d  write=%d\n", BtoA[ READ_END ] , BtoA[ WRITE_END ] ) ;


    // Create both child processes:
    amalPID = Fork() ;
    if ( amalPID == 0 )
    {    
        // This is the Amal process.
        // Amal will not use these ends of the pipes, decrement their 'Ref Count'
        close( AtoB[ READ_END ] ) ;
        close( BtoA[ WRITE_END ] ) ;
        close(AtoK[READ_END]);
        close(KtoA[WRITE_END]);
        
        // Prepare the file descriptors as args to Amal
        snprintf( arg1 , 20 , "%d" , KtoA[ READ_END ] ) ;
        snprintf( arg2 , 20 , "%d" , AtoK[ WRITE_END ] ) ;
        snprintf( arg3 , 20 , "%d" , BtoA[ READ_END ] ) ;
        snprintf( arg4 , 20 , "%d" , AtoB[ WRITE_END ] ) ;
        
        // Now, Start Amal
        char * cmnd = "./amal/amal" ;
        execlp(cmnd, "Amal", arg1, arg2, arg3, arg4, NULL);

        // the above execlp() only returns if an error occurs
        perror("ERROR starting Amal" );
        exit(-1) ;      
    } 
    else
    {    // This is still the Dispatcher process 
        basimPID = Fork() ;
        if ( basimPID == 0 )
        {  
            // This is the Basim process
            // Basim will not use these ends of the pipes, decrement their 'count'
            close( AtoB[ WRITE_END ] ) ;
            close( BtoA[ READ_END ] ) ;
            
            // Prepare the file descriptors as args to Basim
            snprintf( arg1 , 20 , "%d" , AtoB[ READ_END ] ) ;
            snprintf( arg2 , 20 , "%d" , BtoA[ WRITE_END ] ) ;

            // Start Basim
            char * cmnd = "./basim/basim" ;
            execlp(cmnd, "Basim", arg1, arg2, NULL);

            // the above execlp() only returns if an error occurs
            perror("ERROR starting Basim" ) ;
            exit(-1) ;
        }
        else
        {   // This is still the parent Dispatcher  process
            kcdPID = Fork();
            if (kcdPID == 0) {

                // This is the KDC process
                // KDC will not use these ends of the pipes, decrement their 'count
                close(KtoA[READ_END]);
                close(AtoK[WRITE_END]);

                // Prepare file descriptors as args to KDC
                snprintf( arg1 , 20 , "%d" , AtoK[ READ_END ] ) ;
                snprintf( arg2 , 20 , "%d" , KtoA[ WRITE_END ] ) ;

                // Start KDC
                char * cmnd = "./kdc/kdc" ;
                execlp(cmnd, "KDC", arg1, arg2, NULL);

                // the above execlp() only returns if an error occurs
                perror("ERROR starting KDC" ) ;
                exit(-1) ;

            } else {
                // This is still the parent Dispatcher  process
                // close all ends of the pipes so that their 'count' is decremented
                close( AtoB[ WRITE_END ] ); 
                close( AtoB[ READ_END  ]  );   
                close( BtoA[ WRITE_END ] ); 
                close( BtoA[ READ_END  ]  ); 
                close(KtoA[WRITE_END]);
                close(KtoA[READ_END]);
                close(AtoK[WRITE_END]);
                close(AtoK[READ_END]);

                printf("\n\tDispatcher is now waiting for Amal to terminate\n") ;
                int  exitStatus ;
                waitpid( amalPID , &exitStatus , 0 ) ;
                printf("\n\tAmal terminated ... "  ) ;
                if (  WIFEXITED( exitStatus ) )
                        printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\n\tDispatcher is now waiting for Basim to terminate\n") ;
                waitpid( basimPID , &exitStatus , 0 ) ;
                printf("\n\tBasim terminated ... " ) ;
                if (  WIFEXITED( exitStatus ) )
                        printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\n\tDispatcher is now waiting for KDC to terminate\n") ;
                waitpid( kcdPID , &exitStatus , 0 ) ;
                printf("\n\tKDC terminated ... " ) ;
                if (  WIFEXITED( exitStatus ) )
                        printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;
            }
        }
    }  
}

