//
// gcc RemoteProcessList.c -o RemoteProcessList.exe -lnetapi32 -ladvapi32
//

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <process.h>
#include <lm.h>

#define MAX_THREADS 64

VOID              ThreadedSub( VOID *pParameter );
BOOL                  Connect( CHAR *szTarget, CHAR *szUsername, CHAR *szPassword, BOOL *bMultipleHosts );
VOID WriteLastErrorToErrorLog( CHAR *szTarget, CHAR *szFunction, DWORD *dwError, BOOL *bMultipleHosts );
VOID CaptureRemoteProcessList( CHAR *szTarget, BOOL *bMultipleHosts );
BOOL               Disconnect( CHAR *szTarget, BOOL *bMultipleHosts );

typedef struct _THREAD_ARGS
{
	CHAR        Target[ 128 ];
	CHAR      Username[ 128 ];
	CHAR      Password[ 128 ];
	BOOL MultipleHosts;
} THREAD_ARGS, *PTHREAD_ARGS;

HANDLE hSemaphore;

INT nThreads = 0;

INT main( INT argc, CHAR *argv[] )
{
	CHAR szTargetInput[ 128 ];
	CHAR    szUsername[ 128 ];
	CHAR    szPassword[ 128 ];
	FILE   *pInputFile;
	CHAR      szTarget[ 128 ];

	PTHREAD_ARGS pThreadArgs;

	hSemaphore = CreateSemaphore( NULL, 1, 1, NULL );

	if ( argc == 4 )
	{
		strcpy( szTargetInput, argv[1] );
		strcpy( szUsername,    argv[2] );
		strcpy( szPassword,    argv[3] );

		printf( "Running RemoteProcessList v1.2 with the following arguments:\n" );
		printf( "[+] Host Input:   \"%s\"\n", szTargetInput );
		printf( "[+] Username:     \"%s\"\n", szUsername );
		printf( "[+] Password:     \"%s\"\n", szPassword );
		printf( "[+] # of Threads: \"64\"\n" );
		printf( "\n" );

		pInputFile = fopen( szTargetInput, "r" );

		if ( pInputFile != NULL )
		{
			while ( fscanf( pInputFile, "%s", szTarget ) != EOF )
			{
				while ( nThreads >= MAX_THREADS )
				{
					Sleep( 200 );
				}

				pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

				if ( pThreadArgs != NULL )
				{
					strcpy( pThreadArgs->Target,   szTarget );
					strcpy( pThreadArgs->Username, szUsername );
					strcpy( pThreadArgs->Password, szPassword );

					pThreadArgs->MultipleHosts = TRUE;

					WaitForSingleObject( hSemaphore, INFINITE );

					nThreads++;

					ReleaseSemaphore( hSemaphore, 1, NULL );

					_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
				}
			}

			fclose( pInputFile );

			Sleep( 1000 );

			printf( "Waiting for threads to terminate...\n" );
		}
		else
		{
			strcpy( szTarget, szTargetInput );

			pThreadArgs = (PTHREAD_ARGS)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof( THREAD_ARGS ) );

			if ( pThreadArgs != NULL )
			{
				strcpy( pThreadArgs->Target,   szTarget );
				strcpy( pThreadArgs->Username, szUsername );
				strcpy( pThreadArgs->Password, szPassword );

				pThreadArgs->MultipleHosts = FALSE;

				WaitForSingleObject( hSemaphore, INFINITE );

				nThreads++;

				ReleaseSemaphore( hSemaphore, 1, NULL );

				_beginthread( ThreadedSub, 0, (VOID *)pThreadArgs );
			}
		}

		while ( nThreads > 0 )
		{
			Sleep( 200 );
		}
	}
	else
	{
		printf( "RemoteProcessList v1.2 | https://github.com/reedarvin\n" );
		printf( "\n" );
		printf( "Usage: RemoteProcessList <hostname | ip input file> <username> <password>\n" );
		printf( "\n" );
		printf( "<hostname | ip input file>  -- required argument\n" );
		printf( "<username>                  -- required argument\n" );
		printf( "<password>                  -- required argument\n" );
		printf( "\n" );
		printf( "If the <username> and <password> arguments are both plus signs (+), the\n" );
		printf( "existing credentials of the user running this utility will be used.\n" );
		printf( "\n" );
		printf( "Examples:\n" );
		printf( "RemoteProcessList 10.10.10.10 + +\n" );
		printf( "RemoteProcessList 10.10.10.10 administrator password\n" );
		printf( "\n" );
		printf( "RemoteProcessList MyWindowsMachine + +\n" );
		printf( "RemoteProcessList MyWindowsMachine administrator password\n" );
		printf( "\n" );
		printf( "RemoteProcessList IPInputFile.txt + +\n" );
		printf( "RemoteProcessList IPInputFile.txt administrator password\n" );
		printf( "\n" );
		printf( "(Written by Reed Arvin | reedlarvin@gmail.com)\n" );
	}

	CloseHandle( hSemaphore );

	return 0;
}

VOID ThreadedSub( VOID *pParameter )
{
	CHAR       szTarget[ 128 ];
	CHAR     szUsername[ 128 ];
	CHAR     szPassword[ 128 ];
	BOOL bMultipleHosts;

	PTHREAD_ARGS pThreadArgs;

	pThreadArgs = (PTHREAD_ARGS)pParameter;

	strcpy( szTarget,   pThreadArgs->Target );
	strcpy( szUsername, pThreadArgs->Username );
	strcpy( szPassword, pThreadArgs->Password );

	bMultipleHosts = pThreadArgs->MultipleHosts;

	HeapFree( GetProcessHeap(), 0, pThreadArgs );

	if ( bMultipleHosts )
	{
		printf( "Spawning thread for host %s...\n", szTarget );
	}

	if ( strcmp( szUsername, "+" ) == 0 && strcmp( szPassword, "+" ) == 0 )
	{
		CaptureRemoteProcessList( szTarget, &bMultipleHosts );
	}
	else
	{
		if ( Connect( szTarget, szUsername, szPassword, &bMultipleHosts ) )
		{
			CaptureRemoteProcessList( szTarget, &bMultipleHosts );

			Disconnect( szTarget, &bMultipleHosts );
		}
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	nThreads--;

	ReleaseSemaphore( hSemaphore, 1, NULL );

	_endthread();
}

BOOL Connect( CHAR szTarget[], CHAR szUsername[], CHAR szPassword[], BOOL *bMultipleHosts )
{
	BOOL                  bReturn;
	CHAR               *pLocation;
	CHAR             szTempTarget[ 128 ];
	CHAR             szRemoteName[ 128 ];
	DWORD          dwTextLocation;
	DWORD                       i;
	CHAR             szDomainName[ 128 ];
	DWORD                       j;
	CHAR           szTempUsername[ 128 ];
	WCHAR           wszRemoteName[ 256 ];
	WCHAR           wszDomainName[ 256 ];
	WCHAR             wszUsername[ 256 ];
	WCHAR             wszPassword[ 256 ];
	DWORD                 dwLevel;
	USE_INFO_2            ui2Info;
	NET_API_STATUS        nStatus;
	DWORD                 dwError;

	bReturn = FALSE;

	pLocation = strstr( szTarget, "\\\\" );

	if ( pLocation != NULL )
	{
		strcpy( szTempTarget, szTarget );
	}
	else
	{
		sprintf( szTempTarget, "\\\\%s", szTarget );
	}

	sprintf( szRemoteName, "%s\\ADMIN$", szTempTarget );

	pLocation = strstr( szUsername, "\\" );

	if ( pLocation != NULL )
	{
		dwTextLocation = (INT)( pLocation - szUsername );

		i = 0;

		while ( i < dwTextLocation )
		{
			szDomainName[i] = szUsername[i];

			i++;
		}

		szDomainName[i] = '\0';

		i = dwTextLocation + 1;

		j = 0;

		while ( i < strlen( szUsername ) )
		{
			szTempUsername[j] = szUsername[i];

			i++;
			j++;
		}

		szTempUsername[j] = '\0';
	}
	else
	{
		if ( strcmp( szUsername, "" ) != 0 )
		{
			strcpy( szDomainName, szTarget );
		}
		else
		{
			strcpy( szDomainName, "" );
		}

		strcpy( szTempUsername, szUsername );
	}

	MultiByteToWideChar( CP_ACP, 0, szRemoteName,   strlen( szRemoteName ) + 1,   wszRemoteName, sizeof( wszRemoteName ) / sizeof( wszRemoteName[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szDomainName,   strlen( szDomainName ) + 1,   wszDomainName, sizeof( wszDomainName ) / sizeof( wszDomainName[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szTempUsername, strlen( szTempUsername ) + 1, wszUsername,   sizeof( wszUsername ) / sizeof( wszUsername[0] ) );
	MultiByteToWideChar( CP_ACP, 0, szPassword,     strlen( szPassword ) + 1,     wszPassword,   sizeof( wszPassword ) / sizeof( wszPassword[0] ) );

	dwLevel = 2;

	ui2Info.ui2_local      = NULL;
	ui2Info.ui2_remote     = wszRemoteName;
	ui2Info.ui2_password   = wszPassword;
	ui2Info.ui2_asg_type   = USE_WILDCARD;
	ui2Info.ui2_username   = wszUsername;
	ui2Info.ui2_domainname = wszDomainName;

	nStatus = NetUseAdd( NULL, dwLevel, (BYTE *)&ui2Info, NULL );

	if ( nStatus == NERR_Success )
	{
		bReturn = TRUE;
	}
	else
	{
		dwError = nStatus;

		WriteLastErrorToErrorLog( szTarget, "NetUseAdd (Connect)", &dwError, bMultipleHosts );
	}

	return bReturn;
}

VOID WriteLastErrorToErrorLog( CHAR szTarget[], CHAR szFunction[], DWORD *dwError, BOOL *bMultipleHosts )
{
	DWORD     dwReturn;
	CHAR    szErrorMsg[ 128 ];
	CHAR     *pNewLine;
	FILE  *pOutputFile;

	dwReturn = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, *dwError, MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), szErrorMsg, sizeof( szErrorMsg ), NULL );

	if ( dwReturn > 0 )
	{
		pNewLine = strchr( szErrorMsg, '\r' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}

		pNewLine = strchr( szErrorMsg, '\n' );

		if ( pNewLine != NULL )
		{
			*pNewLine = '\0';
		}
	}
	else
	{
		strcpy( szErrorMsg, "Unknown error occurred." );
	}

	if ( !*bMultipleHosts )
	{
		fprintf( stderr, "ERROR! %s - %s\n", szFunction, szErrorMsg );
	}

	WaitForSingleObject( hSemaphore, INFINITE );

	pOutputFile = fopen( "ErrorLog.txt", "r" );

	if ( pOutputFile != NULL )
	{
		fclose( pOutputFile );
	}
	else
	{
		pOutputFile = fopen( "ErrorLog.txt", "w" );

		if ( pOutputFile != NULL )
		{
			fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
			fprintf( pOutputFile, "\n" );
			fprintf( pOutputFile, "Hostname\tFunction Name\tError Number\tError Message\n" );

			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "ErrorLog.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		fprintf( pOutputFile, "%s\t%s\t%d\t%s\n", szTarget, szFunction, *dwError, szErrorMsg );

		fclose( pOutputFile );
	}

	ReleaseSemaphore( hSemaphore, 1, NULL );
}

VOID CaptureRemoteProcessList( CHAR szTarget[], BOOL *bMultipleHosts )
{
	CHAR                   szRemoteEXEPath[ 256 ];
	SC_HANDLE                 schSCManager;
	SC_HANDLE                   schService;
	SERVICE_STATUS_PROCESS        ssStatus;
	DWORD                    dwBytesNeeded;
	CHAR                     szSrcFileName[ 256 ];
	CHAR                     szDstFileName[ 256 ];
	DWORD                          dwError;

	sprintf( szRemoteEXEPath, "\\\\%s\\ADMIN$\\System32\\RemoteProcessListSvc.exe", szTarget );

	if ( CopyFile( "RemoteProcessListSvc.exe", szRemoteEXEPath, FALSE ) )
	{
		schSCManager = OpenSCManager( szTarget, NULL, SC_MANAGER_ALL_ACCESS );

		if ( schSCManager != NULL )
		{
			schService = CreateService( schSCManager, "RemoteProcessListSvc", "RemoteProcessList Service", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, "%SystemRoot%\\System32\\RemoteProcessListSvc.exe", NULL, NULL, NULL, NULL, NULL );

			if ( schService != NULL )
			{
				if ( StartService( schService, 0, NULL ) )
				{
					if ( !*bMultipleHosts )
					{
						printf( "Waiting for RemoteProcessList service to terminate on host %s", szTarget );
					}

					while ( TRUE )
					{
						if ( QueryServiceStatusEx( schService, SC_STATUS_PROCESS_INFO, (BYTE *)&ssStatus, sizeof( SERVICE_STATUS_PROCESS ), &dwBytesNeeded ) )
						{
							if ( ssStatus.dwCurrentState == SERVICE_STOPPED )
							{
								break;
							}
							else
							{
								if ( !*bMultipleHosts )
								{
									printf( "." );
								}
							}
						}
						else
						{
							dwError = GetLastError();

							WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (QueryServiceStatusEx)", &dwError, bMultipleHosts );

							break;
						}

						Sleep( 1000 );
					}

					if ( !*bMultipleHosts )
					{
						printf( "\n" );
						printf( "\n" );
					}

					sprintf( szSrcFileName, "\\\\%s\\ADMIN$\\System32\\ProcessList.txt", szTarget );
					sprintf( szDstFileName, "%s-ProcessList.txt", szTarget );

					if ( CopyFile( szSrcFileName, szDstFileName, FALSE ) )
					{
						if ( !*bMultipleHosts )
						{
							printf( "Retrieved file %s-ProcessList.txt\n", szTarget );
						}

						if ( !DeleteFile( szSrcFileName ) )
						{
							dwError = GetLastError();

							WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (DeleteFile)", &dwError, bMultipleHosts );
						}
					}
					else
					{
						dwError = GetLastError();

						WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (CopyFile)", &dwError, bMultipleHosts );
					}

					sprintf( szSrcFileName, "\\\\%s\\ADMIN$\\System32\\ErrorLog.txt", szTarget );
					sprintf( szDstFileName, "%s-ErrorLog.txt", szTarget );

					if ( CopyFile( szSrcFileName, szDstFileName, FALSE ) )
					{
						if ( !*bMultipleHosts )
						{
							printf( "Retrieved file %s-ErrorLog.txt\n", szTarget );
						}

						if ( !DeleteFile( szSrcFileName ) )
						{
							dwError = GetLastError();

							WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (DeleteFile)", &dwError, bMultipleHosts );
						}
					}
				}
				else
				{
					dwError = GetLastError();

					WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (StartService)", &dwError, bMultipleHosts );
				}

				if ( !DeleteService( schService ) != 0 )
				{
					dwError = GetLastError();

					WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (DeleteService)", &dwError, bMultipleHosts );
				}

				CloseServiceHandle( schService );
			}
			else
			{
				dwError = GetLastError();

				WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (CreateService)", &dwError, bMultipleHosts );
			}

			CloseServiceHandle( schSCManager );
		}
		else
		{
			dwError = GetLastError();

			WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (OpenSCManager)", &dwError, bMultipleHosts );
		}

		if ( !DeleteFile( szRemoteEXEPath ) )
		{
			dwError = GetLastError();

			WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (DeleteFile)", &dwError, bMultipleHosts );
		}
	}
	else
	{
		dwError = GetLastError();

		WriteLastErrorToErrorLog( szTarget, "CaptureRemoteProcessList (CopyFile)", &dwError, bMultipleHosts );
	}
}

BOOL Disconnect( CHAR szTarget[], BOOL *bMultipleHosts )
{
	BOOL                 bReturn;
	CHAR              *pLocation;
	CHAR            szTempTarget[ 128 ];
	CHAR            szRemoteName[ 128 ];
	WCHAR          wszRemoteName[ 256 ];
	NET_API_STATUS       nStatus;
	DWORD                dwError;

	bReturn = FALSE;

	pLocation = strstr( szTarget, "\\\\" );

	if ( pLocation != NULL )
	{
		strcpy( szTempTarget, szTarget );
	}
	else
	{
		sprintf( szTempTarget, "\\\\%s", szTarget );
	}

	sprintf( szRemoteName, "%s\\ADMIN$", szTempTarget );

	MultiByteToWideChar( CP_ACP, 0, szRemoteName, strlen( szRemoteName ) + 1, wszRemoteName, sizeof( wszRemoteName ) / sizeof( wszRemoteName[0] ) );

	nStatus = NetUseDel( NULL, wszRemoteName, USE_LOTS_OF_FORCE );

	if ( nStatus == NERR_Success )
	{
		bReturn = TRUE;
	}
	else
	{
		dwError = nStatus;

		WriteLastErrorToErrorLog( szTarget, "NetUseDel (Disconnect)", &dwError, bMultipleHosts );
	}

	return bReturn;
}

// Written by Reed Arvin | reedlarvin@gmail.com
