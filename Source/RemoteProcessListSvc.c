//
// gcc -c RemoteProcessListSvc.c -o RemoteProcessListSvc.exe
//

#include <windows.h>
#include <string.h>
#include <stdio.h>

typedef BOOL  (WINAPI      *EnumProcesses)( DWORD *, DWORD, DWORD * );
typedef BOOL  (WINAPI *EnumProcessModules)( HANDLE, HMODULE *, DWORD, DWORD * );
typedef DWORD (WINAPI  *GetModuleBaseName)( HANDLE, HMODULE, CHAR *, DWORD );

INT WINAPI              ServiceMain( VOID );
VOID WINAPI    MyServiceCtrlHandler( DWORD dwOption );
VOID                 GetProcessInfo( VOID );
VOID                WriteToErrorLog( CHAR *szErrorMsg );
VOID        GetTokenUserInformation( HANDLE *hToken, CHAR *szUsername, DWORD *dwPID );

SERVICE_STATUS        MyServiceStatus;
SERVICE_STATUS_HANDLE MyServiceStatusHandle;

INT main( INT argc, CHAR *argv[] )
{
	SERVICE_TABLE_ENTRY DispatchTable[] = { { "RemoteProcessListSvc", (LPSERVICE_MAIN_FUNCTION)ServiceMain }, { NULL, NULL } };

	StartServiceCtrlDispatcher( DispatchTable );

	return 0;
}

INT WINAPI ServiceMain( VOID )
{
	MyServiceStatus.dwServiceType             = SERVICE_WIN32;
	MyServiceStatus.dwCurrentState            = SERVICE_STOP;
	MyServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
	MyServiceStatus.dwWin32ExitCode           = 0;
	MyServiceStatus.dwServiceSpecificExitCode = 0;
	MyServiceStatus.dwCheckPoint              = 0;
	MyServiceStatus.dwWaitHint                = 0;

	MyServiceStatusHandle = RegisterServiceCtrlHandler( "RemoteProcessListSvc", MyServiceCtrlHandler );

	if ( MyServiceStatusHandle != 0 )
	{
		MyServiceStatus.dwCurrentState = SERVICE_START_PENDING;

		if ( SetServiceStatus( MyServiceStatusHandle, &MyServiceStatus ) )
		{
			MyServiceStatus.dwCurrentState = SERVICE_RUNNING;
 
			if ( SetServiceStatus( MyServiceStatusHandle, &MyServiceStatus ) )
			{
				GetProcessInfo();
			}
		}
	}

	MyServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;

	if ( SetServiceStatus( MyServiceStatusHandle, &MyServiceStatus ) )
	{
		MyServiceStatus.dwCurrentState = SERVICE_ACCEPT_STOP;

		SetServiceStatus( MyServiceStatusHandle, &MyServiceStatus );
	}

	return 0;
}

VOID WINAPI MyServiceCtrlHandler( DWORD dwOption )
{ 
	switch ( dwOption )
	{
		case SERVICE_CONTROL_PAUSE:
			MyServiceStatus.dwCurrentState = SERVICE_PAUSED;

			SetServiceStatus( MyServiceStatusHandle, &MyServiceStatus );

			break;

		case SERVICE_CONTROL_CONTINUE:
			MyServiceStatus.dwCurrentState = SERVICE_RUNNING;

			SetServiceStatus( MyServiceStatusHandle, &MyServiceStatus );

			break;
 
		case SERVICE_CONTROL_STOP:
			break;

		case SERVICE_CONTROL_INTERROGATE:
			break;

		default:
			break;
	}
}

VOID GetProcessInfo( VOID )
{
	HANDLE                          hPSAPI;
	EnumProcesses           pEnumProcesses;
	EnumProcessModules pEnumProcessModules;
	GetModuleBaseName   pGetModuleBaseName;
	DWORD                     dwProcessIDs[ 2048 ];
	DWORD                         dwNeeded;
	DWORD                      dwProcesses;
	unsigned int                         i;
	HANDLE                        hProcess;
	HMODULE                        hModule;
	CHAR                     szProcessName[ 256 ];
	DWORD                         dwResult;
	HANDLE                          hToken;
	CHAR                        szUsername[ 256 ];
	FILE                      *pOutputFile;
	CHAR                        szErrorMsg[ 128 ];

	hPSAPI = LoadLibrary( "psapi.dll" );

	pEnumProcesses      =      (EnumProcesses)GetProcAddress( hPSAPI, "EnumProcesses" );
	pEnumProcessModules = (EnumProcessModules)GetProcAddress( hPSAPI, "EnumProcessModules" );
	pGetModuleBaseName  =  (GetModuleBaseName)GetProcAddress( hPSAPI, "GetModuleBaseNameA" );

	if ( pEnumProcesses && pEnumProcessModules && pGetModuleBaseName )
	{
		if ( pEnumProcesses( dwProcessIDs, sizeof( dwProcessIDs), &dwNeeded ) )
		{
			dwProcesses = dwNeeded / sizeof( DWORD );

			for ( i = 0; i < dwProcesses; i++ )
			{
				if ( dwProcessIDs[i] != 0 )
				{
					hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, dwProcessIDs[i] );

					if ( hProcess != NULL )
					{
						if ( pEnumProcessModules( hProcess, &hModule, sizeof( hModule ), &dwNeeded ) )
						{
							strcpy( szProcessName, "" );

							dwResult = pGetModuleBaseName( hProcess, hModule, szProcessName, sizeof( szProcessName ) / sizeof( CHAR ) );

							if ( dwResult > 0 )
							{
								if ( OpenProcessToken( hProcess, TOKEN_ALL_ACCESS, &hToken ) )
								{
									strcpy( szUsername, "" );

									GetTokenUserInformation( &hToken, szUsername, &dwProcessIDs[i] );

									pOutputFile = fopen( "ProcessList.txt", "r" );

									if ( pOutputFile != NULL )
									{
										fclose( pOutputFile );
									}
									else
									{
										pOutputFile = fopen( "ProcessList.txt", "w" );

										if ( pOutputFile != NULL )
										{
											fprintf( pOutputFile, "NOTE: This file is tab separated. Open with Excel to view and sort information.\n" );
											fprintf( pOutputFile, "\n" );
											fprintf( pOutputFile, "Process ID\tProcess Name\tRunning As User\n" );

											fclose( pOutputFile );
										}
									}

									pOutputFile = fopen( "ProcessList.txt", "a+" );

									if ( pOutputFile != NULL )
									{
										fprintf( pOutputFile, "%d\t%s\t%s\n", dwProcessIDs[i], szProcessName, szUsername );

										fclose( pOutputFile );
									}

									CloseHandle( hToken );
								}
								else
								{
									sprintf( szErrorMsg, "ERROR! Cannot open process token for process ID %d.\n", dwProcessIDs[i] );

									WriteToErrorLog( szErrorMsg );
								}
							}
							else
							{
								sprintf( szErrorMsg, "ERROR! Cannot retrieve module base name for process ID %d.\n", dwProcessIDs[i] );

								WriteToErrorLog( szErrorMsg );
							}
						}
						else
						{
							sprintf( szErrorMsg, "ERROR! Cannot enumerate modules for process ID %d.\n", dwProcessIDs[i] );

							WriteToErrorLog( szErrorMsg );
						}

						CloseHandle( hProcess );
					}
					else
					{
						sprintf( szErrorMsg, "ERROR! Cannot open process ID %d.\n", dwProcessIDs[i] );

						WriteToErrorLog( szErrorMsg );
					}
				}
			}
		}
		else
		{
			sprintf( szErrorMsg, "ERROR! Cannot enumerate process list.\n" );

			WriteToErrorLog( szErrorMsg );
		}

		FreeLibrary( hPSAPI );
	}
	else
	{
		sprintf( szErrorMsg, "ERROR! Cannot load Psapi.dll functions on remote host.\n" );

		WriteToErrorLog( szErrorMsg );
	}
}

VOID WriteToErrorLog( CHAR szErrorMsg[] )
{
	FILE *pOutputFile;

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
			fclose( pOutputFile );
		}
	}

	pOutputFile = fopen( "ErrorLog.txt", "a+" );

	if ( pOutputFile != NULL )
	{
		fprintf( pOutputFile, "%s", szErrorMsg );

		fclose( pOutputFile );
	}
}

VOID GetTokenUserInformation( HANDLE *hToken, CHAR szUsername[], DWORD *dwPID )
{
	DWORD        dwBytesNeeded;
	DWORD              dwError;
	TOKEN_USER          *pInfo;
	DWORD        dwAccountName;
	DWORD         dwDomainName;
	CHAR         szAccountName[ 128 ];
	CHAR          szDomainName[ 128 ];
        SID_NAME_USE         snUse;
	CHAR            szErrorMsg[ 128 ];

	dwBytesNeeded = 0;

	if ( !GetTokenInformation( *hToken, TokenUser, NULL, 0, &dwBytesNeeded ) )
	{
		dwError = GetLastError();

		if ( dwError == ERROR_INSUFFICIENT_BUFFER )
		{
			pInfo = NULL;

			pInfo = (TOKEN_USER *)malloc( dwBytesNeeded * sizeof( TOKEN_USER ) );

			if ( pInfo != NULL )
			{
				if ( GetTokenInformation( *hToken, TokenUser, pInfo, dwBytesNeeded, &dwBytesNeeded ) )
				{
					dwAccountName = sizeof( szAccountName );
					dwDomainName  = sizeof( szDomainName );

					if ( LookupAccountSid( NULL, pInfo->User.Sid, szAccountName, &dwAccountName, szDomainName, &dwDomainName, &snUse ) )
					{
						sprintf( szUsername, "%s\\%s", szDomainName, szAccountName );
					}
					else
					{
						sprintf( szErrorMsg, "ERROR! Cannot lookup account SID for process ID %d.\n", *dwPID );

						WriteToErrorLog( szErrorMsg );
					}
				}
				else
				{
					sprintf( szErrorMsg, "ERROR! Cannot read token information for process ID %d.\n", *dwPID );

					WriteToErrorLog( szErrorMsg );
				}

				free( pInfo );
			}
		}
		else
		{
			sprintf( szErrorMsg, "ERROR! Cannot read token information for process ID %d.\n", *dwPID );

			WriteToErrorLog( szErrorMsg );
		}
	}
}

// Written by Reed Arvin | reedlarvin@gmail.com
