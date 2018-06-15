#include<iostream>
using namespace std;
#include<stdlib.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<iostream>
#include<windows.h>
#include<tlhelp32.h>
#include<io.h>
 
typedef struct LogFile
{
	char ProcessName[100];
	unsigned int pid;
	unsigned int ppid;
	unsigned int thread_cnt;
}LOGFILE;
class Threadinfo//To display Thread Information
{
   private:
		   DWORD PID;//Process ID (unisinged int)
		   HANDLE hTreadSnap;//Handler
		   THREADENTRY32 te32;
  public:
	       Threadinfo(DWORD);
		   BOOL ThreadsDisplay();
		   ~Threadinfo()
		   {
			   CloseHandle(hTreadSnap);
		   }
};//end  of class TheradInfo

Threadinfo::Threadinfo(DWORD no)
{
	PID=no;

	hTreadSnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,PID);//Taking a snapshot of thread
	if(hTreadSnap==INVALID_HANDLE_VALUE)
 	{
		 cout<<"Unable to create the snapshot of currnt thread pool"<<endl ;
		 return;
	}
	te32.dwSize=sizeof(THREADENTRY32);
}

BOOL Threadinfo::ThreadsDisplay()
{
	if(!Thread32First(hTreadSnap,&te32))//Thread32First first thread
	{
		cout<<"Error:in Getting the First Thread"<<endl;
		CloseHandle(hTreadSnap);
		return FALSE;
	}
     	cout<<endl<<"THREAD OF THIS PROCESS:"<<endl;

		do
		{
			if(te32.th32OwnerProcessID==PID)
			{
				cout<<"\tTHREAD ID:"<<te32.th32ThreadID<<endl;
			}
		}while(Thread32Next(hTreadSnap,&te32));//Thread32Next remaining
			
		return TRUE;
}

class DLLInfo//DLL Information Class
{
	private:
		   DWORD PID;
		   MODULEENTRY32 me32;
		   HANDLE hProcessSnap;
		   
    public:
	       DLLInfo(DWORD);
		   BOOL DependentDLLDisplay ();
		   ~DLLInfo()
		   {
			   CloseHandle(hProcessSnap);
		   }
};
DLLInfo::DLLInfo(DWORD no)
{
	PID=no;
	hProcessSnap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,PID);
	if(hProcessSnap==INVALID_HANDLE_VALUE)
	{
		 cout<<"Unable to create the snapshot of currnt thread pool"<<endl ;
		 return;
	}
	me32.dwSize=sizeof(MODULEENTRY32);

}

BOOL DLLInfo::DependentDLLDisplay()
{
	char arr[200];

	if(!Module32First(hProcessSnap,&me32))
  	{
		cout<<"FAILD to get DLL information"<<endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}
     	cout<<"DEPENDENT DDL OF THIS PROCRSS"<<endl;
		do
		{
			wcstombs_s(NULL,arr,200,(wchar_t *)me32.szModule,200);
			cout<<me32.szModule<<endl;

		}while(Module32Next(hProcessSnap,&me32));
			return TRUE;
}

class ProcessInfo
{
	private:
		   DWORD PID;
		   DLLInfo *pdobj;
		   Threadinfo *ptobj;
	       HANDLE hProcessSnap;
		   PROCESSENTRY32 pe32;
		   
    public:
		   ProcessInfo();
		   BOOL ProcessDisplay(char*);
		   BOOL ProcessLog();
	       BOOL ReadLog(DWORD,DWORD,DWORD,DWORD);
		   BOOL ProcessSearch(char*);
		   BOOL killProcess(char*);
		   ~ProcessInfo()//
		   {
			   CloseHandle(hProcessSnap);
    		  // fclose(fp);
		   }
};

ProcessInfo::ProcessInfo()
{
	ptobj=NULL;
	pdobj=NULL;
	hProcessSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);//snapshot of processes
	if(hProcessSnap==INVALID_HANDLE_VALUE)
	{
		 cout<<"Error:Unable to create the snapshot of running process"<<endl ;
		 return;
	}
	pe32.dwSize=sizeof(PROCESSENTRY32);
}

BOOL ProcessInfo::ProcessLog()
{
	char*month[]={"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"};
	char FileName[50],arr[512];
	int rer=0,fb=0,count=0;
	SYSTEMTIME lt;
	LOGFILE fobj;
	FILE *fp;

	GetLocalTime(&lt);

	sprintf_s(FileName,"C://%02d_%02d_%02d %s.txt",lt.wHour,lt.wMinute,lt.wDay,month[lt.wMonth-1]);
	fp=fopen(FileName,"wb");
	if(fp==NULL)
	{
      cout<<"ERROR:Unable to create log file"<<endl;
      return FALSE;
	}
	else
	{
		cout<<"Log file sucessfully gets created as:"<<FileName<<endl;
		cout<<"Time of log file creation is->"<<lt.wHour<<":"<<lt.wMinute<<":"<<lt.wDay<<"th"<<month[lt.wMonth-1]<<endl;
	}
	if(!Process32First(hProcessSnap,&pe32))
	{
		cout<<"ERROR:In finding the first process."<<endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	do
	{
		wcstombs_s(NULL,arr,200,(wchar_t *)pe32.szExeFile,200);
		strcpy_s(fobj.ProcessName,pe32.szExeFile);
		fobj.pid=pe32.th32ProcessID;
		fobj.ppid=pe32.th32ParentProcessID;
		fobj.thread_cnt= pe32.cntThreads;
		fwrite(&fobj,sizeof(fobj),1,fp);
   }while(Process32Next(hProcessSnap,&pe32));
   
	fclose(fp);
    return TRUE;
}

BOOL ProcessInfo::ProcessDisplay(char* option)
{
	char arr[200]; 
	if(!Process32First(hProcessSnap,&pe32))
  	{
		cout<<"Error:In Finding the First process."<<endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	} 
	cout<<"_____Process Information______"<<endl;
  		do
		{
			cout<<endl<<"---------------------------------------------";
			wcstombs_s(NULL,arr,200,(wchar_t *)pe32.szExeFile,200);
			cout<<endl<<"PROCESS NAME:"<<pe32.szExeFile;
			cout<<endl<<"PID:"<<pe32.th32ProcessID;
			cout<<endl<<"Parent PID:"<<pe32.th32ParentProcessID;
            cout<<endl<<"No of Thread:"<<pe32.cntThreads;
			cout<<arr<<endl;
			if((_stricmp(option,"-a")==0)||(_stricmp(option,"-d")==0)||(_stricmp(option,"-t")==0))
			{
				if((_stricmp(option,"-t")==0) || (_stricmp(option,"-a")==0))
				{
					ptobj =new Threadinfo(pe32.th32ProcessID);
					ptobj->ThreadsDisplay();
					delete ptobj;
				}
				if((_stricmp(option,"-d")==0)||(_stricmp(option,"-a")==0))
				{
					pdobj=new  DLLInfo(pe32.th32ProcessID);
					pdobj->DependentDLLDisplay();
					delete pdobj;
				}
			}

		}while(Process32Next(hProcessSnap,&pe32));
		
		return TRUE;
}
BOOL ProcessInfo::ReadLog(DWORD hr,DWORD min,DWORD date,DWORD month)
{
	char FileName[50];
	char* montharr[]={"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"};
	int ret=0,count=0;
	LOGFILE fobj;
	FILE *fp;
	sprintf_s(FileName,"C://%02d_%02d_%02d %s.text",hr,min,date,montharr[month-1]);
	fp=fopen(FileName,"rb");
	if(fp==NULL)
	{
      cout<<"Error:Unable to open logfile named as"<<FileName<<endl;
      return FALSE;
	}
	while(ret=fread(&fobj,1,sizeof(fobj),fp)!=0)
	{
       cout<<"-------------------------------------------------"<<endl;
	   cout<<"PROCESS NAME:           "<<fobj.ProcessName<<endl;
	   cout<<"PID:					  "<<fobj.pid<<endl;
	   cout<<"Parent PID:			  "<<fobj.ppid<<endl;
	   cout<<"Thread count of process:"<<fobj.thread_cnt<<endl;
	}
	return FALSE;
	    	
}
BOOL ProcessInfo::ProcessSearch(char* name)
{
	  char arr[200];
	  BOOL Flag=FALSE;
	  if(!Process32First(hProcessSnap,&pe32))
	  {
		  CloseHandle(hProcessSnap);
		  return FALSE;
	  }
	  do
	  {
		  wcstombs_s(NULL,arr,200,(wchar_t *)pe32.szExeFile,200);
		  if(_stricmp(arr,name)==0)
		  {
             cout<<"-------------------------------------------------"<<endl;
	         cout<<endl<<"PROCESS NAME:"<<pe32.szExeFile;
	         cout<<endl<<"PID:"<<pe32.th32ProcessID;
	         cout<<endl<<"Parent PID:"<<pe32.th32ParentProcessID;
	         cout<<endl<<"No of Thread:"<<pe32.cntThreads;
			 Flag=TRUE;
			 break;
		  }
	 }while(Process32Next(hProcessSnap,&pe32));

		    return Flag;
   	  

}
BOOL ProcessInfo::killProcess(char* name)
{
	char arr[200];
	int pid=-1;
	BOOL bret;
	HANDLE hProcess;
	if(Process32First(hProcessSnap,&pe32))
	{
		CloseHandle(hProcessSnap);
	    return FALSE;
	}
	do
	{
//        wcstombs_s(NULL,arr,200,(wchar_t *)pe32.szExeFile,200);

	    if(_stricmp(pe32.szExeFile,name)==0)
		{
			pid=pe32.th32ProcessID;
			break;
		}
	}while(Process32Next(hProcessSnap,&pe32));

		CloseHandle(hProcessSnap);
		if(pid == -1)
		{
	        cout<<"Error: There is no such Process"<<endl;
            return FALSE;
		}
		hProcess=OpenProcess(PROCESS_TERMINATE,FALSE,pid);
		if(hProcess==NULL)
		{
			cout<<"Error: There is no access to terminate"<<endl;
			return FALSE;
		}
		bret=TerminateProcess(hProcess,0);
		if(bret==FALSE)
		{
			cout<<"ERROR: Unable to Terminate Process";
			return FALSE;
		}
		CloseHandle(hProcessSnap);
    		
		return TRUE;
}
BOOL HardwareInfo()//Hardware Explorer
{
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);

	cout<<"OEM ID:"<<siSysInfo.dwOemId<<endl;
	cout<<"Number of processors:"<<siSysInfo.dwNumberOfProcessors<<endl;
	cout<<"Page size"<<siSysInfo.dwPageSize<<endl;
	cout<<"Processor type:"<<siSysInfo.dwProcessorType<<endl;
	cout<<"Minimun application address:"<<siSysInfo.lpMinimumApplicationAddress<<endl;
	cout<<"Maximum application address:"<<siSysInfo.lpMaximumApplicationAddress<<endl;
	cout<<"Active processor mask:"<<siSysInfo.dwActiveProcessorMask<<endl;
	return TRUE;
}

void  DisplayHelp()
{
	cout<<"Process Monitoring System"<<endl;
	cout<<"ps     : Display of Information of Process"<<endl;
	cout<<"ps-t   : Display all Information about threads"<<endl;
	cout<<"ps-d   : Dispaly all Inforrmation about DLL"<<endl;
	cout<<"cls    : Clear the contents on condole"<<endl;
	cout<<"log    : Creates log of currrent running process on C drive"<<endl;
	cout<<"readlog: Display  the information from specified log file"<<endl;
	cout<<"sysinfo: Display the current hardware configuration"<<endl;
	cout<<"search : Search and display information of specific running process"<<endl;
	cout<<"exit   : Terminate ProcMon"<<endl;
}
int main(int arg,char* argv[])
{
   BOOL bret;
   char* ptr =NULL;
   ProcessInfo *ppobj=NULL;
   char command[4][80],str[80];
   int count,min,date,month,hr;
   char buffer[MAX_COMPUTERNAME_LENGTH + 1]; 
   DWORD size = MAX_COMPUTERNAME_LENGTH + 1 ;
   
   
   while(1)
   {
	   fflush(stdin);//
	   strcpy_s(str,"");
	   
	   GetComputerName(buffer,&size );
   	   cout<<endl<<buffer<<" ProcMon $-> ";
	  
	   fgets(str,80,stdin);
	   count=sscanf(str,"%s %s %s %s",command[0],command[1],command[2],command[3]);
       
	   
	   if(count==1)
	   {
		   if(_stricmp(command[0],"ps")==0)
		   {
			   ppobj=new ProcessInfo();
			   bret=ppobj->ProcessDisplay("-a");//TO display Processes
			   
			   if(bret==FALSE)
			   {
				   cout<<"ERROR: Unable to Display process"<<endl;
			   }
				   delete ppobj;
		   }
		   else if(_stricmp(command[0],"log")==0)
		   {
			    ppobj=new ProcessInfo();
			    bret=ppobj->ProcessLog();
				if(bret==FALSE)
				{
				   cout<<"ERROR: Unable to Display Create log file"<<endl;
				}
				   delete ppobj;
            }
		   else if(_stricmp(command[0],"sysinfo")==0)
		   {
			    bret=HardwareInfo();
				 if(bret==FALSE)
				   cout<<"ERROR: Unable to get Hardware Information"<<endl;
				   cout<<" Hardware Information of currnt system is:"<<endl;

		   }
		   else if(_stricmp(command[0],"readlog")==0)
		   {
			   ProcessInfo *ppobj;
			   ppobj=new ProcessInfo();
			   cout<<" Enter the log file details as:"<<endl;
			   cout<<"\nHour :"; cin>>hr;
			   cout<<"\nMinute:";cin>>min;
			   cout<<"\nDate:";cin>>date;
			   cout<<"\nMonth:";cin>>month;

			   bret=ppobj->ReadLog(hr,min,date,month);
			    if(bret==FALSE)
	     		{
					cout<<"ERROR: Unable to read specified log file"<<endl;
				}   
				delete ppobj;
		   } 
		   else if(_stricmp(command[0],"cls")==0)
		   {
			   system("cls");
			   continue;
		   }
		     else if (_stricmp(command[0],"help")==0)
		   {
			   DisplayHelp();
			   continue;
		   }
		     else if (_stricmp(command[0],"exit")==0)
		   {
			   cout<<"Terminateting the Marvellous ProcMon"<<endl;
			   break;
		   }
			 else
			 {
				cout<<endl<<"ERROR:command not found !!"<<endl;
				continue;
			 }
		}
	   else if(count==2)
	   {
		     if(_stricmp(command[0],"ps")==0)
			 {
				  ppobj=new ProcessInfo();
				  bret=ppobj->ProcessDisplay(command[1]);
				  if(bret==FALSE)
				  {
					cout<<"ERROR: Unable to display process information " <<endl;
				  }
				  delete ppobj;
			 }
			 else if(_stricmp(command[0],"search")==0)
			 {
				  ppobj=new ProcessInfo();
				  bret=ppobj->ProcessSearch(command[1]);
				  if(bret==FALSE)
				  {
					cout<<"ERROR: There is no such Process " <<endl;
				  } 
				  delete ppobj;
				  continue;
	         }
			  else if(_stricmp(command[0],"kill")==0)
			  {
				  ppobj=new ProcessInfo();
				  bret=ppobj->killProcess(command[1]);
				  if(bret==FALSE)
			      {
					  cout<<"ERROR: There is no such Process " <<endl;
				  }
				  else 
				  {
					 cout <<command[1]<<"Terminated Succesfully"<<endl;
				  }
			      delete ppobj;				  continue; 
			  }
		   }			
	         else
			  {
				  cout<<endl<<"ERROR: Command not found!!!"<<endl;
				  continue;
			  }
		}		 
	       return 0;
} // end of Main 
