/*
  #
  #  Copyright © 2015 The University of Texas System Board of Regents, All Rights Reserved.
  #       Author:        The Systems and Software Security (S3) Laboratory.
  #         Date:        May 28, 2015
  #      Version:        1.0.0
  #
*/
#include"sse.h"
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/sem.h>
#include <sys/mman.h>


#define SEMKEY1 (key_t)0xF00B00
#define SEMKEY2 (key_t)0xF00B01
#define SEMKEY3 (key_t)0xF00B02


size_t sbuf_size = 0x400000;

int sem_get(key_t key)
{
  int semid; 
  semid = semget(key, 1, 0);

  return semid;
}

int mysem_init(key_t key, int inival)
{
  int semid; 
  union semun arg;
  semid=semget(key,1,0600|IPC_CREAT);
  arg.val=inival;
  semctl(semid, 0, SETVAL, arg);
  return semid;
}

static int p1, p2,p3;
static key_t key=1237;
struct sc_info *shm;
int seminit =0;

inline void P1(int semid)
{
	while(shm->sig[semid]==0);
	shm->sig[semid]=0;
}

inline void V1(int semid)
{	
	shm->sig[semid]=1;
}

void P(int semid)
{
    struct sembuf sb; 
    sb.sem_num=0;
    sb.sem_op=-1;
    sb.sem_flg=0;
    semop(semid,&sb,1);
#ifdef DEBUG2
	fprintf(stderr, "ERROR: %s\n", strerror(errno));
#endif
}

void V(int semid)
{
    struct sembuf sb; 
    sb.sem_num=0;
    sb.sem_op=1;
    sb.sem_flg=0;
    semop(semid,&sb,1); 

#ifdef DEBUG2
	fprintf(stderr, "ERROR: %s\n", strerror(errno));
#endif
}


static struct timeval start, end;
int timestart=0;
void time_start()
{
  timestart=1;
   syscallori(78, &start, NULL);
}
void sig_init(void )__attribute__ ((constructor));
void sig_init(void) 
{

    p1 = sem_get(SEMKEY1); 
    p2 = sem_get(SEMKEY2); 
    p3 = sem_get(SEMKEY3); 
#ifdef NONBLOCK
	V(p3);
#endif
       
    int shm_id;
    shm_id = shmget(key,sbuf_size*sizeof(char),NULL);
    shm = shmat(shm_id,NULL,NULL);
    if(shm == -1)
    {   
        printf("Create share memory error");
    }
#ifdef DEBUG
	printf("initl file\n");
    printf("share memory address is %p\n", shm);
#endif
#if 0
	int i;
	for(i=1;i<1024;i++)
	{
		sc_init(6);
		insert_sc_arg(0, i, 0,0);
		dispatch_sc();
	}
#endif
	gettimeofday(&start, NULL);
	seminit=1;
}

void sig_finish(void )__attribute__ ((destructor));
void sig_finish(void)
{
   seminit = 0;
   gettimeofday(&end, NULL);
   char str[100];
   //sprintf(str, "Finish %f\n", ((end.tv_sec-start.tv_sec)*1000000+end.tv_usec-start.tv_usec)/(double)1000000);
   FILE *f=fopen("timelog","a");
   fprintf(f, "%ld\n", (end.tv_sec-start.tv_sec)*1000000+end.tv_usec-start.tv_usec);
   fclose(f);
   sprintf(str, "Finish %ld %ld %ld %ld %ld\n", (end.tv_sec-start.tv_sec)*1000000+end.tv_usec-start.tv_usec, end.tv_sec, start.tv_sec, end.tv_usec, start.tv_usec);
   sprintf(str, "Finish %ld\n", (end.tv_sec-start.tv_sec)*1000000+end.tv_usec-start.tv_usec);
   syscallori(4, 2, str, strlen(str));
#ifdef NONBLOCK
   sendkill();
   sleep(1);
#endif
}

//host catch syscall
void sc_init(int syscall)
{
    memset(shm, 0, sizeof(struct sc_info));
    shm->free = 0x1000;
    shm->syscall = syscall;
}


int insert_sc_arg_with_buffer(int index, target_ulong value, target_ulong size, int iswrite, int bufindex, int bufsize)
{
   shm->arg[index].value = value;
   shm->arg[index].size = size;
   shm->arg[index].iswrite = iswrite;
   shm->arg_num = index+1;
   
   if(size > 0)
   {
     shm->arg[index].pointer = 1;
     shm->arg[index].buf_addr = shm->free;
     shm->free = shm->free + size;   
     if(!iswrite)
     {
       	memcpy((char *)shm +shm->arg[index].buf_addr, (char*) value, size);  
     }
     if(bufindex !=-1)
     {  
     }
   }else
       shm->arg[index].pointer = 0;
}

int insert_sc_arg(int index, target_ulong value, target_ulong size, int iswrite)
{
   shm->arg[index].value = value;
   shm->arg[index].size = size;
   shm->arg[index].iswrite = iswrite;
   shm->arg_num = index+1;
   
   if(size > 0)
   {
     shm->arg[index].pointer = 1;
     shm->arg[index].buf_addr = shm->free;
     shm->free = shm->free + size;   
     {
       	memcpy((char *)shm +shm->arg[index].buf_addr, (char *) value, size);  
     }
   }else
       shm->arg[index].pointer = 0;
}

int sendkill()
{
	sc_init(252);
	insert_sc_arg(0, 0, 0, 0);
	V(p1);
}

int dispatch_sc()
{
  //  sigset_t intmask; 
  //  sigfillset(&intmask);
  //  sigprocmask(SIG_BLOCK, &intmask, NULL);
    V(p1);
//	V1(0);
    P(p2);
//	P1(1);
  //  sigprocmask(SIG_UNBLOCK, &intmask, NULL);

#ifdef DEBUG1
    printf("syscall return %x %x\n", shm->sysret, sizeof(struct sc_info));
#endif
	
	char str[100];
#ifdef DEBUG
	sprintf(str, "syscall return %5d %08x\n",shm->syscall, shm->sysret);
	syscallori(4,1, str, 31);
#endif

	if(shm->syscall ==0x5 ||(shm->syscall == 102 && shm->arg[0].value==0x1)
	    || shm->syscall==41|| shm->syscall==63
		|| (shm->syscall==221&& shm->arg[2].value==F_DUPFD)
		||shm->syscall==295) //open, socket
		shm->sysret = shm->sysret | 0x1000;
    
    int i;
    struct sys_para *para = shm->arg;
    for(i = 0;i < shm->arg_num;i++)
    {
        if(para[i].iswrite)
        {
       		memcpy((char *) para[i].value, (char *)shm + para[i].buf_addr, para[i].size);  
        }
    }  
    
	return shm->sysret;
}

