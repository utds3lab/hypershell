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
#include"cpu.h"
#include <sys/mman.h>


#define SEMKEY1 (key_t)0xF00B00
#define SEMKEY2 (key_t)0xF00B01
#define SEMKEY3 (key_t)0xF00B02


size_t sbuf_size = 0x100000;
target_ulong user_buf;

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

void P(int semid)
{
    struct sembuf sb; 
    sb.sem_num=0;
    sb.sem_op=-1;
    sb.sem_flg=0;
    semop(semid,&sb,1);
#ifdef DEBUG
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

#ifdef DEBUG
	fprintf(stderr, "ERROR: %s\n", strerror(errno));
#endif
}

int p1, p2;
key_t key=1236;
struct sc_info *shm;

extern uint8_t *get_ram_addr();
void sig_init(void)
{

    p1 = mysem_init(SEMKEY1, 0); 
    p2 = mysem_init(SEMKEY2, 0); 
    
	shm = get_ram_addr();
#ifdef DEBUG
    printf("share memory address is %p\n", shm);
#endif
}



//guest inject syscall
void wait_sc(void)
{
    P(p1);
}

void sig_finish(target_ulong ret)
{

#ifdef DEBUG
    printf("syscall return %x\n", ret);
#endif
	
	shm->sysret = ret;
	V(p2);
}

int get_sc_info(int arg[], target_ulong * syscall)
{
	int i;
	*syscall = shm->syscall;
#ifdef DEBUG
    printf("exectue syscall %x %x\n", *syscall, sizeof(struct sc_info));
    if(*syscall == 0x5)
    {
        printf("open file %s\n", (char *)shm + shm->arg[0].buf_addr);
    }
#endif
	for(i=0; i< shm->arg_num;i++)
	{
		if(shm->arg[i].pointer)
			arg[i] = shm->arg[i].buf_addr + user_buf;
		else
			arg[i] = shm->arg[i].value;
	}

	return shm->arg_num;
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
     if(!iswrite)
     {
       	memcpy((char *)shm +shm->arg[index].buf_addr, (char *) value, size);  
     }
   }else
       shm->arg[index].pointer = 0;
}

int dispatch_sc()
{
  //  sigset_t intmask; 
  //  sigfillset(&intmask);
  //  sigprocmask(SIG_BLOCK, &intmask, NULL);
    V(p1);
    P(p2);
  //  sigprocmask(SIG_UNBLOCK, &intmask, NULL);

#ifdef DEBUG
    printf("syscall return %x %x\n", shm->sysret, sizeof(struct sc_info));
#endif
    
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

