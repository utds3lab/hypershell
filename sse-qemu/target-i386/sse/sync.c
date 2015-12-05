#include"sse.h"
#include<linux/sockios.h>
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


size_t sbuf_size = 0x400000;
target_ulong user_buf;
int p1, p2,p3;
key_t key=1237;
struct sc_info *shm;


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

extern uint8_t *get_ram_addr();
void sig_init(void)
{

    p1 = mysem_init(SEMKEY1, 0); 
    p2 = mysem_init(SEMKEY2, 0); 
    p3 = mysem_init(SEMKEY3, 0); 
    
	int shm_id;
    shm_id = shmget(key, sbuf_size * sizeof(char),IPC_CREAT);
	if(shm_id == -1)
        printf("Create share memory error %s \n", strerror(errno));

    shm = shmat(shm_id,NULL,NULL);
   
   	if(shm == -1)
    {   
        printf("Create share memory error %s \n", strerror(errno));
    }
    mremap(shm, 0x100000, 0x100000, 0x3, get_ram_addr());

	shm = get_ram_addr();
#ifdef DEBUG
    printf("share memory address is %p\n", shm);
#endif
}



//guest inject syscall
void wait_start()
{
	P(p3);
}
void wait_sc(void)
{
 //   P1(0);
 	  P(p1);
}

void sig_finish(target_ulong ret)
{

 //   printf("syscall return %x\n", ret);
	
	shm->sysret = ret;
//	V1(1);
	V(p2);
}
struct iovecs{
			void * base;
			unsigned len;
 };
struct msghdr {
	void	*	msg_name;	/* Socket name			*/
	int		msg_namelen;	/* Length of name		*/
	struct iovec *	msg_iov;	/* Data blocks			*/
	int	msg_iovlen;	/* Number of blocks		*/
	void 	*	msg_control;	/* Per protocol magic (eg BSD file descriptor passing) */
	int	msg_controllen;	/* Length of cmsg list */
	unsigned	msg_flags;
};

int get_sc_info(int arg[], target_ulong * syscall)
{
	int i;
	*syscall = shm->syscall;
	if(*syscall==252)
		printf("Exit\n");
#ifdef DEBUG
    printf("exectue syscall %x %x\n", *syscall, sizeof(struct sc_info));
    if(*syscall == 0x5)
    {
        printf("open file %s\n", (char *)shm + shm->arg[0].buf_addr);
    }
#endif
	if(*syscall ==102)  //sockatcall
	{
		arg[0] = shm->arg[0].value;
		arg[1] = shm->free + user_buf;
		unsigned long *a = (char *)shm + shm->free;
		if(shm->arg[1].value==0x10 ||shm->arg[1].value==0x11)
		{
			a[0] = shm->arg[1].value;
			a[1] = shm->arg[2].buf_addr + user_buf;
		    a[2] = shm->arg[3].value;	
			
			struct msghdr *msg;
			msg = (char *)shm + shm->arg[2].buf_addr;
			msg->msg_name = shm->arg[4].buf_addr + user_buf;
			msg->msg_iov  = shm->arg[5].buf_addr + user_buf;
			if(msg->msg_controllen!=0)
				msg->msg_control = shm->arg[7].buf_addr + user_buf;
			struct iovecs *i =(char *)shm + shm->arg[5].buf_addr;
			i->base = shm->arg[6].buf_addr + user_buf;

		}else{

		for (i=1;i<shm->arg_num;i++)
		{
			if(shm->arg[i].pointer)
				a[i-1]= shm->arg[i].buf_addr + user_buf;
			else
				a[i-1]= shm->arg[i].value;
		}

		}
		return 2;
	}
	if(*syscall == 54 && shm->arg[1].value==SIOCGIFCONF)
	{
		arg[0] = shm->arg[0].value;
		arg[1] = shm->arg[1].value;
		arg[2] = shm->arg[2].buf_addr + user_buf;
		unsigned long *a = (char *)shm + shm->arg[2].buf_addr;
		a[1] = shm->arg[3].buf_addr + user_buf;
		return 3;
	}

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

