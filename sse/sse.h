/*
  #
  #  Copyright © 2015 The University of Texas System Board of Regents, All Rights Reserved.
  #       Author:        The Systems and Software Security (S3) Laboratory.
  #         Date:        May 28, 2015
  #      Version:        1.0.0
  #
*/
typedef unsigned int target_ulong;
struct sys_para{
    int pointer;
    target_ulong value;
    target_ulong buf_addr;
    unsigned int size;
    int iswrite;
};

struct sc_info{
    struct sys_para arg[16];
    int arg_num;
    target_ulong syscall;
    target_ulong sysret;
    target_ulong free;
	int sig[3];
};
union semun
{
     int              val;    /* Value for SETVAL */
     struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
     unsigned short  *array;  /* Array for GETALL, SETALL */
};

void sc_init(int syscall);
int insert_sc_arg_with_buffer(int index, target_ulong value, target_ulong size, int iswrite, int bufindex, int bufsize);
int insert_sc_arg(int index, target_ulong value, target_ulong size, int iswrite);
int dispatch_sc();

//#define DEBUG
