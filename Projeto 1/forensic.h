#ifndef _FORENSIC_H_
#define _FORENSIC_H_

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct
{
    bool recursive;
    bool md5;
    bool sha1;
    bool sha256;
    bool output;
    bool verbose;
    char *output_file;
    char *input_file;
    char *log_file_name;
    int logDescriptor;
    int outputDesciptor;

} Arguments;

typedef struct
{
    clock_t start, end;
    struct tms t;
} TimeKeeper;


double getCurrentTime();
void writeToLog(char *act);
void startClock();
int verboseHandler();

void sigint_handler (int signo);
void sigUSR_handler(int signo);
void initializeSignals();


bool initArguments(int argc, char *argv[]);
int getInformationHash(int type, char *info, char *filename);
int getInformationFile(char *displayName, char *filename);
int dirHandler(char *displayName, const char *name);
int inputFilehandler();
int main(int argc, char *argv[]);

#endif
