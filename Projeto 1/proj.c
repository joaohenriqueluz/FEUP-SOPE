#include "forensic.h"

Arguments arguments;
TimeKeeper timeKepper;

int parentPid;
int filesN = 0;
int dirN = 0;
bool doneProg = false;

double getCurrentTime()
{
    long ticks = sysconf(_SC_CLK_TCK);
    timeKepper.end = times(&timeKepper.t);
    return (double)(timeKepper.end - timeKepper.start) / ticks * 1000;
}

void writeToLog(char *act)
{

    char *logLine = malloc(sizeof(char) * 1024);
    double inst = getCurrentTime();
    pid_t pid = getpid();

    sprintf(logLine, "%10.2f - %8d - %s\n", inst, pid, act);
    write(arguments.logDescriptor, logLine, strlen(logLine));
    free(logLine);
}

void startClock()
{
    timeKepper.start = times(&timeKepper.t); /* início da medição de tempo */
}

int verboseHandler()
{
    char *res = getenv("LOGFILENAME");
    arguments.log_file_name = res;
    if (res == NULL)
    {
        printf("LOGFILENAME environment variable not defined\n");
        exit(1);
    }

    arguments.logDescriptor = open(arguments.log_file_name, O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (arguments.logDescriptor == -1)
    {
        printf("LogFile error: \n");
        perror(arguments.log_file_name);
        return 3;
    }

    return 0;
}

void sigint_handler(int signo)
{
    //CTRL-C
    if (signo == SIGINT)
    {
        doneProg = true;
        if (arguments.verbose)
            writeToLog("SIGNAL_RECEIVED SIGINT");
        printf("DONE: %d\n", getpid());
    }
}

void sigUSR_handler(int signo)
{
    if (signo == SIGUSR1)
    {
        dirN++;
        if(arguments.output)
            printf("\nNew directory: %d/%d directories/files at this time.\n", dirN, filesN);
        if (arguments.verbose)
            writeToLog("SIGNAL_RECEIVED USR1");
    }
    else if (signo == SIGUSR2)
    {
        filesN++;
        if (arguments.verbose)
            writeToLog("SIGNAL_RECEIVED USR2");
    }
}

void initializeSignals()
{
    if (signal(SIGUSR1, sigUSR_handler) == SIG_ERR)
    {
        fprintf(stderr, "Unable to install SIGUSR1 handler\n");
        exit(1);
    }

    if (signal(SIGUSR2, sigUSR_handler) == SIG_ERR)
    {
        fprintf(stderr, "Unable to install SIGUSR2 handler\n");
        exit(1);
    }

    if (signal(SIGINT, sigint_handler) == SIG_ERR)
    {
        fprintf(stderr, "Unable to install SIGINT handler\n");
        exit(1);
    }

    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
    {
        fprintf(stderr, "Unable to ignore SIGINT\n");
        exit(1);
    }
}

bool initArguments(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>\n");
        return 1;
    }

    int index = 1;
    bool done = false;
    if (strcmp(argv[index], "-r") == 0)
    {
        arguments.recursive = true;
        index++;
        if (index >= argc)
            done = true;
    }

    if (!done && strcmp(argv[index], "-h") == 0)
    {
        index++;

        if (strstr(argv[index], "md5") != NULL)
        {
            arguments.md5 = true;
            printf("md5\n");
        }

        if (strstr(argv[index], "sha1") != NULL)
        {
            arguments.sha1 = true;
            printf("sha1\n");
        }

        if (strstr(argv[index], "sha256") != NULL)
        {
            arguments.sha256 = true;
            printf("sha256\n");
        }
        if (!arguments.md5 && !arguments.sha1 && !arguments.sha256)
            return 1;
        index++;
        if (index >= argc)
            done = true;
    }

    if (!done && strcmp(argv[index], "-o") == 0)
    {
        index++;
        arguments.output = true;
        arguments.output_file = argv[index++];

        arguments.outputDesciptor = open(arguments.output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (arguments.outputDesciptor == -1)
        {
            printf("output file error: \n");
            return 3;
        }
        if (index >= argc)
            done = true;
    }

    if (!done && strcmp(argv[index], "-v") == 0)
    {
        index++;
        arguments.verbose = true;
        verboseHandler();
        if (index >= argc)
            done = true;
    }

    if (done)
    {
        printf("No specified input file\n");
        return 1;
    }

    arguments.input_file = argv[index++];

    return 0;
}

int getInformationHash(int type, char *info, char *filename)
{
    int MAXLINE = 200;
    char line[MAXLINE];
    FILE *fpout;
    char buffer[200];
    strcat(info, ",");

    if (type == 0)
        snprintf(buffer, sizeof(buffer), "/usr/bin/md5sum %s", filename);

    else if (type == 1)
    {
        snprintf(buffer, sizeof(buffer), "/usr/bin/sha1sum %s", filename);
    }

    else
    {
        snprintf(buffer, sizeof(buffer), "/usr/bin/sha256sum %s", filename);
    }

    fpout = popen(buffer, "r");
    fgets(line, MAXLINE, fpout);

    for (unsigned int i = 0; i < strlen(line); i++)
        if (line[i] == ' ')
        {
            line[i] = '\0';
            break;
        }

    strcat(info, line);

    pclose(fpout);

    return 0;
}

int getInformationFile(char *displayName, char *filename)
{
    struct stat status;
    char *info = malloc(sizeof(char) * 1024);
    stat(filename, &status);

    
    if (arguments.verbose)
        writeToLog("SIGNAL_SENT USR2");
    kill(parentPid, SIGUSR2);

    strcpy(info, displayName);
    strcat(info, ",");

    int MAXLINE = 200;
    char line[MAXLINE];
    FILE *fpout;
    char buffer[200];
    snprintf(buffer, sizeof(buffer), "/usr/bin/file %s", filename);

    fpout = popen(buffer, "r");
    fgets(line, MAXLINE, fpout);
    char *new;
    if ((new = strrchr(line, ',')) == NULL)
    {
        new = strrchr(line, ':') + 2;
    }
    else
    {
        new += 2;
    }
    char *pos;
    if ((pos = strchr(new, '\n')) != NULL)
        *pos = '\0';

    strcat(info, new);
    strcat(info, ",");
    pclose(fpout);

    snprintf(buffer, sizeof(buffer), "%ld", status.st_size);

    strcat(info, buffer);
    strcat(info, ",");

    strcat(info, (status.st_mode & S_IRUSR) ? "r" : "");

    strcat(info, (status.st_mode & S_IWUSR) ? "w" : "");

    strcat(info, (status.st_mode & S_IXUSR) ? "x" : "");

    strcat(info, ",");

    char buff[20];
    strftime(buff, 20, "%Y-%m-%dT%H:%M:%S", localtime(&status.st_atime));
    strcat(info, buff);
    strcat(info, ",");

    strftime(buff, 20, "%Y-%m-%dT%H:%M:%S", localtime(&status.st_mtime));
    strcat(info, buff);

    if (arguments.md5)
    {
        getInformationHash(0, info, filename);
    }
    if (arguments.sha1)
    {
        getInformationHash(1, info, filename);
    }
    if (arguments.sha256)
    {
        getInformationHash(2, info, filename);
    }

    strcat(info, "\n");
    if (arguments.output)
    {
        write(arguments.outputDesciptor, info, strlen(info));
    }
    else
    {
        printf("%s", info);
    }

    if (arguments.verbose)
    {
        char *act = malloc(sizeof(char) * 1024);
        sprintf(act, "ANALIZED %s", displayName);
        writeToLog(act);
        free(act);
    }

    free(info);

    return 0;
}

int dirHandler(char *displayName, const char *name)
{
    DIR *dir;
    struct dirent *dirent;
    struct stat stat_entry;

    if (!(dir = opendir(name)))
    {
        printf("Failed open dir\n");
        return -1;
    }

    if (arguments.verbose){
        char *act = malloc(sizeof(char) * 1024);
        sprintf(act, "OPENED DIRECTORY %s",name);
        writeToLog(act);
        free(act);

        writeToLog("SIGNAL_SENT USR1");
    }
    kill(parentPid, SIGUSR1);

    while ((dirent = readdir(dir)) != NULL && !doneProg)
    {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", name, dirent->d_name);

        char displayPath[1024];
        if (strcmp(displayName, "") == 0)
            snprintf(displayPath, sizeof(displayPath), "%s", dirent->d_name);
        else
            snprintf(displayPath, sizeof(displayPath), "%s/%s", displayName, dirent->d_name);

        if (lstat(path, &stat_entry) == -1)
        {
            perror("lstat Error");
            return -1;
        }

        if (S_ISREG(stat_entry.st_mode))
        {
            getInformationFile(displayPath, path);
        }
        else if (S_ISDIR(stat_entry.st_mode))
        {
            if (!arguments.recursive)
                continue;

            if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
                continue;

            pid_t pid = fork();
            if (pid < 0)
            {
                perror("Fork Error");
                return -1;
            }
            else if (pid == 0)
            {
                dirHandler(displayPath, path);

                break;
            }
                  
            
        }
    }

    if(closedir(dir) == 0)
        if (arguments.verbose){
            char *act = malloc(sizeof(char) * 1024);
            sprintf(act, "CLOSED DIRECTORY %s",name);
            writeToLog(act);
            free(act);
        }
    return 0;
}

int inputFilehandler()
{
    struct stat buf;

    if (lstat(arguments.input_file, &buf) == -1)
    {
        perror("lstat Error");
        exit(2);
    }

    if (S_ISREG(buf.st_mode))
    {
        char *filename = arguments.input_file;
        if (getInformationFile(filename, filename) != 0)
            return 1;
    }
    else if (S_ISDIR(buf.st_mode))
    {
        dirHandler("", arguments.input_file);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    startClock();

    if (initArguments(argc, argv))
    {
        return 1;
    }

    parentPid = getpid();

    if (arguments.verbose)
    {
        char *act = malloc(sizeof(char) * 1024);

        strcpy(act, "COMMAND");

        for (int i = 0; i < argc; i++)
        {
            strcat(act, " ");
            strcat(act, argv[i]);
        }

        writeToLog(act);
        free(act);
    }

    initializeSignals();

    inputFilehandler();

    while(wait(NULL)>0){
        continue;
    }
    
    if (getpid() == parentPid){
        printf("\n");
        if (arguments.output){
            printf("Data saved on file %s\n", arguments.output_file);
            close(arguments.outputDesciptor);
        }
        if (arguments.verbose){
            printf("Execution records saved on file %s\n", arguments.log_file_name);
            close(arguments.logDescriptor);
        }
    }
    

    return 0;
}
