#include "server.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "sope.h"
#include "types.h"

int num_bank_offices; //number of bank accounts of the server given when it's created
offices_t bank_offices[MAX_BANK_OFFICES+1]; //array of server's bank offices

int nextIdx = 0; //next free index in accounts array to be filled with the next created account
bank_account_t bank_accounts[MAX_BANK_ACCOUNTS]; //array of all bank accounts

int freeIndex = 0, firstIndex = 0;  //freeIndex - index of queue to write new requests; firstIndex - index of queue of the first request to proces
tlv_request_t messages_queue[MAX_BANK_OFFICES]; //array which is implemented as a queue that keeps requests waiting to be processed

int sLogDes; // server log file descriptor

pthread_mutex_t mutex_accounts[MAX_BANK_ACCOUNTS]; // mutex for each account
pthread_mutex_t thread_mutex_first = PTHREAD_MUTEX_INITIALIZER; //mutex consumidor
pthread_mutex_t thread_mutex_free = PTHREAD_MUTEX_INITIALIZER;  //mutex produtor

int serverToShutdown = 0; //1 if server got a request to shutdown, 0 otherwise
int threadsWorking = 0; //number of threads processing a request in an instance
pthread_mutex_t thread_working_mutex = PTHREAD_MUTEX_INITIALIZER; //mutex contador de número de threads ativas



int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Incorret number of arguments!\n");
        return 1;
    }

    signal(SIGINT, SIG_IGN); //Ignore Ctrl-C

    bank_offices[0].id = 0;
    bank_offices[0].tid = pthread_self();

    sLogDes = open(SERVER_LOGFILE, O_CREAT | O_WRONLY | O_APPEND | O_TRUNC, 0644);

    if (parseArguments(argv)) {
        return 1;
    }

    mkfifo(SERVER_FIFO_PATH, 0644);
    int sFifo = open(SERVER_FIFO_PATH, O_RDONLY | O_NONBLOCK);

    tlv_request_t user_request;

    for (int i = 0; i < MAX_BANK_ACCOUNTS; i++)
        pthread_mutex_init (&mutex_accounts[i], NULL);

    while (1) {
        if ((freeIndex + 1) % MAX_BANK_OFFICES == firstIndex)  // queue is FULL
            continue;

        int read_r = read(sFifo, &user_request, sizeof(tlv_request_t));

        if (read_r > 0) {
            logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_PRODUCER, user_request.value.header.account_id);
            pthread_mutex_lock(&thread_mutex_free); 
            messages_queue[freeIndex] = user_request;
            freeIndex = (freeIndex + 1) % MAX_BANK_OFFICES;
            logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_PRODUCER, user_request.value.header.account_id);
            pthread_mutex_unlock(&thread_mutex_free); 
            if (logRequest(sLogDes, 0, &user_request) < 0)
            {
                printf("ERROR: printing to log in function \"logRequest()\"\n");
                close(sFifo);
                unlink(SERVER_FIFO_PATH);
                exit(1);
            }
        } else if (serverToShutdown){
            break;
        }
    }

    close(sFifo);
    unlink(SERVER_FIFO_PATH);

    closeBankOffices();

    return 0;
}

int parseArguments(char *argv[]) {
    char *endptr;

    num_bank_offices = strtol(argv[1], &endptr, 10);

    if (*endptr != '\0' || endptr == argv[1]) {
        printf("Number of bank accounts must be a number..\n");
        return 1;
    }

    if (num_bank_offices <= 0 || num_bank_offices > MAX_BANK_ACCOUNTS) {
        printf("Number of bank accounts must be between 1 and %d..\n", MAX_BANK_ACCOUNTS);
        return 1;
    }

    createBankOffices();

    /// PASSWORD ///
    if (invalidPassWord(argv)) {
        return 1;
    }

    logAdmin(argv[2]);

    return 0;
}

int invalidPassWord(char *argv[]) {
    if (strchr(argv[2], ' ') != NULL) {
        printf("The password can't have blank spaces..\n");
        return 1;
    }

    if (strlen(argv[2]) < MIN_PASSWORD_LEN || strlen(argv[2]) > MAX_PASSWORD_LEN) {
        printf("The password must be between %d and %d characters.\n", MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
        return 1;
    }
    return 0;
}

void logAdmin(char *pass) {
    char hash[HASH_LEN];
    char salt[SALT_LEN];


    logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_ACCOUNT, 0);
    pthread_mutex_lock(&mutex_accounts[0]);

    logSyncDelay(sLogDes,findThreadId(pthread_self()),0,0);

    strcpy(salt, makeSalt());
    strcpy(bank_accounts[0].salt, salt);

    strcpy(hash, makeHash(pass, salt));
    strcpy(bank_accounts[0].hash, hash);

    bank_accounts[0].balance = 0;
    bank_accounts[0].account_id = 0;

    logAccountCreation (sLogDes, findThreadId(pthread_self()), &bank_accounts[0]);

    logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_ACCOUNT, 0);
    pthread_mutex_unlock(&mutex_accounts[0]);


    nextIdx++;
}

char *makeSalt() {
    char pool[16] = "0123456789abcdef";
    char *salt = malloc(SALT_LEN + 1);
    for (int i = 0; i < SALT_LEN + 1; i++) {
        salt[i] = pool[rand() % 16];
    }
    salt[SALT_LEN] = '\0';
    fflush(stdout);
    return salt;
}

char *makeHash(char *password, char *salt) {
    FILE *fpout;
    char *buffer = malloc(HASH_LEN + 1);
    char *sha256sum = malloc(sizeof("echo -n |sha256sum") + MAX_PASSWORD_LEN + SALT_LEN + 1);
    sprintf(sha256sum, "echo -n %s%s | sha256sum", password, salt);
    fpout = popen(sha256sum, "r");
    fgets(buffer, HASH_LEN, fpout);
    fflush(stdout);
    free(sha256sum);
    return buffer;
}

int validateLogin(req_header_t rHeader) {
    int index_acnt = accountIndex(rHeader.account_id);

    if (index_acnt == -1) {
        return 1;
    }
    pthread_mutex_lock(&mutex_accounts[index_acnt]);
    char *guess = malloc(HASH_LEN);
    strcpy(guess, makeHash(rHeader.password, bank_accounts[index_acnt].salt));

    if (strcmp(bank_accounts[index_acnt].hash, guess) == 0) {
        pthread_mutex_unlock(&mutex_accounts[index_acnt]);
        free(guess);
        return 0;
    } else {
        pthread_mutex_unlock(&mutex_accounts[index_acnt]);
        free(guess);
        return 1;
    }
}

void operationHandler(tlv_request_t request, tlv_reply_t *reply) {
    switch (request.type) {
        case OP_CREATE_ACCOUNT:
            if (hasPermissions(OP_CREATE_ACCOUNT, request.value.header.account_id))
                createAccount(request.value, &reply->value);
            else
                reply->value.header.ret_code = RC_OP_NALLOW;
            break;

        case OP_BALANCE:
            if (hasPermissions(OP_BALANCE, request.value.header.account_id)) {
                checkAccountBalance(request.value.header, &reply->value);
                reply->length += sizeof(reply->value.balance);
            } else
                reply->value.header.ret_code = RC_OP_NALLOW;
            break;

        case OP_TRANSFER:
            if (hasPermissions(OP_TRANSFER, request.value.header.account_id)) {
                transferToAccount(request.value, &reply->value);
                reply->length += sizeof(reply->value.transfer);
            } else
                reply->value.header.ret_code = RC_OP_NALLOW;
            break;

        case OP_SHUTDOWN:
            if (hasPermissions(OP_SHUTDOWN, request.value.header.account_id)) {
                usleep(request.value.header.op_delay_ms*1000);
                logDelay(sLogDes,findThreadId(pthread_self()),request.value.header.op_delay_ms);
                shutdownServer(&reply->value);
                reply->length += sizeof(reply->value.shutdown);  
            } else
                reply->value.header.ret_code = RC_OP_NALLOW;
            break;

        default:
            reply->value.header.ret_code = RC_OTHER;
            break;
    }
}

int hasPermissions(int operation, uint32_t accountId) {
    if (operation == OP_CREATE_ACCOUNT || operation == OP_SHUTDOWN) {
        if (accountId == 0) {
            return 1;
        }
    } else if (operation == OP_BALANCE || operation == OP_TRANSFER) {
        if (accountId != 0) {
            return 1;
        }
    }
    return 0;
}



void createAccount(req_value_t request, rep_value_t *reply) {
    if (accountIndex(request.create.account_id) >= 0) {
        reply->header.ret_code = RC_ID_IN_USE;
        return;
    }

    logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_ACCOUNT, request.create.account_id);
    pthread_mutex_lock(&mutex_accounts[nextIdx]);

    usleep(request.header.op_delay_ms*1000);
    logSyncDelay(sLogDes,findThreadId(pthread_self()),request.create.account_id,request.header.op_delay_ms);
    bank_accounts[nextIdx].account_id = request.create.account_id;
    bank_accounts[nextIdx].balance = request.create.balance;
    strcpy(bank_accounts[nextIdx].salt, makeSalt());
    strcpy(bank_accounts[nextIdx].hash, makeHash(request.create.password, bank_accounts[nextIdx].salt));

    logAccountCreation (sLogDes, findThreadId(pthread_self()), &bank_accounts[nextIdx]);

    logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_ACCOUNT, request.create.account_id);
    pthread_mutex_unlock(&mutex_accounts[nextIdx]);

    reply->header.ret_code = RC_OK;

    nextIdx++;
}

void checkAccountBalance(req_header_t requestHeader, rep_value_t *rep_value) {
    usleep(requestHeader.op_delay_ms* 1000);
    logSyncDelay(sLogDes, findThreadId(pthread_self()), requestHeader.account_id, requestHeader.op_delay_ms);

    rep_value->balance.balance = getBalance(requestHeader.account_id);
    rep_value->header.ret_code = RC_OK;    
}

void transferToAccount(req_value_t request, rep_value_t *reply) {
    int targetIndex = 0;
    int userIndex;

    userIndex = accountIndex(request.header.account_id);

    reply->transfer.balance = request.transfer.amount; // Amount to transfer between accounts

    if ((targetIndex = accountIndex(request.transfer.account_id)) == -1) {
        reply->header.ret_code = RC_ID_NOT_FOUND;
        return;
    }

    if (request.header.account_id == request.transfer.account_id) {
        reply->header.ret_code = RC_SAME_ID;
        return;
    }

    if (userIndex < targetIndex){
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_ACCOUNT, request.header.account_id);
        pthread_mutex_lock(&mutex_accounts[userIndex]);
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_CONSUMER, request.transfer.account_id);
        pthread_mutex_lock(&mutex_accounts[targetIndex]);
    } else {
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_CONSUMER, request.transfer.account_id);
        pthread_mutex_lock(&mutex_accounts[targetIndex]);
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_ACCOUNT, request.header.account_id);
        pthread_mutex_lock(&mutex_accounts[userIndex]);
    }
    

    if (bank_accounts[userIndex].balance < request.transfer.amount) {
        reply->header.ret_code = RC_NO_FUNDS;
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_ACCOUNT, request.header.account_id);
        pthread_mutex_unlock(&mutex_accounts[userIndex]);
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_CONSUMER, request.transfer.account_id);
        pthread_mutex_unlock(&mutex_accounts[targetIndex]);
        return;
    }

    if (bank_accounts[targetIndex].balance + request.transfer.amount > MAX_BALANCE) {
        reply->header.ret_code = RC_TOO_HIGH;
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_ACCOUNT, request.header.account_id);
        pthread_mutex_unlock(&mutex_accounts[userIndex]);
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_CONSUMER, request.transfer.account_id);
        pthread_mutex_unlock(&mutex_accounts[targetIndex]);
        return;
    }

    if (targetIndex == 0) {
        reply->header.ret_code = RC_OTHER;
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_ACCOUNT, request.header.account_id);
        pthread_mutex_unlock(&mutex_accounts[userIndex]);
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_CONSUMER, request.transfer.account_id);
        pthread_mutex_unlock(&mutex_accounts[targetIndex]);
        return;
    }

    // Tranfering
    usleep(request.header.op_delay_ms*1000);
    logSyncDelay(sLogDes, findThreadId(pthread_self()), request.header.account_id, request.header.op_delay_ms);
    bank_accounts[targetIndex].balance = bank_accounts[targetIndex].balance + request.transfer.amount;
    usleep(request.header.op_delay_ms*1000);
    logSyncDelay(sLogDes, findThreadId(pthread_self()), request.header.account_id, request.header.op_delay_ms);
    bank_accounts[userIndex].balance = bank_accounts[userIndex].balance - request.transfer.amount;

    reply->transfer.balance = bank_accounts[userIndex].balance;
    reply->header.ret_code = RC_OK;

    logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_ACCOUNT, request.header.account_id);
    pthread_mutex_unlock(&mutex_accounts[userIndex]);
    logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_CONSUMER, request.transfer.account_id);
    pthread_mutex_unlock(&mutex_accounts[targetIndex]);
}

void shutdownServer(rep_value_t *reply){

    if (chmod(SERVER_FIFO_PATH, 0444)){
        reply->shutdown.active_offices = 0;
        reply->header.ret_code = RC_OTHER;
    } else {
        reply->header.ret_code = RC_OK;
        pthread_mutex_lock(&thread_working_mutex);
        reply->shutdown.active_offices = threadsWorking - 1; //excluding the current thread that is doing shutdown operation
        pthread_mutex_unlock(&thread_working_mutex);
        serverToShutdown = 1;
    }    
}

int accountIndex(uint32_t id) {
    for (int i = 0; i < nextIdx; i++) {
        if (bank_accounts[i].account_id == id) {
            return i;  //true
        }
    }
    return -1;  // false;
}

float getBalance(uint32_t accountId) {
    for (int i = 0; i < MAX_BANK_ACCOUNTS; i++) {
        if (bank_accounts[i].account_id == accountId) {
            return bank_accounts[i].balance;  //true
        }
    }
    return -1;  //false
}

void createBankOffices() {
    int rc;
    for (int t = 1; t <= num_bank_offices; t++) {
        bank_offices[t].id = t;
        rc = pthread_create(&(bank_offices[t].tid), NULL, bankOffice,NULL);

        if (rc) {
            printf("ERROR: return code from pthread_create is: %d\n", rc);
            exit(1);
        }

        int res = logBankOfficeOpen(sLogDes, t + 1, bank_offices[t].tid);
        if (res < 0)        {
            printf("ERROR: printing to log in function \"logBankOfficeOpen()\"\n");
            exit(1);
        }
    }
}

int findThreadId(pthread_t tid)
{
    for (int i = 0; i <= num_bank_offices; i++)
    {
        if(tid == bank_offices[i].tid)
        {
            return bank_offices[i].id;
        }
    }
    return -1;
}

void *bankOffice() {
    while ( 1 ) {
        logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_LOCK, SYNC_ROLE_CONSUMER, 0);
        pthread_mutex_lock(&thread_mutex_first);  // Lock a todas as threads, apartir de aqui 
                                            // so existe uma thread a executar o codigo a frente
        int stop = 0;
        tlv_reply_t srv_reply;

        //initialize reply
        srv_reply.value.balance.balance = 0;
        srv_reply.value.shutdown.active_offices = 0;
        srv_reply.value.transfer.balance = 0;

        while (!stop){  // enquanto esta thread nao ler uma mensagem
            if (firstIndex != freeIndex) {  //queue not empty
                pthread_mutex_lock(&thread_working_mutex);
                threadsWorking += 1;
                pthread_mutex_unlock(&thread_working_mutex);
                tlv_request_t user_request = messages_queue[firstIndex];
                firstIndex = (firstIndex + 1) % MAX_BANK_OFFICES;
                stop = 1;  // esta thread ja leu uma mensagem ja pode parar com este loop
                logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_CONSUMER, user_request.value.header.pid);
                pthread_mutex_unlock(&thread_mutex_first);  // ja temos a mensagem a processar, outra thread pode esperar por mensagens
                srv_reply.type = user_request.type;
                srv_reply.value.header.account_id = user_request.value.header.account_id;
                srv_reply.length = sizeof(srv_reply.value.header);

                if (validateLogin(user_request.value.header)) {
                    srv_reply.value.header.ret_code = RC_LOGIN_FAIL;
                } else {
                    operationHandler(user_request, &srv_reply);
                }

                char *uFifoPath = malloc(USER_FIFO_PATH_LEN);
                sprintf(uFifoPath, USER_FIFO_PATH_PREFIX);
                sprintf(uFifoPath, "%d", user_request.value.header.pid);

                int uFifo = open(uFifoPath, O_WRONLY | O_NONBLOCK);
                int write_r;
                if (uFifo != -1) {
                    do {
                        write_r = write(uFifo, &srv_reply, sizeof(srv_reply));
                    } while (write_r == -1 && errno == EAGAIN);

                    close(uFifo);
                }

                if (uFifo == -1 || write_r == -1) {
                    srv_reply.value.header.ret_code = RC_USR_DOWN;
                }
                

                free(uFifoPath);
                pthread_mutex_lock(&thread_working_mutex);
                threadsWorking -= 1;
                pthread_mutex_unlock(&thread_working_mutex);
            } else if (serverToShutdown){
                logSyncMech(sLogDes, findThreadId(pthread_self()), SYNC_OP_MUTEX_UNLOCK, SYNC_ROLE_CONSUMER, 0);
                pthread_mutex_unlock(&thread_mutex_first);
                return NULL;
            }
        }
        if (logReply(sLogDes, findThreadId(pthread_self()), &srv_reply) < 0)
        {
            printf("ERROR: printing to log in function \"logReply()\"\n");
        }
    }
    return NULL;
}

void closeBankOffices() {
    for (int t = 1; t <= num_bank_offices; t++) {
        pthread_join(bank_offices[t].tid, NULL);
        int res = logBankOfficeClose(sLogDes, t, bank_offices[t].tid);
        if (res < 0)
        {
            printf("ERROR: printing to log in function \"logBankOfficeClose()\"\n");
            return;
        }
    }
}
