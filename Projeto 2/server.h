#pragma once

#include "types.h"
#include <pthread.h>

/**
 * @brief Id and tid of a bank office
 */
typedef struct offices
{
    int id;
    pthread_t tid;
} offices_t; 

int findThreadId(pthread_t tid);
void assembleReply(tlv_reply_t reply, enum op_type type);
void operationHandler(tlv_request_t request, tlv_reply_t *reply);
void checkAccountBalance(req_header_t requestHeader, rep_value_t *rep_value);
void transferToAccount(req_value_t request, rep_value_t *reply);
void shutdownServer(rep_value_t *reply);
int accountIndex(uint32_t id);
float getBalance(uint32_t accountId);
int hasPermissions(int operation, uint32_t accountId);
int validateLogin(req_header_t rHeader);
void createAccount(req_value_t request, rep_value_t *reply);
void closeBankOffices();
void createBankOffices();
void *bankOffice();
int parseArguments(char *argv[]);
int invalidPassWord(char *argv[]);
void logAdmin(char *pass);
char *makeHash(char *password, char *salt);
char *makeSalt();
