#pragma once

#include "types.h"

int ufifo_bkup; //fifo descriptor to use in alarm handler
int ulog_des_bkup; //user log file descriptor to use in alarm handler
char* ufifopath_bkup; //user fifo path to use in alarm handler
tlv_reply_t reply_bkup; //reply struct to use in alarm handler


int fillRequestTLV(char *argv[], tlv_request_t *tlvRequest);
int transferOperation(uint32_t *leng, req_value_t *reqValue, char *argv[], char *endptr);
int createAccountOperation(uint32_t *leng, req_value_t *reqValue, char *argv[], char *endptr);
int invalidOperation(enum op_type op, char *argv[], char *endptr);
int invalidDelay(long delay, char *argv[], char *endptr);
int invalidPassWord(char *argv[]);
int invalidAccountId(long id, char *argv[], char *endptr);
void cleanup();
void timeoutHandler();
void setBackUpReplyValues(tlv_request_t *tlvRequest);
