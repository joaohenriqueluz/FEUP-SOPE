#include "user.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "sope.h"

int invalidAccountId(long id, char *argv[], char *endptr)
{
    if (*endptr != '\0' || endptr == argv[1])
    {
        printf("Account ID must be a number..\n");
        return 1;
    }

    if (id >= MAX_BANK_ACCOUNTS)
    {
        printf("Account account ID invalid! Must be a value between 0 and %d.\n", MAX_BANK_ACCOUNTS - 1);
        return 1;
    }
    return 0;
}

int invalidPassWord(char *argv[])
{
    if (strchr(argv[2], ' ') != NULL)
    {
        printf("The password can't have blanck spaces..\n");
        return 1;
    }

    if (strlen(argv[2]) < MIN_PASSWORD_LEN || strlen(argv[2]) > MAX_PASSWORD_LEN)
    {
        printf("The password must be between %d and %d characters.\n", MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
        return 1;
    }
    return 0;
}

int invalidDelay(long delay, char *argv[], char *endptr)
{
    if (*endptr != '\0' || endptr == argv[3])
    {
        printf("Operation delay must be a number..\n");
        return 1;
    }

    if (delay < 1 || delay > MAX_OP_DELAY_MS)
    {
        printf("Delay invalid! Must be a value between 1 and %d.\n", MAX_OP_DELAY_MS);
        return 1;
    }

    return 0;
}

int invalidOperation(enum op_type op, char *argv[], char *endptr)
{
    if (*endptr != '\0' || endptr == argv[4])
    {
        printf("Operation must be a number..\n");
        return 1;
    }

    if (op < 0 || op > 3)
    {
        printf("Operation not valid! It must be between 0 and 3.\n");
        return 1;
    }

    return 0;
}

int createAccountOperation(uint32_t *leng, req_value_t *reqValue, char *argv[], char *endptr)
{
    char *ttemp = malloc(MAX_BANK_ACCOUNTS + 1 + MAX_BALANCE + 1 + MAX_PASSWORD_LEN + 1);
    strcpy(ttemp, argv[5]);

    req_create_account_t create;

    // Account ID
    char *argument = strtok(ttemp, " ");

    if (argument == NULL)
    {
        printf("Create account operation needs 3 arguments..\n");
        return 1;
    }

    create.account_id = strtol(argument, &endptr, 10);

    if (*endptr != '\0' || endptr == argument)
    {
        printf("Account ID for create account operation must be a number..\n");
        return 1;
    }

    if (create.account_id < 1 || create.account_id >= MAX_BANK_ACCOUNTS)
    {
        printf("Account account ID invalid! Must be a value between 1 and %d.\n", MAX_BANK_ACCOUNTS - 1);
        return 1;
    }

    // Balance
    argument = strtok(NULL, " ");

    if (argument == NULL)
    {
        printf("Create account operation needs 3 arguments..\n");
        return 1;
    }

    create.balance = strtol(argument, &endptr, 10);

    if (*endptr != '\0' || endptr == argument)
    {
        printf("Balance must be a number..\n");
        return 1;
    }

    if (create.balance < MIN_BALANCE || create.balance > MAX_BALANCE)
    {
        printf("Balance invalid! Must be a value between %ld and %ld.\n", MIN_BALANCE, MAX_BALANCE);
        return 1;
    }

    // Password
    argument = strtok(NULL, " ");

    if (argument == NULL)
    {
        printf("Create account operation needs 3 arguments..\n");
        return 1;
    }

    if (strlen(argument) < MIN_PASSWORD_LEN || strlen(argument) > MAX_PASSWORD_LEN)
    {
        printf("The password must be between %d and %d characters.\n Your password was %s", MIN_PASSWORD_LEN, MAX_PASSWORD_LEN, argument);
        return 1;
    }

    strcpy(create.password, argument);

    // No more arguments
    if (strtok(NULL, " ") != NULL)
    {
        printf("Create account operation needs only 3 arguments..\n");
        return 1;
    }

    // Final data about create account operation
    (*reqValue).create = create;
    *leng += sizeof((*reqValue).create);

    free(ttemp);

    return 0;
}

int transferOperation(uint32_t *leng, req_value_t *reqValue, char *argv[], char *endptr)
{
    char *ttemp = malloc(MAX_BANK_ACCOUNTS + 1 + MAX_BALANCE + 1);
    strcpy(ttemp, argv[5]);

    req_transfer_t transfer;

    // Account ID
    char *argument = strtok(ttemp, " ");

    if (argument == NULL)
    {
        printf("Transfer operation needs 2 arguments..\n");
        return 1;
    }

    transfer.account_id = strtol(argument, &endptr, 10);

    if (*endptr != '\0' || endptr == argument)
    {
        printf("Account ID for transfer operation must be a number..\n");
        return 1;
    }

    if (transfer.account_id < 1 || transfer.account_id >= MAX_BANK_ACCOUNTS)
    {
        printf("Destination account ID invalid! Must be a value between 1 and %d.\n", MAX_BANK_ACCOUNTS - 1);
        return 1;
    }

    // Amount
    argument = strtok(NULL, " ");

    if (argument == NULL)
    {
        printf("Transfer operation needs 2 arguments..\n");
        return 1;
    }

    transfer.amount = strtol(argument, &endptr, 10);

    if (*endptr != '\0' || endptr == argument)
    {
        printf("Amount for transfer operation must be a number..\n");
        return 1;
    }

    if (transfer.amount < 1 || transfer.amount >= MAX_BALANCE)
    {
        printf("Ammount to tranfer invalid! Must be a value between 1 and %ld.\n", MAX_BALANCE);
        return 1;
    }

    // No more arguments
    if (strtok(NULL, " ") != NULL)
    {
        printf("Transfer operation needs only 2 arguments..\n");
        return 1;
    }

    // Final data about transfer operation
    (*reqValue).transfer = transfer;
    *leng += sizeof((*reqValue).transfer);

    free(ttemp);
    return 0;
}

int fillRequestTLV(char *argv[], tlv_request_t *tlvRequest)
{
    char *endptr;      //used to check if some arguments are numbers
    uint32_t leng = 0; //length of union of transfer and create structs

    req_value_t reqValue;
    req_header_t header;

    /// HEADER ///
    header.pid = getpid();

    ///// ACCOUNT ID /////
    header.account_id = strtol(argv[1], &endptr, 10);

    if (invalidAccountId(header.account_id, argv, endptr))
        return 1;

    ///// PASSWORD /////
    if (invalidPassWord(argv))
        return 1;
    else
        strcpy(header.password, argv[2]);

    ///// DELAY /////

    header.op_delay_ms = strtol(argv[3], &endptr, 10);

    if (invalidDelay(header.op_delay_ms, argv, endptr))
        return 1;

    reqValue.header = header;

    /// END OF HEADER ///

    ///// TYPE OF OPERATION /////
    (*tlvRequest).type = strtol(argv[4], &endptr, 10);

    if (invalidOperation((*tlvRequest).type, argv, endptr))
        return 1;

    ///// OPERATION ARGUMENTS /////

    /// Create account operation ///
    if ((*tlvRequest).type == 0)
    {
        if (createAccountOperation(&leng, &reqValue, argv, endptr))
        {
            return 1;
        }
    }

    /// Tranfer operation ///
    else if ((*tlvRequest).type == 2)
    {
        if (transferOperation(&leng, &reqValue, argv, endptr))
        {
            return 1;
        }
    }

    /// Other operation types ///
    else
    {
        char *ttemp = malloc(20);
        strcpy(ttemp, argv[5]);

        if (strtok(ttemp, " ") != NULL)
        {
            printf("This type of operation doesn't need any arguments..\n");
            return 1;
        }

        free(ttemp);
    }

    (*tlvRequest).value = reqValue;
    (*tlvRequest).length = sizeof(header) + leng;

    return 0;
}

void timeoutHandler(){
    reply_bkup.value.header.ret_code= RC_SRV_TIMEOUT;
    logReply(ulog_des_bkup,getpid(),&reply_bkup);
    cleanup();
    exit(0);
}

void cleanup(){
    close (ufifo_bkup);
    unlink(ufifopath_bkup);
    close(ulog_des_bkup);

    free(ufifopath_bkup);
}

void setBackUpReplyValues(tlv_request_t* tlvRequest){
    reply_bkup.type = tlvRequest->type;
    reply_bkup.value.header.account_id = tlvRequest->value.header.account_id;
    reply_bkup.value.header.ret_code = RC_OTHER;
    reply_bkup.value.balance.balance = 0;
    reply_bkup.value.shutdown.active_offices = 0;
    reply_bkup.value.transfer.balance = 0;
    reply_bkup.length = sizeof(reply_bkup.value.header);

}

int main(int argc, char *argv[])
{    
    if (argc != 6)
    {
        printf("Incorret number of arguments!\n Usage: %s accountID password delay op{0,1,2,3} argList\n\n", argv[0]);
        return 1;
    }

    signal(SIGINT, SIG_IGN); //Ignore Ctrl-C
    signal(SIGALRM, timeoutHandler);

    //Open ulog.txt
    int ulog_des = open(USER_LOGFILE, O_CREAT | O_WRONLY | O_APPEND | O_TRUNC, 0644); //Opens log file with descripter ulog_des
    ulog_des_bkup = ulog_des;

    tlv_request_t tlvRequest;
    tlv_reply_t reply;
    

    if (fillRequestTLV(argv, &tlvRequest))
        return 1;

    int sfifo = open(SERVER_FIFO_PATH, O_WRONLY | O_NONBLOCK);
    int write_r;

    if (sfifo != -1)
    {
        do
        {
            write_r = write(sfifo, &tlvRequest, sizeof(tlvRequest));
        } while (write_r == -1 && errno == EAGAIN);

        close(sfifo);
    }

    setBackUpReplyValues(&tlvRequest);

    if (logRequest(ulog_des, getpid(), &tlvRequest) <= 0)
    {
        printf("Error writing request to ulog.txt");
        return 1;
    }

    if (sfifo == -1 || write_r == -1)
    {
        reply.type = tlvRequest.type;
        reply.value.header.account_id = tlvRequest.value.header.account_id;
        reply.value.header.ret_code = RC_SRV_DOWN;
        reply.length = sizeof(reply.value.header);
        reply.value.balance.balance = 0;
        reply.value.shutdown.active_offices = 0;
        reply.value.transfer.balance = 0;

        if (logReply(ulog_des, getpid(), &reply) <= 0)
        {
            printf("Error writing reply to ulog.txt");
            return 1;
        }
        return 0;
    }

    // Name of user FIFO
    char *uFifoPath = malloc(USER_FIFO_PATH_LEN);
    sprintf(uFifoPath, USER_FIFO_PATH_PREFIX);
    sprintf(uFifoPath, "%d", getpid());
    
    ufifopath_bkup = malloc(USER_FIFO_PATH_LEN);
    strcpy(ufifopath_bkup,uFifoPath);
    mkfifo(uFifoPath, 0644);

    int ufifo = open(uFifoPath, O_RDONLY | O_NONBLOCK);
    ufifo_bkup = ufifo;
    int read_r;
    alarm(FIFO_TIMEOUT_SECS);

    do
    {
        read_r = read(ufifo, &reply, sizeof(reply));
        
    } while (read_r == 0 || (read_r == -1 && errno == EAGAIN));

    if (logReply(ulog_des, getpid(), &reply) <= 0)
    {
        printf("Error writing reply to ulog.txt");
        cleanup();
        return 1;
    }

    free (uFifoPath);
    cleanup();

    return 0;
}
