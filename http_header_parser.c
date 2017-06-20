#include <stdio.h>
#include <string.h>
#include "debug.h"

// key is NULL at first line.
typedef void parse_line_cb(void* args, const char *key, const char *val);

int http_header_parse(parse_line_cb callback, void* args, char* payload, int payload_len){
    char *line_end = NULL;
    payload[payload_len]='\0';
    line_end = strstr(payload, "\r\n");
    if(line_end == NULL){
        IF_DEBUG(sprintf(last_error, "[error][http header]: bad format.\n"));
        return -1;
    }
    *line_end = '\0';
    // first line
    callback(args, NULL, payload);
    payload = line_end+2;
    while(payload_len > 0){
        char *kv_split;
        line_end = strstr(payload, "\r\n");
        if(line_end == payload){
            return 0; // end of header
        }
        *line_end = '\0';
        kv_split = strchr(payload, ':');
        if(kv_split == NULL){
            IF_DEBUG(sprintf(last_error, "[error][http header]: bad format in line.\n"));
            return -1;
        }
        *kv_split = '\0';
        callback(args, payload, kv_split+1);
        payload_len -= (line_end-payload)+2;
        payload = line_end+2;
    }
    IF_DEBUG(sprintf(last_error, "[error][http header]: not enough length or bad format.\n"));
    return -1;
}