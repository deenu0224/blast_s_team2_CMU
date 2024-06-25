#ifndef USER_AUTHENTICATION_H
#define USER_AUTHENTICATION_H

#include <iostream>
#include <vector>
#include <cstring>

typedef struct
{
    char            UserId[32]; // sha256 of name
    char            Name[32];   // user name
    unsigned long   Timestamp;  // Enroll time
    unsigned int    Privilege;  // 0 : user 1: admin, default = 0
} __attribute__((packed)) UserInfo;

typedef struct
{
    UserInfo        User;
    char            Password[32];
    char            Signature[32];   // HMAC of (USER + Password)
} __attribute__((packed)) UserHandle;

typedef struct
{
    char            UserId[32]; // sha256 of name
    unsigned char   Iv[16];     // random value
    unsigned int    EncryptedDataLen;
    char*           EncryptedData;
}  __attribute__((packed)) StoredUserInfo;

typedef struct
{
    int             AuthType;   // Authenticated : 1, Authendticated, but Expired : 2
    int             Challenge[32]; // randum value to prevent reply attack
    unsigned long   Timestamp;  // issue time
    char            UserId[32];  // sha256 of name
    unsigned int    Privilege;  // 0 : user 1: admin, default = 0          
} __attribute__((packed)) TokenInfo;

typedef struct
{
    char            UserId[32]; // sha256 of name
    unsigned int    FailCount;  // fail count, default = 0
    unsigned long   Throttle;  // start throttling timestamp
    unsigned int    Privilege;  // 0 : user 1: admin, default = 0
} __attribute__((packed)) FailInfo;

typedef struct
{
    FailInfo        UserFailInfo; // sha256 of name
    char            Signature[32];   // HMAC of FailInfo
} __attribute__((packed)) FailHandle;

typedef struct
{
    char            UserId[32]; // sha256 of name
    unsigned char   Iv[16];     // random value
    unsigned int    EncryptedDataLen;
    char*           EncryptedData;
}  __attribute__((packed)) StoredFailInfo;

void initialize_keys();
int ResetToken(const std::vector<unsigned char>& token);
int GlobalResetToken();
int TokenVerifier(const std::vector<unsigned char>& token);
int EnrollPwd(const char* username, const char* password);
int VerifyPwd(const char* username, const char* password, std::vector<unsigned char>& token, FailInfo& fail_info);
int ChangePwd(const char* username, const char* password, const std::vector<unsigned char>& token);

#endif