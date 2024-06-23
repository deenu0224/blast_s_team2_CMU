//------------------------------------------------------------------------------------------------
//Include
//------------------------------------------------------------------------------------------------
#ifndef MessageH
#define MessageH

#define MT_COMMANDS              1
#define MT_TARGET_SEQUENCE       2
#define MT_IMAGE                 3
#define MT_TEXT                  4
#define MT_PREARM                5
#define MT_STATE                 6
#define MT_STATE_CHANGE_REQ      7
#define MT_CALIB_COMMANDS        8
#define MT_LOGIN_ENROLL_REQ      9
#define MT_LOGIN_VERITY_REQ     10
#define MT_LOGIN_CHANGEPW_REQ   11
#define MT_LOGIN_ENROLL_RES     12
#define MT_LOGIN_VERITY_RES     13
#define MT_LOGIN_CHANGEPW_RES   14

#define PAN_LEFT_START  0x01
#define PAN_RIGHT_START 0x02
#define PAN_UP_START    0x04
#define PAN_DOWN_START  0x08
#define FIRE_START      0x10
#define PAN_LEFT_STOP   0xFE
#define PAN_RIGHT_STOP  0xFD
#define PAN_UP_STOP     0xFB
#define PAN_DOWN_STOP   0xF7
#define FIRE_STOP       0xEF

#define DEC_X           0x01
#define INC_X           0x02
#define DEC_Y           0x04
#define INC_Y           0x08

enum SystemState_t : unsigned int
{
    UNKNOWN      = 0,
    SAFE         = 0x1,
    PREARMED     = 0x2,
    ENGAGE_AUTO  = 0x4,
    ARMED_MANUAL = 0x8,
    ARMED        = 0x10,
    FIRING       = 0x20,
    LASER_ON     = 0x40,
    CALIB_ON     = 0x80 
};

enum LogInState_t : unsigned int
{
    SUCCESS             = 0x0,
    NOT_EXIST_USER      = 0x1,
    INVALID_PASSWORD    = 0x2,
    EXIST_USER          = 0x3,
    EXPIRE_PASSWORD     = 0x4,
    INVALID_TOKEN       = 0x5,
    INVALID_OPERATION   = 0x6,
    INVALID_MSG         = 0x7,
    AUTH_THROTTLED      = 0x8,
    NO_PERMISSION       = 0x9,
};

#define CLEAR_LASER_MASK    (~LASER_ON)
#define CLEAR_FIRING_MASK   (~FIRING)
#define CLEAR_ARMED_MASK    (~ARMED)
#define CLEAR_CALIB_MASK    (~CALIB_ON)
#define CLEAR_LASER_FIRING_ARMED_CALIB_MASK  (~(LASER_ON|FIRING|ARMED|CALIB_ON))

typedef struct
{
    unsigned int Len;
    unsigned int Type;
    char         HMAC[32];
} TMesssageHeader;

typedef struct
{
    TMesssageHeader Hdr;
    unsigned char  Commands;
} TMesssageCommands;

typedef struct
{
    TMesssageHeader Hdr;
    char  FiringOrder[11];
} TMesssageTargetOrder;

typedef struct
{
    TMesssageHeader Hdr;
    char   Text[1];
} TMesssageText;

typedef struct
{
    TMesssageHeader Hdr;
    unsigned char   Image[1];
} TMesssageImage;

typedef struct
{
    TMesssageHeader Hdr;
    char   Code[10];
} TMesssagePreArm;

typedef struct
{
    TMesssageHeader Hdr;
    SystemState_t   State;
} TMesssageSystemState;

typedef struct
{
    TMesssageHeader Hdr;
    SystemState_t   State;
} TMesssageChangeStateRequest;

typedef struct
{
    TMesssageHeader Hdr;
    unsigned char  Commands;
} TMesssageCalibCommands;

typedef struct
{
    TMesssageHeader Hdr;
    char    Name[32];
    char    Password[32];
} TMesssageLoginEnrollRequest;

typedef struct
{
    TMesssageHeader Hdr;
    char    Name[32];
    char    Password[32];
} TMesssageLoginVerifyRequest;

typedef struct
{
    TMesssageHeader Hdr;
    char    Name[32];
    char    Password[32];
    char    Token[32];
} TMesssageLoginChangePwRequest;

typedef struct
{
    TMesssageHeader Hdr;
    unsigned int  LoginState;
} TMesssageLoginEnrollResponse;

typedef struct
{
    TMesssageHeader Hdr;
    unsigned int  LoginState;
    unsigned int    FailCount;
    unsigned long   Throttle;
    unsigned int    Privilege;
    char            Token[32];
} TMesssageLoginVerifyResponse;

typedef struct
{
    TMesssageHeader Hdr;
    unsigned int  LoginState;
} TMesssageLoginChangePwResponse;

#endif
//------------------------------------------------------------------------------------------------
//END of Include
//------------------------------------------------------------------------------------------------

