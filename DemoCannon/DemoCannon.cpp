
//------------------------------------------------------------------------------------------------
// File: Cannon.cpp
// Project: LG Exec Ed Program
// Versions:
// 1.0 April 2024 - initial version
//------------------------------------------------------------------------------------------------
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <math.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <sys/select.h>
#include "NetworkTCP.h"
#include "TcpSendRecvJpeg.h"
#include "Message.h"
#include "KeyboardSetup.h"
#include "IsRPI.h"
#include <lccv.hpp>
#include "ServoPi.h"
#include "ObjectDetector.h"
#include "lgpio.h"
#include "CvImageMatch.h"
#include "ssd1306.h"

//KO ADD
#include "Crypto.h"
#include "UserAuthentication.h"

//#define USE_TFLITE      1 
#define USE_IMAGE_MATCH 1

#define PORT            5000
#define PAN_SERVO       1
#define TILT_SERVO      2
#define MIN_TILT         (-15.0f)
#define MAX_TILT         ( 15.0f)
#define MIN_PAN          (-15.0f)
#define MAX_PAN          ( 15.0f)


#define WIDTH           1920
#define HEIGHT          1080

#define INC             0.5f

#define USE_USB_WEB_CAM 0

using namespace cv;
using namespace std;


typedef enum
{
 NOT_ACTIVE,
 ACTIVATE,
 NEW_TARGET,
 LOOKING_FOR_TARGET,
 TRACKING,
 TRACKING_STABLE,
 ENGAGEMENT_IN_PROGRESS,
 ENGAGEMENT_COMPLETE
} TEngagementState;


typedef struct
{
 int                       NumberOfTartgets;
 int                       FiringOrder[10];
 int                       CurrentIndex;
 bool                      HaveFiringOrder;
 volatile TEngagementState State;
 int                       StableCount;
 float                     LastPan;
 float                     LastTilt;   
 int                       Target;
} TAutoEngage;


static TAutoEngage            AutoEngage;
static float                  Pan=0.0f;
static float                  Tilt=0.0f;
static unsigned char          RunCmds=0;
static int                    gpioid;
static uint8_t                i2c_node_address = 1;
static bool                   HaveOLED=false;
static int                    OLED_Font=0;
static pthread_t              NetworkThreadID=-1;
static pthread_t              EngagementThreadID=-1;
static volatile SystemState_t SystemState= UNKNOWN;
static pthread_mutex_t        TCP_Mutex;
static pthread_mutex_t        GPIO_Mutex;
static pthread_mutex_t        I2C_Mutex;
static pthread_mutex_t        Engmnt_Mutex;
static pthread_mutexattr_t    TCP_MutexAttr;
static pthread_mutexattr_t    GPIO_MutexAttr;
static pthread_mutexattr_t    I2C_MutexAttr;
static pthread_mutexattr_t    Engmnt_MutexAttr;
static pthread_cond_t         Engagement_cv;
static float                  xCorrect=60.0,yCorrect=-90.0;
static volatile bool          isConnected=false;
static Servo                  *Servos=NULL;
static volatile unsigned long long RecvSeqNum = 0;
static volatile unsigned long long SendSeqNum = 0;


#if USE_USB_WEB_CAM
cv::VideoCapture       * capture=NULL;
#else
static lccv::PiCamera  * capture=NULL;
#endif


static Mat NoDataAvalable;

static TTcpListenPort    *TcpListenPort=NULL;
static TTcpConnectedPort *TcpConnectedPort=NULL;

static void   Setup_Control_C_Signal_Handler_And_Keyboard_No_Enter(void);
static void   CleanUp(void);
static void   Control_C_Handler(int s);
static void   HandleInputChar(Mat &image);
static void * NetworkInputThread(void *data);
static void * EngagementThread(void *data); 
static int    PrintfSend(const char *fmt, ...); 
static bool   GetFrame( Mat &frame);
static void   CreateNoDataAvalable(void);
static int    SendSystemState(SystemState_t State);
static bool   compare_float(float x, float y, float epsilon = 0.5f);
static void   ServoAngle(int Num,float &Angle) ;

std::mutex log_mutex;

static void AuditLog(const char* message)
{
  std::lock_guard<std::mutex> lock(log_mutex);
  std::ofstream log_file("audit_log.txt", std::ios_base::app);
  if (!log_file.is_open()) {
      std::cerr << "Failed to open audit log file." << std::endl;
      return;
  }
  std::time_t time = std::time({});
  char timeString[std::size("yyyy-mm-ddThh:mm:ssZ")];
  std::strftime(std::data(timeString), std::size(timeString),
                "%FT%TZ", std::gmtime(&time));
  log_file << "[" << timeString << "][" << TcpConnectedPort->ClientIp << "] : " << message  << std::endl;
  log_file.close();
}
/*************************************** TF LITE START ********************************************************/ 
#if USE_TFLITE && !USE_IMAGE_MATCH
static ObjectDetector *detector;
/*************************************** TF LITE END   ********************************************************/ 
#elif USE_IMAGE_MATCH && !USE_TFLITE
/*************************************** IMAGE_MATCH START *****************************************************/ 


/*************************************** IMAGE_MATCH END *****************************************************/ 
#endif

uint64_t GetSendSeqNum(void)
{
	if(SendSeqNum > 0x0FFFFFFFFFFFFFFF)
		SendSeqNum = 0;
	return ++SendSeqNum;
}

//------------------------------------------------------------------------------------------------
// static void ReadOffsets
//------------------------------------------------------------------------------------------------
static void ReadOffsets(void)
{
   FILE * fp;
   float x=0.0f,y=0.0f;
   char xs[100]={0},ys[100]={0};
   int retval=0;
   
   fp = fopen ("Correct.ini", "r");
   if (fp==NULL)
   {
    printf("Error opening file 'Correct.ini': %s\n", strerror(errno));
    return;
   }
   retval+=fscanf(fp, "%99s %f", xs,&x);
   retval+=fscanf(fp, "%99s %f", ys,&y);
   if (retval==4)
   {
    if ((strcmp(xs,"xCorrect")==0) && (strcmp(ys,"yCorrect")==0))
       {
         xCorrect=x;
         yCorrect=y;
         printf("Read Offsets:\n");
         printf("xCorrect= %f\n",xCorrect);
         printf("yCorrect= %f\n",yCorrect);
       }
   }
   fclose(fp);

}
//------------------------------------------------------------------------------------------------
// END  static void readOffsets
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void readOffsets
//------------------------------------------------------------------------------------------------
static void WriteOffsets(void)
{
   FILE * fp;

   fp = fopen ("Correct.ini", "w+");
   if (fp==NULL)
   {
    printf("Error opening file 'Correct.ini': %s\n", strerror(errno));
    return;
   }
   rewind(fp);
   fprintf(fp,"xCorrect %f\n", xCorrect);
   fprintf(fp,"yCorrect %f\n", yCorrect);
      
   printf("Wrote Offsets:\n");
   printf("xCorrect= %f\n",xCorrect);
   printf("yCorrect= %f\n",yCorrect);
   fclose(fp);

}
//------------------------------------------------------------------------------------------------
// END  static void readOffsets
//------------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------------
// static bool compare_float
//------------------------------------------------------------------------------------------------
static bool compare_float(float x, float y, float epsilon)
{
   if(fabs(x - y) < epsilon)
      return true; //they are same
      return false; //they are not same
}
//------------------------------------------------------------------------------------------------
// END static bool compare_float
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void ServoAngle
//------------------------------------------------------------------------------------------------
static void ServoAngle(int Num,float &Angle)     
{
  pthread_mutex_lock(&I2C_Mutex);
  if (Num==TILT_SERVO)
   {
     if (Angle< MIN_TILT) Angle=MIN_TILT; 
     else if (Angle > MAX_TILT) Angle=MAX_TILT; 
   }
  else if (Num==PAN_SERVO)
   {
    if (Angle< MIN_PAN) Angle = MIN_PAN;
    else if (Angle > MAX_PAN) Angle=MAX_PAN;
   }
  if (Servos!=NULL)
  {
    Servos->angle(Num,Angle);
  }
  else
  {
    printf("Servo is not opened!\n");
  }
  pthread_mutex_unlock(&I2C_Mutex);
} 
//------------------------------------------------------------------------------------------------
// END static void ServoAngle
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void fire
//------------------------------------------------------------------------------------------------
static void fire(bool value)
{
 pthread_mutex_lock(&GPIO_Mutex);
 if (value && !(SystemState & (UNKNOWN|SAFE|PREARMED))) {
   SystemState=(SystemState_t)(SystemState|FIRING);
 } else {
   SystemState=(SystemState_t)(SystemState & CLEAR_FIRING_MASK);
   value=false;
 }
 lgGpioWrite(gpioid,17,value);
 pthread_mutex_unlock(&GPIO_Mutex);
}
//------------------------------------------------------------------------------------------------
// END static void fire
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void armed
//------------------------------------------------------------------------------------------------
static void armed(bool value)
{
  pthread_mutex_lock(&GPIO_Mutex);
  if (value) SystemState=(SystemState_t)(SystemState | ARMED);
  else SystemState=(SystemState_t)(SystemState & CLEAR_ARMED_MASK);
  pthread_mutex_unlock(&GPIO_Mutex);
}
//------------------------------------------------------------------------------------------------
// END static void armed
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void calibrate
//------------------------------------------------------------------------------------------------
static void calibrate(bool value)
{
  pthread_mutex_lock(&GPIO_Mutex);
  if (value) SystemState=(SystemState_t)(SystemState|CALIB_ON);
  else SystemState=(SystemState_t)(SystemState & CLEAR_CALIB_MASK);
  pthread_mutex_unlock(&GPIO_Mutex);
}
//------------------------------------------------------------------------------------------------
// END static void calibrate
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void laser
//------------------------------------------------------------------------------------------------
static void laser(bool value)
{
  pthread_mutex_lock(&GPIO_Mutex);
  if (value) SystemState=(SystemState_t)(SystemState|LASER_ON);
  else SystemState=(SystemState_t)(SystemState & CLEAR_LASER_MASK);
  lgGpioWrite(gpioid,18,value);
  pthread_mutex_unlock(&GPIO_Mutex);
}
//------------------------------------------------------------------------------------------------
// END static void laser
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void ProcessTargetEngagements
//------------------------------------------------------------------------------------------------
static void ProcessTargetEngagements(TAutoEngage *Auto,int width,int height)
{
 
 bool NewState=false;
 if(isConnected == false)
 	return;
 
 switch(Auto->State)
  {
   case NOT_ACTIVE:
                   break;
   case ACTIVATE:
                   Auto->CurrentIndex=0;
                   Auto->State=NEW_TARGET;

   case NEW_TARGET:
                   AutoEngage.Target=Auto->FiringOrder[Auto->CurrentIndex];
                   Auto->StableCount=0;
                   Auto->LastPan=-99999.99;
                   Auto->LastTilt=-99999.99;
                   NewState=true;

   case LOOKING_FOR_TARGET:
   case TRACKING:
                {
                  int retval;
                  TEngagementState state=LOOKING_FOR_TARGET;
                  bool targetFound = false; // Added variable to track if target is found
                  for (int i = 0; i < NumMatches; i++)
                     {
                      if (DetectedMatches[i].match==Auto->Target)
                        {
                         float PanError,TiltError;
                         PanError=(DetectedMatches[i].center.x+xCorrect)-width/2;
                         Pan=Pan-PanError/75;
                         ServoAngle(PAN_SERVO, Pan);

                         TiltError=(DetectedMatches[i].center.y+yCorrect)-height/2;
                         Tilt=Tilt-TiltError/75;
                         ServoAngle(TILT_SERVO, Tilt);
 
                         if ((compare_float(Auto->LastPan,Pan)) && (compare_float(Auto->LastTilt,Tilt)))
                          {
                            Auto->StableCount++;
                          }
                         else Auto->StableCount=0;

                         Auto->LastPan=Pan;
                         Auto->LastTilt=Tilt;
                         if (Auto->StableCount>2) state=TRACKING_STABLE;
                         else state=TRACKING;
                         targetFound = true; // Set targetFound to true
                         break;
                        }
                     }
                  if (Auto->State!=state)  
                     {
                      NewState=true;
                      Auto->State=state;
                     }
                  if (NewState) 
                     {
                      if (state==LOOKING_FOR_TARGET)
                        {
                          armed(false);
                          SendSystemState(SystemState);
                          PrintfSend("Looking for Target %d",AutoEngage.Target);
                        }
                      else if (state==TRACKING)
                        {
                         armed(true);
                         SendSystemState(SystemState);
                         PrintfSend("Tracking Target Unstable %d",AutoEngage.Target);
                        }

                      else if (state==TRACKING_STABLE)
                        {
                             
                          PrintfSend("Target Tracking Stable %d",AutoEngage.Target); 
                          Auto->State=ENGAGEMENT_IN_PROGRESS;
                          printf("Signaling Engagement\n");
                          if ((retval = pthread_cond_signal(&Engagement_cv)) != 0) 
                            {
                             printf("pthread_cond_signal Error\n");
                             exit(0);
                            }
                        }
                     }
                     else if (state==LOOKING_FOR_TARGET && !targetFound) // If target is not found
                     {
                          Auto->State = NOT_ACTIVE; // Move to NOT_ACTIVE state
                          SystemState = PREARMED; // Set system state to PREARMED
                          SendSystemState(SystemState);
                          PrintfSend("Unable to locate target %d. Please troubleshoot the issue.", AutoEngage.Target);
                          break; // Exit the switch statement
                     }
                }    
                break;
   case ENGAGEMENT_IN_PROGRESS:
                {
                }
                break;      
   case ENGAGEMENT_COMPLETE:
                {
                 AutoEngage.CurrentIndex++;
                 if (AutoEngage.CurrentIndex>=AutoEngage.NumberOfTartgets) 
                   {
                    Auto->State=NOT_ACTIVE;
                    SystemState=PREARMED;
                    SendSystemState(SystemState);
                    PrintfSend("Target List Completed");
                   }
                 else  Auto->State=NEW_TARGET; 
                }
                break;  
    default: 
             printf("Invaid State\n");
             break;    
 }
  return;
}
//------------------------------------------------------------------------------------------------
// END static void ProcessTargetEngagements
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void CreateNoDataAvalable
//------------------------------------------------------------------------------------------------
static void CreateNoDataAvalable(void)
{
  while (!GetFrame(NoDataAvalable)) printf("blank frame grabbed\n");    
  cv::String Text =format("NO DATA");

  int baseline;
  float FontSize=3.0; //12.0;
  int Thinkness=4;
    
  NoDataAvalable.setTo(cv::Scalar(128, 128, 128));
  Size TextSize= cv::getTextSize(Text, cv::FONT_HERSHEY_COMPLEX, FontSize,  Thinkness,&baseline); // Get font size

  int textX = (NoDataAvalable.cols- TextSize.width) / 2;
  int textY = (NoDataAvalable.rows + TextSize.height) / 2;
  putText(NoDataAvalable,Text,Point(textX , textY),cv::FONT_HERSHEY_COMPLEX,FontSize,Scalar(255,255,255),Thinkness*Thinkness,cv::LINE_AA);
  putText(NoDataAvalable,Text,Point(textX , textY),cv::FONT_HERSHEY_COMPLEX,FontSize,Scalar(0,0,0),Thinkness,cv::LINE_AA);
  printf("frame size %d %d\n", NoDataAvalable.cols,NoDataAvalable.rows);
}
//------------------------------------------------------------------------------------------------
// END static void CreateNoDataAvalable
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static bool OpenCamera
//------------------------------------------------------------------------------------------------
static bool OpenCamera(void)
{
#if USE_USB_WEB_CAM
    capture=new (std::nothrow) cv::VideoCapture("/dev/video8",cv::CAP_V4L);
    if (capture==NULL)
    {
        printf("Failed to open camera\n");
        return false;
    }
    if(!capture->isOpened()) {
        std::cout<<"Failed to open camera."<<std::endl;
        delete capture;
        return false;
    }

#else
    capture= new (std::nothrow) lccv::PiCamera();
    if (capture==NULL)
    {
        printf("Failed to open camera\n");
        return false;
    }
    capture->options->video_width=WIDTH;
    capture->options->video_height=HEIGHT;
    capture->options->framerate=30;
    capture->options->verbose=true;
    capture->startVideo();
    usleep(500*1000);
#endif
 return(true);
}
//------------------------------------------------------------------------------------------------
// END static bool OpenCamera
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static bool GetFrame
//------------------------------------------------------------------------------------------------
static bool GetFrame(Mat &frame)
{
    if (capture==NULL)
    {
      printf("Camera was not opened\n");
      return (false);
    }
#if USE_USB_WEB_CAM
    // wait for a new frame from camera and store it into 'frame'
    capture->read(frame);
    // check if we succeeded
    if (image.empty()) return(false);
#else
    if(!capture->getVideoFrame(frame,1000)) return(false);
#endif

    flip(frame, frame,-1);       // if running on PI5 flip(-1)=180 degrees
    
    return (true);
}
//------------------------------------------------------------------------------------------------
// END static bool GetFrame
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void CloseCamera
//------------------------------------------------------------------------------------------------
static void CloseCamera(void)
{
 if (capture!=NULL)  
 {
#if USE_USB_WEB_CAM
       capture->release();
#else    
       capture->stopVideo();
#endif 
       delete capture;
       capture=NULL;
 }
}
//------------------------------------------------------------------------------------------------
// END static void CloseCamera
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void OpenServos
//------------------------------------------------------------------------------------------------
static void OpenServos(void)
{
 Servos = new (std::nothrow) Servo(0x40, 0.750, 2.250);
 if (Servos==NULL)
  {
    printf("Failed to open Servos\n");
    return;
  }
}
//------------------------------------------------------------------------------------------------
// END static void OpenServos
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static bool CloseServos
//------------------------------------------------------------------------------------------------
static void CloseServos(void)
{
 if (Servos!=NULL)
  {
   delete Servos;
   Servos=NULL;
  }
}
//------------------------------------------------------------------------------------------------
// END static  CloseServos
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void OpenGPIO
//------------------------------------------------------------------------------------------------
static void OpenGPIO(void)
{
  gpioid = lgGpiochipOpen(4); //4 - PI 5
  lgGpioClaimOutput(gpioid,0,17,0); // Fire Cannon
  lgGpioClaimOutput(gpioid,0,18,0); // Laser
}
//------------------------------------------------------------------------------------------------
// END static void OpenGPIO
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void CloseGPIO
//------------------------------------------------------------------------------------------------
static void CloseGPIO(void)
{
 lgGpiochipClose(gpioid);
}
//------------------------------------------------------------------------------------------------
// END static void CloseGPIO
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static bool OLEDInit
//------------------------------------------------------------------------------------------------
static bool OLEDInit(void)
{
    uint8_t rc = 0;
    // open the I2C device node
    rc = ssd1306_init(i2c_node_address);
    
    if (rc != 0)
    {
        printf("no oled attached to /dev/i2c-%d\n", i2c_node_address);
        return (false);
    }
   rc= ssd1306_oled_default_config(64, 128);
    if (rc != 0)
    {
        printf("OLED DIsplay initialization failed\n");
        return (false);
    }
    rc=ssd1306_oled_clear_screen();
    if (rc != 0)
    {
        printf("OLED Clear screen Failed\n");
        return (false);

    }
  ssd1306_oled_set_rotate(0);
  ssd1306_oled_set_XY(0, 0);
  ssd1306_oled_write_line(OLED_Font, (char *) "READY");
  return(true); 
}
//------------------------------------------------------------------------------------------------
// END static bool OLEDInit
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void OLED_UpdateStatus
//------------------------------------------------------------------------------------------------
static void OLED_UpdateStatus(void)
{
    char Status[128];
    static SystemState_t LastSystemState=UNKNOWN;
    static SystemState_t LastSystemStateBase=UNKNOWN;
    SystemState_t SystemStateBase;
    if (!HaveOLED) return;
    pthread_mutex_lock(&I2C_Mutex);
    if (LastSystemState==SystemState)
       {
        pthread_mutex_unlock(&I2C_Mutex);
        return;
       }
    SystemStateBase=(SystemState_t)(SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK);
    if (SystemStateBase!=LastSystemStateBase)
      {
       LastSystemStateBase=SystemStateBase;
       ssd1306_oled_clear_line(0);  
       ssd1306_oled_set_XY(0, 0);
       if  (SystemStateBase==UNKNOWN)  strncpy(Status,"Unknown", sizeof(Status));
       else if  (SystemStateBase==SAFE)  strncpy(Status,"SAFE", sizeof(Status));
       else if  (SystemStateBase==PREARMED)  strncpy(Status,"PREARMED", sizeof(Status));
       else if  (SystemStateBase==ENGAGE_AUTO)  strncpy(Status,"ENGAGE AUTO", sizeof(Status));
       else if  (SystemStateBase==ARMED_MANUAL)  strncpy(Status,"ARMED_MANUAL", sizeof(Status));
       if (SystemState & ARMED) strncat(Status,"-ARMED", sizeof(Status) - strlen(Status) - 1);
       ssd1306_oled_write_line(OLED_Font, Status);
      }

   if((SystemState & LASER_ON)!=(LastSystemState & LASER_ON)||(LastSystemState==UNKNOWN))
    {
     ssd1306_oled_clear_line(1); 
     ssd1306_oled_set_XY(0, 1);
     if (SystemState & LASER_ON ) strncpy(Status,"LASER-ON", sizeof(Status));
     else strncpy(Status,"LASER-OFF", sizeof(Status));
     ssd1306_oled_write_line(OLED_Font, Status);
    }
   if((SystemState & FIRING)!=(LastSystemState & FIRING)||(LastSystemState==UNKNOWN))
   {
     ssd1306_oled_clear_line(2); 
     ssd1306_oled_set_XY(0, 2);
     if (SystemState & FIRING ) strncpy(Status,"FIRING-TRUE", sizeof(Status));
     else strncpy(Status,"FIRING-FALSE", sizeof(Status));
     ssd1306_oled_write_line(OLED_Font, Status);
    }
   LastSystemState=SystemState;
   pthread_mutex_unlock(&I2C_Mutex);
   return;
}
//------------------------------------------------------------------------------------------------
// END static void OLED_UpdateStatus
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void DrawCrosshair
//------------------------------------------------------------------------------------------------
static void DrawCrosshair(Mat &img, Point correct, const Scalar &color)
{
  // Use `shift` to try to gain sub-pixel accuracy
  int shift = 10;
  int m = pow(2, shift);

  Point pt = Point((int)((img.cols/2-correct.x/2) * m), (int)((img.rows/2-correct.y/2) * m));

  int size = int(10 * m);
  int gap = int(4 * m);
  line(img, Point(pt.x, pt.y-size), Point(pt.x, pt.y-gap), color, 1,LINE_8, shift);
  line(img, Point(pt.x, pt.y+gap), Point(pt.x, pt.y+size), color, 1,LINE_8, shift);
  line(img, Point(pt.x-size, pt.y), Point(pt.x-gap, pt.y), color, 1,LINE_8, shift);
  line(img, Point(pt.x+gap, pt.y), Point(pt.x+size, pt.y), color, 1,LINE_8, shift);
  line(img, pt, pt, color, 1,LINE_8, shift);
}
//------------------------------------------------------------------------------------------------
// END static void DrawCrosshair
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// main - This is the main program for the Gel Cannon and contains the control loop
//------------------------------------------------------------------------------------------------
int main(int argc, const char** argv)
{
  Mat                              Frame,ResizedFrame;      // camera image in Mat format 
  float                            avfps=0.0,FPS[16]={0.0,0.0,0.0,0.0,
                                                      0.0,0.0,0.0,0.0,
                                                      0.0,0.0,0.0,0.0,
                                                      0.0,0.0,0.0,0.0};
  int                              retval,i,Fcnt = 0;
  chrono::steady_clock::time_point Tbegin, Tend;
 
  ReadOffsets();

  for (i = 0; i < 16; i++) FPS[i] = 0.0;
    
  AutoEngage.State=NOT_ACTIVE;
  AutoEngage.HaveFiringOrder=false;
  AutoEngage.NumberOfTartgets=0;

  pthread_mutexattr_init(&TCP_MutexAttr);
  pthread_mutexattr_settype(&TCP_MutexAttr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutexattr_init(&GPIO_MutexAttr);
  pthread_mutexattr_settype(&GPIO_MutexAttr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutexattr_init(&I2C_MutexAttr);
  pthread_mutexattr_settype(&I2C_MutexAttr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutexattr_init(&Engmnt_MutexAttr);
  pthread_mutexattr_settype(&Engmnt_MutexAttr, PTHREAD_MUTEX_ERRORCHECK);

  if (pthread_mutex_init(&TCP_Mutex, &TCP_MutexAttr)!=0) return -1;
  if (pthread_mutex_init(&GPIO_Mutex, &GPIO_MutexAttr)!=0) return -1; 
  if (pthread_mutex_init(&I2C_Mutex, &I2C_MutexAttr)!=0) return -1; 
  if (pthread_mutex_init(&Engmnt_Mutex, &Engmnt_MutexAttr)!=0) return -1; 

  HaveOLED=OLEDInit();   

  printf("OpenCV: Version %s\n",cv::getVersionString().c_str());

  //printf("OpenCV: %s", cv::getBuildInformation().c_str());

#if USE_TFLITE
 printf("TensorFlow Lite Mode\n");
 detector = new (std::nothrow) ObjectDetector("../TfLite-2.17/Data/detect.tflite", false);
 if (detector == NULL)
   {
    printf("Error creating detector\n");
    return -1;
   }
#elif USE_IMAGE_MATCH

 printf("Image Match Mode\n");

 DetectedMatches = new (std::nothrow) TDetectedMatches[MAX_DETECTED_MATCHES];
  if (DetectedMatches == NULL)
    {
      printf("Error creating DetectedMatches\n");
      return -1;
    }

 if (LoadRefImages(symbols) == -1) 
   {
    printf("Error reading reference symbols\n");
    return -1;
   }

#endif

   OpenGPIO();
   laser(false);
   fire(false);
   calibrate(false);
   
   OpenServos();
   ServoAngle(PAN_SERVO, Pan);
   ServoAngle(TILT_SERVO, Tilt);

   Setup_Control_C_Signal_Handler_And_Keyboard_No_Enter(); // Set Control-c handler to properly exit clean

  if (!OpenCamera())
     {
      printf("Could not Open Camera\n");
      return(-1);
     }
  else printf("Opened Camera\n");
  
  CreateNoDataAvalable();

  if (pthread_create(&NetworkThreadID, NULL,NetworkInputThread, NULL)!=0)
   {
     printf("Failed to Create Network Input Thread\n");
     exit(0);
   }
  printf("Create Network\n");
  if (pthread_create(&EngagementThreadID, NULL,EngagementThread, NULL)!=0)
   {
     printf("Failed to Create ,Engagement Thread\n");
     exit(0);
   }
   printf("Create Engagement\n");

  do
   {
    Tbegin = chrono::steady_clock::now();
    
    if (!GetFrame(Frame))
        {
         printf("ERROR! blank frame grabbed\n");
         continue;
        }

    HandleInputChar(Frame);                           // Handle Keyboard Input
#if USE_TFLITE

    DetectResult* res = detector->detect(Frame); 
    for (i = 0; i < detector->DETECT_NUM; ++i) 
        {
	  int labelnum = res[i].label;
	  float score = res[i].score;
	  float xmin = res[i].xmin;
	  float xmax = res[i].xmax;
	  float ymin = res[i].ymin;
	  float ymax = res[i].ymax;
          int baseline=0;
                
          if (score<0.10) continue;
                    
          cv::rectangle(Frame, Point(xmin,ymin), Point(xmax,ymax), Scalar(10, 255, 0), 2);
          cv::String label =to_string(labelnum) + ": " + to_string(int(score*100))+ "%";
               
          Size labelSize= cv::getTextSize(label, cv::FONT_HERSHEY_SIMPLEX, 0.7, 2,&baseline); // Get font size
          int label_ymin = std::max((int)ymin, (int)(labelSize.height + 10)); // Make sure not to draw label too close to top of window
          rectangle(Frame, Point(xmin, label_ymin-labelSize.height-10), Point(xmin+labelSize.width, label_ymin+baseline-10), Scalar(255, 255, 255), cv::FILLED); // Draw white box to put label text in
          putText(Frame, label, Point(xmin, label_ymin-7), cv::FONT_HERSHEY_SIMPLEX, 0.7, Scalar(0, 0, 0), 2); // Draw label text
       }
   delete[] res;
#elif USE_IMAGE_MATCH
         TEngagementState tmpstate=AutoEngage.State;

         if (tmpstate!=ENGAGEMENT_IN_PROGRESS) FindTargets(Frame);
         ProcessTargetEngagements(&AutoEngage,Frame.cols,Frame.rows);
         if (tmpstate!=ENGAGEMENT_IN_PROGRESS) DrawTargets(Frame);
#endif
#define FPS_XPOS 0
#define FPS_YPOS 20
    cv::String FPS_label =format("FPS %0.2f",avfps / 16);
    int FPS_baseline=0;
                      
    Size FPS_labelSize= cv::getTextSize(FPS_label, cv::FONT_HERSHEY_SIMPLEX, 0.7, 2,&FPS_baseline); // Get font size
    int FPS_label_ymin = std::max((int)FPS_YPOS, (int)(FPS_labelSize.height + 10)); // Make sure not to draw label too close to top of window
    rectangle(Frame, Point(FPS_XPOS, FPS_label_ymin-FPS_labelSize.height-10), Point(FPS_XPOS+FPS_labelSize.width, FPS_label_ymin+FPS_baseline-10), Scalar(255, 255, 255), cv::FILLED); // Draw white box to put label text in
    putText(Frame, FPS_label, Point(FPS_XPOS, FPS_label_ymin-7), cv::FONT_HERSHEY_SIMPLEX, 0.7, Scalar(0, 0, 0), 2); // Draw label text

   if (SystemState==SAFE)
      {
        Frame=NoDataAvalable.clone();
        resize(Frame, ResizedFrame, Size(Frame.cols/2,Frame.rows/2));
      } 
   else
     {
      resize(Frame, ResizedFrame, Size(Frame.cols/2,Frame.rows/2));
      DrawCrosshair(ResizedFrame,Point((int)xCorrect,(int)yCorrect),Scalar(0, 0, 255)); //BGR
     }

    
    if (isConnected)
		{
			
		    pthread_mutex_lock(&TCP_Mutex); 
			if(TcpSendImageAsJpeg(TcpConnectedPort,ResizedFrame)<0)  break;
			pthread_mutex_unlock(&TCP_Mutex); 
    	}
   
    Tend = chrono::steady_clock::now();
    avfps = chrono::duration_cast <chrono::milliseconds> (Tend - Tbegin).count();
    if (avfps > 0.0) FPS[((Fcnt++) & 0x0F)] = 1000.0 / avfps;
    for (avfps = 0.0, i = 0; i < 16; i++) { avfps += FPS[i]; }
  } while (1);

  printf("Main Thread Exiting\n");
  CleanUp();
  return 0;
}
//------------------------------------------------------------------------------------------------
// End main
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void * EngagementThread
//------------------------------------------------------------------------------------------------
static void * EngagementThread(void *data) 
{
  int ret;
  while (1) {
    if ((ret = pthread_mutex_lock(&Engmnt_Mutex)) != 0) {
      
      printf("Engmnt_Mutex ERROR\n");
      break;
    }
    printf("Waiting for Engagement Order\n");
    if ((ret = pthread_cond_wait(&Engagement_cv, &Engmnt_Mutex)) != 0) {
       printf("Engagement  pthread_cond_wait ERROR\n");
      break;

    }

    printf("Engagment in Progress\n");
    laser(true);
    SendSystemState(SystemState);
    usleep(1500*1000);
    fire(true);
    SendSystemState(SystemState);
    usleep(200*1000);
    fire(false);
    laser(false);
    armed(false);
    SendSystemState(SystemState);
    PrintfSend("Engaged Target %d",AutoEngage.Target);
    AutoEngage.State=ENGAGEMENT_COMPLETE;

    if ((ret = pthread_mutex_unlock(&Engmnt_Mutex)) != 0) 
    {
        printf("Engagement pthread_cond_wait ERROR\n");
       break;
    }
  }

  return NULL;
}
//------------------------------------------------------------------------------------------------
// END static void * EngagementThread
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static int PrintfSend
//------------------------------------------------------------------------------------------------
static int PrintfSend(const char *fmt, ...) 
{
    char Buffer[2048];
    int  BytesWritten;
    int  retval;
	if(isConnected == false) return -1;
    pthread_mutex_lock(&TCP_Mutex); 
    va_list args;
    va_start(args, fmt);
    BytesWritten=vsnprintf(Buffer,sizeof(Buffer),fmt, args);
    va_end(args);
    if (BytesWritten>0)
      {
       TMesssageHeader MsgHdr;
       BytesWritten++;
       MsgHdr.Len=htonl(BytesWritten);
       MsgHdr.Type=htonl(MT_TEXT);
	   MsgHdr.seqN=htonll(GetSendSeqNum());
       if (WriteDataTcp(TcpConnectedPort,(unsigned char *)&MsgHdr, sizeof(TMesssageHeader))!=sizeof(TMesssageHeader)) 
           {
            pthread_mutex_unlock(&TCP_Mutex);
            return (-1);
           }
       retval=WriteDataTcp(TcpConnectedPort,(unsigned char *)Buffer,BytesWritten);
       pthread_mutex_unlock(&TCP_Mutex);
       return(retval);
      }
    else 
     {
      pthread_mutex_unlock(&TCP_Mutex);
      return(BytesWritten);
     }
}

// KO_ADD

static int SendSharedHmacKey(char* HMACKey) {
	if(isConnected == false) return -1;
    pthread_mutex_lock(&TCP_Mutex);
    printf("SendSharedHmacKey Enter\n");
    TMesssageSharedHmacKey response;
    response.Hdr.Len = htonl(sizeof(response) - sizeof(response.Hdr));
    response.Hdr.Type = htonl(MT_SHARED_HMAC_KEY);
	response.Hdr.seqN=htonll(GetSendSeqNum());

    std::vector<unsigned char> sharedHmacKey = generate_random_bytes(HMAC_SIZE);
    memcpy(response.SharedKey, sharedHmacKey.data(), HMAC_SIZE);
    memcpy(HMACKey, sharedHmacKey.data(), HMAC_SIZE);

    if (WriteDataTcp(TcpConnectedPort, reinterpret_cast<unsigned char*>(&response), sizeof(response)) != sizeof(response)) {
        pthread_mutex_unlock(&TCP_Mutex);
        return -1;
    }
    pthread_mutex_unlock(&TCP_Mutex);
    printf("SendSharedHmacKey Exit\n");
    return 0;
}

static int SendLoginEnrollResponse(LogInState_t login_state, const char* key) {
	if(isConnected == false) return -1;

    printf("SendLoginEnrollResponse Enter\n");
    pthread_mutex_lock(&TCP_Mutex);
    TMesssageLoginEnrollResponse response;
    response.Hdr.Len = htonl(sizeof(response) - sizeof(response.Hdr));
    response.Hdr.Type = htonl(MT_LOGIN_ENROLL_RES);
	response.Hdr.seqN=htonll(GetSendSeqNum());
    response.LoginState = htonl(login_state);

    // Calculate HMAC
    std::vector<unsigned char> response_hmac = calculate_hmac(key, &response.LoginState, sizeof(response) - sizeof(TMesssageHeader));
    memcpy(response.Hdr.HMAC, response_hmac.data(), response_hmac.size());

    if (WriteDataTcp(TcpConnectedPort, reinterpret_cast<unsigned char*>(&response), sizeof(response)) != sizeof(response)) {
        pthread_mutex_unlock(&TCP_Mutex);
        return -1;
    }
    pthread_mutex_unlock(&TCP_Mutex);
    printf("SendLoginEnrollResponse Exit\n");
    return 0;
}

static int SendLoginVerifyResponse(LogInState_t login_state, const std::vector<unsigned char>& token, FailInfo& fail_info, const char* key) {
	if(isConnected == false) return -1;

    pthread_mutex_lock(&TCP_Mutex);
    TMesssageLoginVerifyResponse response = {0,};
    printf("SendLoginVerifyResponse Enter\n");
    response.Hdr.Len = htonl(sizeof(response) - sizeof(response.Hdr));
    response.Hdr.Type = htonl(MT_LOGIN_VERITY_RES);
	response.Hdr.seqN=htonll(GetSendSeqNum());
    response.LoginState = htonl((unsigned int)login_state);

    if (login_state == SUCCESS) {
        response.FailCount = 0;
        response.Throttle = 0;
        response.Privilege = htonl(fail_info.Privilege);
        memcpy(response.Token, token.data(), token.size());
    }
    else {
        response.FailCount = htonl(fail_info.FailCount);
        response.Throttle = htonl(fail_info.Throttle);
        response.Privilege = htonl(fail_info.Privilege);
    }

    // Calculate HMAC
    std::vector<unsigned char> response_hmac = calculate_hmac(key, &response.LoginState, sizeof(response) - sizeof(TMesssageHeader));
    memcpy(response.Hdr.HMAC, response_hmac.data(), response_hmac.size());

    if (WriteDataTcp(TcpConnectedPort, reinterpret_cast<unsigned char*>(&response), sizeof(response)) != sizeof(response)) {
        pthread_mutex_unlock(&TCP_Mutex);
        return -1;
    }
    pthread_mutex_unlock(&TCP_Mutex);
    printf("SendLoginVerifyResponse Exit\n");
    return 0;
}

static int SendLoginChangePwResponse(LogInState_t login_state, const char* key) {
	if(isConnected == false) return -1;

    printf("SendLoginChangePwResponse Enter\n");
    pthread_mutex_lock(&TCP_Mutex);
    TMesssageLoginChangePwResponse response;
    response.Hdr.Len = htonl(sizeof(response) - sizeof(response.Hdr));
    response.Hdr.Type = htonl(MT_LOGIN_CHANGEPW_RES);
	response.Hdr.seqN=htonll(GetSendSeqNum());
    response.LoginState = (LogInState_t)htonl(login_state);

    // Calculate HMAC
    std::vector<unsigned char> response_hmac = calculate_hmac(key, &response.LoginState, sizeof(response) - sizeof(TMesssageHeader));
    memcpy(response.Hdr.HMAC, response_hmac.data(), response_hmac.size());

    if (WriteDataTcp(TcpConnectedPort, reinterpret_cast<unsigned char*>(&response), sizeof(response)) != sizeof(response)) {
        pthread_mutex_unlock(&TCP_Mutex);
        return -1;
    }
    pthread_mutex_unlock(&TCP_Mutex);
    printf("SendLoginChangePwResponse Exit\n");
    return 0;
}

static int SendLogoutResponse(LogInState_t login_state, const char* key) {
    printf("SendLogoutResponse Enter\n");
    pthread_mutex_lock(&TCP_Mutex);
    TMesssageLogoutResponse response;
    response.Hdr.Len = htonl(sizeof(response) - sizeof(response.Hdr));
    response.Hdr.Type = htonl(MT_LOGOUT_RES);
	response.Hdr.seqN=htonll(GetSendSeqNum());
    response.LoginState = (LogInState_t)htonl(login_state);

    // Calculate HMAC
    std::vector<unsigned char> response_hmac = calculate_hmac(key, &response.LoginState, sizeof(response) - sizeof(TMesssageHeader));
    memcpy(response.Hdr.HMAC, response_hmac.data(), response_hmac.size());

    if (WriteDataTcp(TcpConnectedPort, reinterpret_cast<unsigned char*>(&response), sizeof(response)) != sizeof(response)) {
        pthread_mutex_unlock(&TCP_Mutex);
        return -1;
    }
    pthread_mutex_unlock(&TCP_Mutex);
    printf("SendLogoutResponse Exit\n");
    return 0;
}
//------------------------------------------------------------------------------------------------
// END static int PrintfSend
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static int SendSystemState
//------------------------------------------------------------------------------------------------
static int SendSystemState(SystemState_t State)
{
	if(isConnected == false) return -1;
 TMesssageSystemState StateMsg;
 int                  retval;
 pthread_mutex_lock(&TCP_Mutex);
 StateMsg.State=(SystemState_t)htonl(State);
 StateMsg.Hdr.Len=htonl(sizeof(StateMsg.State));
 StateMsg.Hdr.Type=htonl(MT_STATE);
 StateMsg.Hdr.seqN=htonll(GetSendSeqNum());
 OLED_UpdateStatus();
 retval=WriteDataTcp(TcpConnectedPort,(unsigned char *)&StateMsg,sizeof(TMesssageSystemState));
 pthread_mutex_unlock(&TCP_Mutex);
 return(retval);
} 
//------------------------------------------------------------------------------------------------
// END static int SendSystemState
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void ProcessPreArm
//------------------------------------------------------------------------------------------------
static void ProcessPreArm(char * Code)
{
 char Decode[]={0x61,0x60,0x76,0x75,0x67,0x7b,0x72,0x7c};

 if (SystemState==SAFE)
  {
    if ((Code[sizeof(Decode)]==0) && (strlen(Code)==sizeof(Decode)))
      { 
        for (int i=0;i<sizeof(Decode);i++) Code[i]^=Decode[i];
        if (strncmp((const char*)Code,"PREARMED",sizeof(Decode))==0)
          {
            SystemState=PREARMED;
            SendSystemState(SystemState);
            AuditLog("STATE_CHANGE_PRE_ARMED");
          } 
      }
  }
}
//------------------------------------------------------------------------------------------------
// END static void ProcessPreArm
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void ProcessStateChangeRequest
//------------------------------------------------------------------------------------------------
static void ProcessStateChangeRequest(SystemState_t state)
{  
 static bool CalibrateWasOn=false;
 switch(state&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)
 {
  case SAFE:
            {
              laser(false);
              calibrate(false);
              fire(false);
              SystemState=(SystemState_t)(state & CLEAR_LASER_FIRING_ARMED_CALIB_MASK);
              AutoEngage.State=NOT_ACTIVE;
              AutoEngage.HaveFiringOrder=false;
              AutoEngage.NumberOfTartgets=0;
            }
            AuditLog("STATE_CHANGE_SAFE");
            break;
  case PREARMED:
            { 
              if (((SystemState&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)==ENGAGE_AUTO) || 
                  ((SystemState&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)==ARMED_MANUAL))
                {
                  laser(false);
                  fire(false);
                  calibrate(false);
                  if ((SystemState&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)==ENGAGE_AUTO)
                     {
                      AutoEngage.State=NOT_ACTIVE;
                      AutoEngage.HaveFiringOrder=false;
                      AutoEngage.NumberOfTartgets=0;
                     }
                  SystemState=(SystemState_t)(state & CLEAR_LASER_FIRING_ARMED_CALIB_MASK);
                }
             }
             AuditLog("STATE_CHANGE_PRE_ARMED");
             break;

  case ENGAGE_AUTO:
            {
              if ((SystemState&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=PREARMED)
              {
               PrintfSend("Invalid State request to Auto %d\n",SystemState); 
              }
             else if (!AutoEngage.HaveFiringOrder)
              {
               PrintfSend("No Firing Order List");
              }
             else 
              {
                laser(false);
                calibrate(false);
                fire(false);
                SystemState=(SystemState_t)(state & CLEAR_LASER_FIRING_ARMED_CALIB_MASK);
                AutoEngage.State=ACTIVATE;
              }
            }
            AuditLog("STATE_CHANGE_ENGAGE_AUTO");
            break;
  case ARMED_MANUAL:
            {
              if (((SystemState&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=PREARMED) && 
                  ((SystemState&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=ARMED_MANUAL)) 
              {
               PrintfSend("Invalid State request to Auto %d\n",SystemState); 
              }
             else if ((SystemState&CLEAR_LASER_FIRING_ARMED_CALIB_MASK)==PREARMED)
              {
                laser(false);
                calibrate(false);
                fire(false);
                SystemState=(SystemState_t)(state & CLEAR_LASER_FIRING_ARMED_CALIB_MASK);
              }
             else SystemState=state;

            }
            if (SystemState & LASER_ON) AuditLog("STATE_CHANGE_LASER_ON");
            else if (SystemState & CALIB_ON) AuditLog("STATE_CHANGE_CALIB_ON");
            else AuditLog("STATE_CHANGE_ARMED_MANUAL");
            break;
  default:
             {
              printf("UNKNOWN STATE REQUEST %d\n",state);
             }
             AuditLog("STATE_CHANGE_UNKNOWN_REQUEST");
              break;

 }

 if (SystemState & LASER_ON)  laser(true);
 else laser(false);

 if (SystemState & CALIB_ON)  
    {
     calibrate(true);
     CalibrateWasOn=true;
    }
 else 
    {
     calibrate(false);
     if (CalibrateWasOn) 
        {
         CalibrateWasOn=false;
         WriteOffsets();
        }
    }

 SendSystemState(SystemState);
}
//------------------------------------------------------------------------------------------------
// END static void ProcessStateChangeRequest
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void ProcessFiringOrder
//------------------------------------------------------------------------------------------------
static void ProcessFiringOrder(char * FiringOrder)
{
  int len=strlen(FiringOrder);
  
  AutoEngage.State=NOT_ACTIVE;
  AutoEngage.HaveFiringOrder=false;
  AutoEngage.NumberOfTartgets=0;
  AutoEngage.Target=0;

  if (len>10) 
     {
      printf("Firing order error\n");
      return; 
     }
  for (int i=0;i<len;i++)
    {
      AutoEngage.FiringOrder[i]=FiringOrder[i]-'0';
	  if(AutoEngage.FiringOrder[i] > 9 || AutoEngage.FiringOrder[i] < 0)
	  {
	  	AutoEngage.HaveFiringOrder=false;
	     printf("Invalid Target number.\n");
	     return;
	  }
    }
  if (len>0)  AutoEngage.HaveFiringOrder=true;
  else
    {
     AutoEngage.HaveFiringOrder=false;
     PrintfSend("Empty Firing List");
     return;
    }
  AutoEngage.NumberOfTartgets=len; 
#if 0  
  printf("Firing order:\n");
  for (int i=0;i<len;i++) printf("%d\n",AutoEngage.FiringOrder[i]);
  printf("\n\n");
#endif
}
//------------------------------------------------------------------------------------------------
// END static void ProcessFiringOrder
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void ProcessCommands
//------------------------------------------------------------------------------------------------
static void ProcessCommands(unsigned char cmd)
{
 if (((SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=PREARMED) &&
     ((SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=ARMED_MANUAL))
    {
      printf("received Commands outside of Pre-Arm or Armed Manual State %x \n",cmd);
      return;
    } 
 if (((cmd==FIRE_START) || (cmd==FIRE_STOP)) && ((SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=ARMED_MANUAL))
    {
      printf("received Fire Commands outside of Armed Manual State %x \n",cmd);
      return;
    } 


      switch(cmd)
        {
         case PAN_LEFT_START:
              RunCmds|=PAN_LEFT_START;
              RunCmds&=PAN_RIGHT_STOP;
              Pan+=INC;
              ServoAngle(PAN_SERVO, Pan);
              AuditLog("MANUAL_ARMED_PAN_LEFT_START");
              break;
         case PAN_RIGHT_START:
              RunCmds|=PAN_RIGHT_START;
              RunCmds&=PAN_LEFT_STOP;
              Pan-=INC;
              ServoAngle(PAN_SERVO, Pan);
              AuditLog("MANUAL_ARMED_PAN_RIGHT_START");
              break;
         case PAN_UP_START:
              RunCmds|=PAN_UP_START;
              RunCmds&=PAN_DOWN_STOP;
              Tilt+=INC; 
              ServoAngle(TILT_SERVO, Tilt);
              AuditLog("MANUAL_ARMED_PAN_UP_START");
              break;
         case PAN_DOWN_START:
              RunCmds|=PAN_DOWN_START;
              RunCmds&=PAN_UP_STOP;
              Tilt-=INC; 
              ServoAngle(TILT_SERVO, Tilt);
              AuditLog("MANUAL_ARMED_PAN_DOWN_START");
              break;
         case FIRE_START:
              RunCmds|=FIRE_START;
              fire(true);
              SendSystemState(SystemState);
              AuditLog("MANUAL_ARMED_FIRE_START");
              break;   
         case PAN_LEFT_STOP:
              RunCmds&=PAN_LEFT_STOP;
              AuditLog("MANUAL_ARMED_PAN_LEFT_STOP");
              break;
         case PAN_RIGHT_STOP:
              RunCmds&=PAN_RIGHT_STOP;
              AuditLog("MANUAL_ARMED_PAN_RIGHT_STOP");
              break;
         case PAN_UP_STOP:
              RunCmds&=PAN_UP_STOP;
              AuditLog("MANUAL_ARMED_PAN_UP_STOP");
              break;
         case PAN_DOWN_STOP:
              RunCmds&=PAN_DOWN_STOP;
              AuditLog("MANUAL_ARMED_PAN_DOWN_STOP");
              break;
         case FIRE_STOP: 
              RunCmds&=FIRE_STOP;
              fire(false);
              SendSystemState(SystemState);
              AuditLog("MANUAL_ARMED_FIRE_STOP");
              break;
         default:
              printf("invalid command %x\n",cmd);
              AuditLog("MANUAL_ARMED_INVALID_COMMAND");
              break;
      }

}
//------------------------------------------------------------------------------------------------
// END static void ProcessCommands
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
// static void ProcessCalibCommands
//------------------------------------------------------------------------------------------------
static void ProcessCalibCommands(unsigned char cmd)
{
 if (((SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=PREARMED) &&
     ((SystemState & CLEAR_LASER_FIRING_ARMED_CALIB_MASK)!=ARMED_MANUAL) &&
       !(SystemState & CALIB_ON))
    {
      printf("received Commands outside of Armed Manual State %x \n",cmd);
      return;
    } 

      switch(cmd)
        {
         case DEC_X:
              xCorrect++;
              AuditLog("CALIB_COMMAND_DEC_X");
              break;
         case INC_X:
              xCorrect--;
              AuditLog("CALIB_COMMAND_INC_X");
              break;
         case DEC_Y:
              yCorrect--;
              AuditLog("CALIB_COMMAND_DEC_Y");
              break;
         case INC_Y:
              yCorrect++;
              AuditLog("CALIB_COMMAND_INC_Y");
              break;

         default:
              printf("invalid command %x\n",cmd);
              break;
      }

}
//------------------------------------------------------------------------------------------------
// END static void ProcessCalibCommands
//------------------------------------------------------------------------------------------------
#define MAX_MESSAGE_BUF_SIZE 512
int GetExpectedTotalLength(int Type)
{
	int expected_total_len;
	switch(Type)
	{
		case MT_COMMANDS :
			expected_total_len = sizeof(TMesssageCommands);
			break;
		case MT_CALIB_COMMANDS :
			expected_total_len = sizeof(TMesssageCalibCommands);
			break;
		case MT_PREARM :
			expected_total_len = sizeof(TMesssagePreArm);
			break;
		case MT_STATE_CHANGE_REQ :
			expected_total_len = sizeof(TMesssageChangeStateRequest);
			break;
		case MT_TARGET_SEQUENCE :
			expected_total_len = sizeof(TMesssageTargetOrder);
			break;
    case MT_LOGIN_ENROLL_REQ :
      expected_total_len = sizeof(TMesssageLoginEnrollRequest);
      break;
    case MT_LOGIN_VERITY_REQ :
      expected_total_len = sizeof(TMesssageLoginVerifyRequest);
      break;
    case MT_LOGIN_CHANGEPW_REQ :
      expected_total_len = sizeof(TMesssageLoginChangePwRequest);
      		break;
    	case MT_LOGOUT_REQ :
      		expected_total_len = sizeof(TMesssageLogoutRequest);
      break;
		default:
			break;
	}
	return expected_total_len;
}

int IsValidRecvMessageLength(int body_len, int Type)
{
	if(body_len < 0 || body_len > MAX_MESSAGE_BUF_SIZE - sizeof(TMesssageHeader))
		return false;
	
	if(body_len + sizeof(TMesssageHeader) > GetExpectedTotalLength(Type))
		return false;
	return true;
}

void system_reset(void)
{
    GlobalResetToken();
	laser(false);
	calibrate(false);
	fire(false);
	SystemState=SAFE;
	RecvSeqNum = 0;
}

//------------------------------------------------------------------------------------------------
// static void *NetworkInputThread
//------------------------------------------------------------------------------------------------
static void *NetworkInputThread(void *data)
{
 unsigned char Buffer[512];
 TMesssageHeader *MsgHdr;
 char HMACKey[HMAC_SIZE] = {0,};
 
 while (1)
 {
 	if(isConnected == 0)
 	{
		if  ((TcpListenPort=OpenTcpListenPort(PORT))==NULL)  // Open UDP Network port
		{
			printf("OpenTcpListenPortFailed\n");
			exit(0);
		}
		socklen_t						clilen;
		struct sockaddr_in               cli_addr;
	   	printf("Listening for connections by OPEN SSL\n");
	   	clilen = sizeof(cli_addr);
	   	if  ((TcpConnectedPort=AcceptTcpConnection(TcpListenPort,&cli_addr,&clilen))==NULL)
	     {
	       printf("AcceptTcpConnection Failed\n");
			exit(0);
	     }
	   	isConnected=true;
	   	printf("Accepted connection Request\n");
	   	CloseTcpListenPort(&TcpListenPort);  // Close listen port
      // Server creates a secret. And the secret to use hmac key share between server and client.
      SendSharedHmacKey(HMACKey);
      // load keys from filesystem
      initialize_keys();
	  
	   	ProcessStateChangeRequest(SAFE);

	   	continue;
 	}

   int fd=TcpConnectedPort->ConnectedFd,retval;
   SSL *ssl = TcpConnectedPort->ssl;
   if ((retval = SSL_read(ssl, &Buffer, sizeof(TMesssageHeader))) != sizeof(TMesssageHeader)) {
	    if (retval == 0) printf("Client Disconnected\n");
	    else printf("Connection Lost %s\n", ERR_reason_error_string(ERR_get_error()));
	    isConnected = false;
		system_reset();
 		CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
		continue;
	}
   MsgHdr=(TMesssageHeader *)Buffer;
   MsgHdr->Len = ntohl(MsgHdr->Len);
   MsgHdr->Type = ntohl(MsgHdr->Type);
	MsgHdr->seqN = ntohll(MsgHdr->seqN);
	
   if (!IsValidRecvMessageLength(MsgHdr->Len, MsgHdr->Type))
     {
	      printf("oversized message error %d\n",MsgHdr->Len);
	      isConnected = false;
		  system_reset();
		  CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
		  continue;
     }
   if ((retval = SSL_read(ssl, &Buffer[sizeof(TMesssageHeader)], MsgHdr->Len)) != MsgHdr->Len) {
	   if (retval == 0) printf("Client Disconnected\n");
	   else printf("Connection Lost %s\n", ERR_reason_error_string(ERR_get_error()));
	   isConnected = false;
	   system_reset();
	   CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
	   continue;
   }
	printf("Recv type : %d \t Len : %d\n", MsgHdr->Type, MsgHdr->Len + sizeof(TMesssageHeader));


		if(MsgHdr->seqN <= RecvSeqNum)
	{
		printf("seq. Num is already used %llx\n", MsgHdr->seqN);
		continue;
	}
	else
	{
		if(MsgHdr->seqN >= 0x0FFFFFFFFFFFFFFF)
		{
			RecvSeqNum = 0;
		}
		else
		{
			RecvSeqNum = MsgHdr->seqN;
		}
	}
	printf("seq. Num recieved %llx\n", MsgHdr->seqN);
   switch(MsgHdr->Type)
    {
      case MT_COMMANDS: 
      {
       TMesssageCommands *msgCmds=(TMesssageCommands *)Buffer;
       
      std::vector<unsigned char> hmac_input(sizeof(TMesssageCommands) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), &msgCmds->Commands, sizeof(TMesssageCommands) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());
       
       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgCmds->Hdr.HMAC)) {
          printf("Diffenet HMAC\n");
          break;
       }
       std::vector<unsigned char> token(msgCmds->Token, msgCmds->Token + HMAC_SIZE);
       if(!TokenVerifier(token)) {
         ProcessCommands(msgCmds->Commands);
       }
      }
      break;
      case MT_CALIB_COMMANDS: 
      {
       TMesssageCalibCommands *msgCmds=(TMesssageCalibCommands *)Buffer;

       std::vector<unsigned char> hmac_input(sizeof(TMesssageCalibCommands) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), &msgCmds->Commands, sizeof(TMesssageCalibCommands) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());
       
       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgCmds->Hdr.HMAC)) {
          printf("Diffenet HMAC\n");
          break;
       }

       std::vector<unsigned char> token(msgCmds->Token, msgCmds->Token + HMAC_SIZE);
       if(!TokenVerifier(token)) {
         ProcessCalibCommands(msgCmds->Commands);
       }
      }
      break;

      case MT_TARGET_SEQUENCE: 
      {
       TMesssageTargetOrder *msgTargetOrder=(TMesssageTargetOrder *)Buffer;

       std::vector<unsigned char> hmac_input(sizeof(TMesssageTargetOrder) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), &msgTargetOrder->FiringOrder, sizeof(TMesssageTargetOrder) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());
       
       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgTargetOrder->Hdr.HMAC)) {
          printf("Diffenet HMAC\n");
          break;
       }
       std::vector<unsigned char> token(msgTargetOrder->Token, msgTargetOrder->Token + HMAC_SIZE);
       if(!TokenVerifier(token)) {
         ProcessFiringOrder(msgTargetOrder->FiringOrder);
       }
      }
      break;
      case MT_PREARM: 
      {
       TMesssagePreArm *msgPreArm=(TMesssagePreArm *)Buffer;
       std::vector<unsigned char> hmac_input(sizeof(TMesssagePreArm) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), &msgPreArm->Code, sizeof(TMesssagePreArm) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());
       
       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgPreArm->Hdr.HMAC)) {
          printf("Diffenet HMAC\n");
          break;
       }
       std::vector<unsigned char> token(msgPreArm->Token, msgPreArm->Token + HMAC_SIZE);
       if(!TokenVerifier(token)) {
         ProcessPreArm(msgPreArm->Code);
       }
      }
      break;
      case MT_STATE_CHANGE_REQ: 
      {
       TMesssageChangeStateRequest *msgChangeStateRequest=(TMesssageChangeStateRequest *)Buffer;
       std::vector<unsigned char> hmac_input(sizeof(TMesssageChangeStateRequest) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), &msgChangeStateRequest->State, sizeof(TMesssageChangeStateRequest) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());

       msgChangeStateRequest->State=(SystemState_t)ntohl(msgChangeStateRequest->State);

       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgChangeStateRequest->Hdr.HMAC)) {
          printf("Diffenet HMAC\n");
          break;
       }

       std::vector<unsigned char> token(msgChangeStateRequest->Token, msgChangeStateRequest->Token + HMAC_SIZE);
       if(!TokenVerifier(token)) {
         ProcessStateChangeRequest(msgChangeStateRequest->State);
       }
      }
      break;
      case MT_LOGIN_ENROLL_REQ:
      {
       printf("MT_LOGIN_ENROLL_REQ\n");
       AuditLog("MT_LOGIN_ENROLL_REQ");
       TMesssageLoginEnrollRequest* msgLoginEnroll = (TMesssageLoginEnrollRequest*)Buffer;

       // 1. MsgHdr->HMAC 값과 msgLoginEnroll의 HMAC값이 같은지 확인
       std::vector<unsigned char> hmac_input(sizeof(TMesssageLoginEnrollRequest) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), msgLoginEnroll->Name, sizeof(TMesssageLoginEnrollRequest) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());
       
       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgLoginEnroll->Hdr.HMAC)) {
          printf("Diffenet HMAC\n");
          SendLoginEnrollResponse(INVALID_MSG, HMACKey);
          break;
       }

       // 2. Enroll API 호출
       int enroll_result = EnrollPwd(msgLoginEnroll->Name, msgLoginEnroll->Password);

       // 3. response API 호출
	   LogInState_t login_state = (enroll_result == 0) ? (LogInState_t)E_SUCCESS : (LogInState_t)enroll_result;
       SendLoginEnrollResponse(login_state, HMACKey);
      }
      break;
      case MT_LOGIN_VERITY_REQ:
      {
       printf("MT_LOGIN_VERITY_REQ\n");
       AuditLog("MT_LOGIN_VERITY_REQ");
       TMesssageLoginVerifyRequest* msgLoginVerify = (TMesssageLoginVerifyRequest*)Buffer;
       FailInfo fail_info = {0,};


       // 1. MsgHdr->HMAC 값과 msgLoginVerify의 HMAC값이 같은지 확인
       std::vector<unsigned char> hmac_input(sizeof(TMesssageLoginVerifyRequest) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), msgLoginVerify->Name, sizeof(TMesssageLoginVerifyRequest) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());

       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgLoginVerify->Hdr.HMAC)) {
          SendLoginVerifyResponse(INVALID_MSG, std::vector<unsigned char>(), fail_info, HMACKey);
          break;
       }

       // 2. Verify API 호출
       std::vector<unsigned char> token(32);
       int verify_result = VerifyPwd(msgLoginVerify->Name, msgLoginVerify->Password, token, fail_info);

       // 3. Verify 결과를 반환하는 response API 호출
       LogInState_t login_state = (verify_result == 0) ? (LogInState_t)SUCCESS : (LogInState_t)verify_result;
       SendLoginVerifyResponse(login_state, token, fail_info, HMACKey);
      }
      break;
      case MT_LOGIN_CHANGEPW_REQ:
      {
       AuditLog("MT_LOGIN_CHANGEPW_REQ");
       TMesssageLoginChangePwRequest* msgLoginChangePw = (TMesssageLoginChangePwRequest*)Buffer;

      // 1. MsgHdr->HMAC 값과 msgLoginChangePw의 HMAC값이 같은지 확인
       std::vector<unsigned char> hmac_input(sizeof(TMesssageLoginChangePwRequest) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), msgLoginChangePw->Name, sizeof(TMesssageLoginChangePwRequest) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());

       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgLoginChangePw->Hdr.HMAC)) {
           printf("different HMAC\n");
           SendLoginChangePwResponse(INVALID_MSG, HMACKey);
           break;
       }

      // 2. ChangePwd API 호출
       std::vector<unsigned char> token(msgLoginChangePw->Token, msgLoginChangePw->Token + 32);
       int change_pwd_result = ChangePwd(msgLoginChangePw->Name, msgLoginChangePw->Password, token);

      // 3. response API 호출
       LogInState_t login_state = (change_pwd_result == 0) ? (LogInState_t)C_SUCCESS : (LogInState_t)change_pwd_result;
       SendLoginChangePwResponse(login_state, HMACKey);
       }
      break;
      case MT_LOGOUT_REQ:
      {
       TMesssageLogoutRequest* msgLogout = (TMesssageLogoutRequest*)Buffer;

       std::vector<unsigned char> hmac_input(sizeof(TMesssageLogoutRequest) - sizeof(TMesssageHeader));
       memcpy(hmac_input.data(), msgLogout->Token, sizeof(TMesssageLogoutRequest) - sizeof(TMesssageHeader));
       std::vector<unsigned char> calculated_hmac = calculate_hmac(HMACKey, hmac_input.data(), hmac_input.size());

       if (!std::equal(calculated_hmac.begin(), calculated_hmac.end(), msgLogout->Hdr.HMAC)) {
           SendLogoutResponse(INVALID_TOKEN, HMACKey);
           break;
       }

      // 2. Call ResetToken
       std::vector<unsigned char> token(msgLogout->Token, msgLogout->Token + 32);
       int reset_token_result = ResetToken(token);

      // 3. response API ???
       LogInState_t login_state = (reset_token_result == 0) ? (LogInState_t)SUCCESS : (LogInState_t)reset_token_result;
       SendLogoutResponse(login_state, HMACKey);
       }
      break;

      default:
       printf("Invalid Message Type\n");
      break; 
    }
  }
   isConnected=false;
   NetworkThreadID=-1; // Temp Fix OS probem determining if thread id are valid
   printf("Network Thread Exit\n");
   return NULL;
 }
//------------------------------------------------------------------------------------------------
// END static void *NetworkInputThread
//------------------------------------------------------------------------------------------------
//----------------------------------------------------------------
// Setup_Control_C_Signal_Handler_And_Keyboard_No_Enter - This 
// sets uo the Control-c Handler and put the keyboard in a mode
// where it will not
// 1. echo input
// 2. need enter hit to get a character 
// 3. block waiting for input
//-----------------------------------------------------------------
static void Setup_Control_C_Signal_Handler_And_Keyboard_No_Enter(void)
{
 struct sigaction sigIntHandler;
 sigIntHandler.sa_handler = Control_C_Handler; // Setup control-c callback 
 sigemptyset(&sigIntHandler.sa_mask);
 sigIntHandler.sa_flags = 0;
 sigaction(SIGINT, &sigIntHandler, NULL);
 ConfigKeyboardNoEnterBlockEcho();             // set keyboard configuration
}
//-----------------------------------------------------------------
// END Setup_Control_C_Signal_Handler_And_Keyboard_No_Enter
//-----------------------------------------------------------------
//----------------------------------------------------------------
// CleanUp - Performs cleanup processing before exiting the
// the program
//-----------------------------------------------------------------
static void CleanUp(void)
{
 void *res;
 int s;
 
RestoreKeyboard();                // restore Keyboard
 if (NetworkThreadID!=-1)
  {
   //printf("Cancel Network Thread\n");
   s = pthread_cancel(NetworkThreadID);
   if (s!=0)  printf("Network Thread Cancel Failure\n");
 
   //printf("Network Thread Join\n"); 
   s = pthread_join(NetworkThreadID, &res);
   if (s != 0)   printf("Network Thread Join Failure\n"); 

   if (res == PTHREAD_CANCELED)
       printf("Network Thread canceled\n"); 
   else
       printf("Network Thread was not canceled\n"); 
 }
 if (EngagementThreadID!=-1)
  {
   //printf("Cancel Engagement Thread\n");
   s = pthread_cancel(EngagementThreadID);
   if (s!=0)  printf("Engagement Thread Cancel Failure\n");
 
   //printf("Engagement Thread Join\n"); 
   s = pthread_join(EngagementThreadID, &res);
   if (s != 0)   printf("Engagement  Thread Join Failure\n"); 

   if (res == PTHREAD_CANCELED)
       printf("Engagement Thread canceled\n"); 
   else
       printf("Engagement Thread was not canceled\n"); 
 }

 CloseCamera();
 CloseServos();
 
 laser(false);
 fire(false);
 calibrate(false);
 CloseGPIO();

 CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
 
 if (HaveOLED) ssd1306_end();
 printf("CleanUp Complete\n");
}
//-----------------------------------------------------------------
// END CleanUp
//-----------------------------------------------------------------
//----------------------------------------------------------------
// Control_C_Handler - called when control-c pressed
//-----------------------------------------------------------------
static void Control_C_Handler(int s)
{
 printf("Caught signal %d\n",s);
 CleanUp();
 printf("Exiting\n");
 exit(1);
}
//-----------------------------------------------------------------
// END Control_C_Handler
//-----------------------------------------------------------------
//----------------------------------------------------------------
// HandleInputChar - check if keys are press and proccess keys of
// interest.
//-----------------------------------------------------------------
static void HandleInputChar( Mat &frame)
{
 int ch;
 static unsigned int ImageCount=0;

  if ((ch=getchar())!=EOF) 
  {
   if  (ch=='s')
    {
      char String[1024];
      ImageCount++;
      snprintf(String,sizeof(String),"images/Capture%d.jpg",ImageCount);
      imwrite(String, frame);
      printf("saved %s\n", String);
    }

  }
}
//-----------------------------------------------------------------
// END HandleInputChar
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------

