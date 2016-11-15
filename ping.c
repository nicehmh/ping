#include<stdio.h>
#include<Winsock2.h>
#include<ws2tcpip.h>
#include<stdlib.h>
#include<malloc.h>
#include<string.h>
#pragma comment("WS2_32.lib")
#define DEF_ICMP_TIMEOUT 3000  //定义超时为3秒
#define ICMP_ECHO_REQUEST 8 //定义回显请求类型
#define DEF_ICMP_DATA_SIZE 20 //定义发送数据长度
#define DEF_ICMP_PACK_SIZE 32 //定义数据包长度
#define MAX_ICMP_PACKET_SIZE 1024 //定义最大数据包长度
#define ICMP_ECHO_REPLY 0 //定义回显应答类型

/*
 *IP报头结构
 */
typedef struct
{
    byte h_len_ver ; //IP版本号
    byte tos ; // 服务类型
    unsigned short total_len ; //IP包总长度
    unsigned short ident ; // 标识
    unsigned short frag_and_flags ; //标志位
    byte ttl ; //生存时间
    byte proto ; //协议
    unsigned short cksum ; //IP首部校验和
    unsigned long sourceIP ; //源IP地址
    unsigned long destIP ; //目的IP地址
} IP_HEADER ;
/*
 *定义ICMP数据类型
 */
typedef struct
{
    byte type ; //类型-----8
    byte code ; //代码-----8
    unsigned short cksum ; //校验和------16
    unsigned short id ; //标识符-------16
    unsigned short seq ; //序列号------16
    unsigned int choose ; //选项-------32
} ICMP_HEADER ;
typedef struct
{
    int usSeqNo ; //记录序列号
    DWORD dwRoundTripTime ; //记录当前时间
    byte ttl ; //生存时间
    IN_ADDR dwIPaddr ; //源IP地址
} DECODE_RESULT ;

//将命令行参数转换为ip地址
unsigned long GetIp(char *str){
   unsigned long ulDestIP=inet_addr(str);
   if(ulDestIP==INADDR_NONE){
      HOSTENT *pHostent=gethostbyname(str);
      if(pHostent){
         ulDestIP=(*(IN_ADDR*)pHostent->h_addr).s_addr;
      }
      pHostent=gethostbyname("www.baidu.com");
       if (pHostent == NULL) {
           perror("getaddrinfo");
              ulDestIP=2;
       }
   }
   return ulDestIP;
}
//产生网际校验和
unsigned short GenerateChecksum(unsigned short *pBuf,int iSize){
   unsigned long cksum=0;
   while(iSize>1){
     cksum+=*pBuf++;//将待校验的数据每16位逐位相加保存在cksum中
     iSize-=sizeof(unsigned short);//每16位加完则将带校验数据量减16
   }
   //
   if(iSize){
       cksum+=*(unsigned char *)pBuf;
   }
   cksum=(cksum>>16)+(cksum&0xffff);
   cksum+=(cksum>>16);

   return (unsigned short)(~cksum);
}

//解析应答信息
int DecodeIcmpResponse(char *pBuf,int iPacketSize,DECODE_RESULT *stDecodeResult)

{
    //获取收到的IP数据包的首部信息
   IP_HEADER *pIpHrd=(IP_HEADER *)pBuf;
   int iIpHrdLen=20;
   if(iPacketSize<(int)(iIpHrdLen+sizeof(ICMP_HEADER))){
      return 0;
   }
   //指针指向ICMP报文的首地址
   ICMP_HEADER *pIcmpHrd=(ICMP_HEADER *)(pBuf+iIpHrdLen);

   unsigned short usID,usSquNo;
   //获取的数据包的type字段为ICMP_ECHO_REPLY,即受到一个回显应答的报文
   if(pIcmpHrd->type==ICMP_ECHO_REPLY){
      usID=pIcmpHrd->id;
      //接受到的是网络字节顺序的seq字段信息，需要转成主机字节顺序
      usSquNo=ntohs(pIcmpHrd->seq);
   }
   if(usID!=GetCurrentProcessId()||usSquNo!=stDecodeResult->usSeqNo){
     return 0;
   }
   if(pIcmpHrd->type==ICMP_ECHO_REPLY){
       stDecodeResult->ttl=pIpHrd->ttl;
       stDecodeResult->dwIPaddr.s_addr=pIpHrd->sourceIP;
       stDecodeResult->dwRoundTripTime=GetTickCount()-stDecodeResult->dwRoundTripTime;
       return 1;
   }
   return 0;
}

//填充目的的socket
int CreateSocket(unsigned long ulDestIP){
    //填充目的的socket
   SOCKADDR_IN destSockAddr;
   ZeroMemory(&destSockAddr,sizeof(SOCKADDR_IN));
   destSockAddr.sin_family=AF_INET;
   destSockAddr.sin_addr.s_addr=ulDestIP;
   destSockAddr.sin_port = htons(0);

   //初始化WinSock
    WORD wVersionRequested = MAKEWORD(2,2);
    WSADATA wsaData;
    if(WSAStartup(wVersionRequested,&wsaData) != 0)
    {
        printf("初始化WinSock失败！\n") ;
        return ;
    }
//使用ICMP协议创建Raw Socket
   SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if(sockRaw == INVALID_SOCKET)
   {
       printf("WSASocket() failed: %d\n", WSAGetLastError());
       return ;
   }
   //设置端口属性
   int iTimeout=DEF_ICMP_TIMEOUT;
   if(setsockopt(sockRaw,SOL_SOCKET, SO_RCVTIMEO,(char *)&iTimeout,sizeof(iTimeout))==SOCKET_ERROR){
      printf("设置SO_RCVTIMEO失败\n");
   }
   if(setsockopt(sockRaw,SOL_SOCKET, SO_SNDTIMEO,(char *)&iTimeout,sizeof(iTimeout))==SOCKET_ERROR){
      printf("设置SO_SNDTIMEO失败\n");
   }

    //定义发送的数据段
   char IcmpSendBuf[DEF_ICMP_PACK_SIZE] ;
   //填充ICMP数据包各字段
   ICMP_HEADER * pIcmpHeader=(ICMP_HEADER *)IcmpSendBuf;
   pIcmpHeader->type=ICMP_ECHO_REQUEST;
   pIcmpHeader->code=0;
   pIcmpHeader->id=(unsigned short)GetCurrentProcessId();
   memset(IcmpSendBuf+sizeof(ICMP_HEADER),'E',DEF_ICMP_DATA_SIZE);

   //循环发送3个请求回显icmp数据包
   DECODE_RESULT stDecodeResult;
   int usSeqNo;
   for(usSeqNo=0;usSeqNo<=3;usSeqNo++){
      pIcmpHeader->seq=htons(usSeqNo);
      pIcmpHeader->cksum=0;
      pIcmpHeader->cksum=GenerateChecksum((unsigned short *)IcmpSendBuf,sizeof(ICMP_HEADER)+DEF_ICMP_DATA_SIZE);

      //记录序列号和当前时间
      stDecodeResult.usSeqNo=usSeqNo;
      stDecodeResult.dwRoundTripTime=GetTickCount();
      //发送ICMP的EchoRequest数据包
      if(sendto(sockRaw,IcmpSendBuf,sizeof(IcmpSendBuf),0,(SOCKADDR*)&destSockAddr,sizeof(destSockAddr))==SOCKET_ERROR){
         //如果主机不可达则直接退出
         if(WSAGetLastError()==WSAEHOSTUNREACH){
              return 0;
         }
      }
      SOCKADDR_IN from;
      int iFromLen=sizeof(from);
      int iReadLen;
       //定义接收的数据包
      char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE] ;
      while(1){
        iReadLen=recvfrom(sockRaw,IcmpRecvBuf,MAX_ICMP_PACKET_SIZE,0,(SOCKADDR*)&from,&iFromLen);
        if(iReadLen!=SOCKET_ERROR){//正确接受到一个ICMP报文
             if(DecodeIcmpResponse(IcmpRecvBuf , sizeof(IcmpRecvBuf) , &stDecodeResult)==1)
             {
                printf("来自 %s 的回复: 字节 = %d 时间 = %dms TTL = %d\n" , inet_ntoa(stDecodeResult.dwIPaddr) ,
                         iReadLen - 20,stDecodeResult.dwRoundTripTime ,stDecodeResult.ttl) ;
             }
             break ;
        }else if(WSAGetLastError()==WSAETIMEDOUT){//接受超时
              printf("time out !  *****\n") ;
              break ;
        }else{
             printf("发生未知错误！\n") ;
             break ;
        }
      }
   }
   printf("\nping complete.\n");
   closesocket(sockRaw);
   WSACleanup();
   return 0;
}
int main(int argc,char *argv[]){
    char *arr=(char *)malloc(sizeof(char));
    unsigned long ulDestIP;//ip地址
    if(argv[1]!=NULL){
       ulDestIP=GetIp(argv[1]);
    }else{
       printf("请输入ip地址：");
       scanf("%s",arr);
       ulDestIP=GetIp(arr);
    }
    CreateSocket(ulDestIP);
}
