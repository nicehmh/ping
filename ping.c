#include<stdio.h>
#include<Winsock2.h>
#include<ws2tcpip.h>
#include<stdlib.h>
#include<malloc.h>
#include<string.h>
#pragma comment("WS2_32.lib")
#define DEF_ICMP_TIMEOUT 3000  //���峬ʱΪ3��
#define ICMP_ECHO_REQUEST 8 //���������������
#define DEF_ICMP_DATA_SIZE 20 //���巢�����ݳ���
#define DEF_ICMP_PACK_SIZE 32 //�������ݰ�����
#define MAX_ICMP_PACKET_SIZE 1024 //����������ݰ�����
#define ICMP_ECHO_REPLY 0 //�������Ӧ������

/*
 *IP��ͷ�ṹ
 */
typedef struct
{
    byte h_len_ver ; //IP�汾��
    byte tos ; // ��������
    unsigned short total_len ; //IP���ܳ���
    unsigned short ident ; // ��ʶ
    unsigned short frag_and_flags ; //��־λ
    byte ttl ; //����ʱ��
    byte proto ; //Э��
    unsigned short cksum ; //IP�ײ�У���
    unsigned long sourceIP ; //ԴIP��ַ
    unsigned long destIP ; //Ŀ��IP��ַ
} IP_HEADER ;
/*
 *����ICMP��������
 */
typedef struct
{
    byte type ; //����-----8
    byte code ; //����-----8
    unsigned short cksum ; //У���------16
    unsigned short id ; //��ʶ��-------16
    unsigned short seq ; //���к�------16
    unsigned int choose ; //ѡ��-------32
} ICMP_HEADER ;
typedef struct
{
    int usSeqNo ; //��¼���к�
    DWORD dwRoundTripTime ; //��¼��ǰʱ��
    byte ttl ; //����ʱ��
    IN_ADDR dwIPaddr ; //ԴIP��ַ
} DECODE_RESULT ;

//�������в���ת��Ϊip��ַ
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
//��������У���
unsigned short GenerateChecksum(unsigned short *pBuf,int iSize){
   unsigned long cksum=0;
   while(iSize>1){
     cksum+=*pBuf++;//����У�������ÿ16λ��λ��ӱ�����cksum��
     iSize-=sizeof(unsigned short);//ÿ16λ�����򽫴�У����������16
   }
   //
   if(iSize){
       cksum+=*(unsigned char *)pBuf;
   }
   cksum=(cksum>>16)+(cksum&0xffff);
   cksum+=(cksum>>16);

   return (unsigned short)(~cksum);
}

//����Ӧ����Ϣ
int DecodeIcmpResponse(char *pBuf,int iPacketSize,DECODE_RESULT *stDecodeResult)

{
    //��ȡ�յ���IP���ݰ����ײ���Ϣ
   IP_HEADER *pIpHrd=(IP_HEADER *)pBuf;
   int iIpHrdLen=20;
   if(iPacketSize<(int)(iIpHrdLen+sizeof(ICMP_HEADER))){
      return 0;
   }
   //ָ��ָ��ICMP���ĵ��׵�ַ
   ICMP_HEADER *pIcmpHrd=(ICMP_HEADER *)(pBuf+iIpHrdLen);

   unsigned short usID,usSquNo;
   //��ȡ�����ݰ���type�ֶ�ΪICMP_ECHO_REPLY,���ܵ�һ������Ӧ��ı���
   if(pIcmpHrd->type==ICMP_ECHO_REPLY){
      usID=pIcmpHrd->id;
      //���ܵ����������ֽ�˳���seq�ֶ���Ϣ����Ҫת�������ֽ�˳��
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

//���Ŀ�ĵ�socket
int CreateSocket(unsigned long ulDestIP){
    //���Ŀ�ĵ�socket
   SOCKADDR_IN destSockAddr;
   ZeroMemory(&destSockAddr,sizeof(SOCKADDR_IN));
   destSockAddr.sin_family=AF_INET;
   destSockAddr.sin_addr.s_addr=ulDestIP;
   destSockAddr.sin_port = htons(0);

   //��ʼ��WinSock
    WORD wVersionRequested = MAKEWORD(2,2);
    WSADATA wsaData;
    if(WSAStartup(wVersionRequested,&wsaData) != 0)
    {
        printf("��ʼ��WinSockʧ�ܣ�\n") ;
        return ;
    }
//ʹ��ICMPЭ�鴴��Raw Socket
   SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if(sockRaw == INVALID_SOCKET)
   {
       printf("WSASocket() failed: %d\n", WSAGetLastError());
       return ;
   }
   //���ö˿�����
   int iTimeout=DEF_ICMP_TIMEOUT;
   if(setsockopt(sockRaw,SOL_SOCKET, SO_RCVTIMEO,(char *)&iTimeout,sizeof(iTimeout))==SOCKET_ERROR){
      printf("����SO_RCVTIMEOʧ��\n");
   }
   if(setsockopt(sockRaw,SOL_SOCKET, SO_SNDTIMEO,(char *)&iTimeout,sizeof(iTimeout))==SOCKET_ERROR){
      printf("����SO_SNDTIMEOʧ��\n");
   }

    //���巢�͵����ݶ�
   char IcmpSendBuf[DEF_ICMP_PACK_SIZE] ;
   //���ICMP���ݰ����ֶ�
   ICMP_HEADER * pIcmpHeader=(ICMP_HEADER *)IcmpSendBuf;
   pIcmpHeader->type=ICMP_ECHO_REQUEST;
   pIcmpHeader->code=0;
   pIcmpHeader->id=(unsigned short)GetCurrentProcessId();
   memset(IcmpSendBuf+sizeof(ICMP_HEADER),'E',DEF_ICMP_DATA_SIZE);

   //ѭ������3���������icmp���ݰ�
   DECODE_RESULT stDecodeResult;
   int usSeqNo;
   for(usSeqNo=0;usSeqNo<=3;usSeqNo++){
      pIcmpHeader->seq=htons(usSeqNo);
      pIcmpHeader->cksum=0;
      pIcmpHeader->cksum=GenerateChecksum((unsigned short *)IcmpSendBuf,sizeof(ICMP_HEADER)+DEF_ICMP_DATA_SIZE);

      //��¼���кź͵�ǰʱ��
      stDecodeResult.usSeqNo=usSeqNo;
      stDecodeResult.dwRoundTripTime=GetTickCount();
      //����ICMP��EchoRequest���ݰ�
      if(sendto(sockRaw,IcmpSendBuf,sizeof(IcmpSendBuf),0,(SOCKADDR*)&destSockAddr,sizeof(destSockAddr))==SOCKET_ERROR){
         //����������ɴ���ֱ���˳�
         if(WSAGetLastError()==WSAEHOSTUNREACH){
              return 0;
         }
      }
      SOCKADDR_IN from;
      int iFromLen=sizeof(from);
      int iReadLen;
       //������յ����ݰ�
      char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE] ;
      while(1){
        iReadLen=recvfrom(sockRaw,IcmpRecvBuf,MAX_ICMP_PACKET_SIZE,0,(SOCKADDR*)&from,&iFromLen);
        if(iReadLen!=SOCKET_ERROR){//��ȷ���ܵ�һ��ICMP����
             if(DecodeIcmpResponse(IcmpRecvBuf , sizeof(IcmpRecvBuf) , &stDecodeResult)==1)
             {
                printf("���� %s �Ļظ�: �ֽ� = %d ʱ�� = %dms TTL = %d\n" , inet_ntoa(stDecodeResult.dwIPaddr) ,
                         iReadLen - 20,stDecodeResult.dwRoundTripTime ,stDecodeResult.ttl) ;
             }
             break ;
        }else if(WSAGetLastError()==WSAETIMEDOUT){//���ܳ�ʱ
              printf("time out !  *****\n") ;
              break ;
        }else{
             printf("����δ֪����\n") ;
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
    unsigned long ulDestIP;//ip��ַ
    if(argv[1]!=NULL){
       ulDestIP=GetIp(argv[1]);
    }else{
       printf("������ip��ַ��");
       scanf("%s",arr);
       ulDestIP=GetIp(arr);
    }
    CreateSocket(ulDestIP);
}
