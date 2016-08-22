#ifndef SNIFF_H
#define SNIFF_H

#include <QThread>
#include <iostream>
#include <QtWidgets/QListWidget>
#include <QLabel>
#include <QDateTime>
using namespace std;
extern "C"
{
    #include <sys/socket.h>
    #include <linux/if_ether.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <arpa/inet.h>
}
#define START 1
#define STOP  0
#define MAXDATAGRAM 50

enum Protocol{ALL = 0,ICMP=1,IGMP=2, IP=4, TCP=6, UDP=17};


// MAC 帧头结构
struct MacHeader
{
        unsigned char 	dest_adr[6];	//目的地址
        unsigned char 	source_adr[6];	//源地址
        unsigned short	type;			//类型
};

// IP数据包头结构
struct IpHeader
{
    unsigned int 	header_len:4;		//首部长度
    unsigned int 	versoin:4;			//版本号
    unsigned char 	service;			//区分服务
    unsigned short 	tatol_len;			//总长度      （需要进行字节调整）
    unsigned short 	ident;				//标识		  （需要进行字节调整）
    unsigned short 	flag_frag;			//标志与片偏移（需要进行字节调整）
    unsigned char 	ttl;				//生存时间
    unsigned char 	protocol;			//协议
    unsigned short 	check_sum;			//检验和	  （需要进行字节调整）
    unsigned char 	source_ip[4];		//源地址
    unsigned char 	dest_ip[4];			//目的地址
};

// ICMP数据头结构
struct IcmpHeader
{
    unsigned char type;       	//类型
    unsigned char code;			//代码
    unsigned short check_sum;	//检验和    （需要进行字节调整）
    unsigned short id;			//标识符 	（需要进行字节调整）
    unsigned short seq;			//序列号	（需要进行字节调整）
    //unsigned long  timestamp;	//当前时间

};


struct UdpHeader
{
    unsigned short source_port;			//源端口		（需要进行字节调整）
    unsigned short dest_port;			//目的端口		（需要进行字节调整）
    unsigned short len;					//udp总长度		（需要进行字节调整）
    unsigned short check_sum;			//检验和		（需要进行字节调整）
};

struct TcpHeader
{
    unsigned short source_port;			//源端口		（需要进行字节调整）
    unsigned short dest_port;			//目的端口		（需要进行字节调整）
    unsigned int   send_num;
    unsigned int   recv_num;

    unsigned char  reserved1:4;
    unsigned char  offset:4;

    unsigned char  flag:6;
    unsigned char  reserved2:2;

    unsigned short window;
    unsigned short check_sum;
    unsigned short urg_pointer;
};



class Sniff : public QThread
{
    Q_OBJECT
public:
    explicit Sniff(QObject *parent = 0);
    void setW(QListWidget *_list_lw, QLabel *_load_lb);
    void run();
    void startsniff(int _filter);
    void stop();
    char data_li[MAXDATAGRAM][2048];
    void setFilter(int _filter);
    QString getProtocol(int protocol);

signals:

public slots:

private:
    int sock;
    struct ifreq ethreq;
    int n;
    struct MacHeader *mheader;
    struct IpHeader *ipheader;
    int state;
    int filter;

    QListWidget *list_lw;
    QLabel *load_lb;

};

#endif // SNIFF_H
