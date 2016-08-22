#include "sniff.h"

Sniff::Sniff(QObject *parent) :
    QThread(parent)
{
   // list_lw = _list;
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //设置网卡为混杂模式
    strncpy(ethreq.ifr_name,"eth0",IFNAMSIZ);
    ioctl(sock,SIOCGIFFLAGS,&ethreq);
    ethreq.ifr_flags|=IFF_PROMISC;
    ioctl(sock,SIOCSIFFLAGS,&ethreq);

    state = STOP;
    filter = ALL;
}

void Sniff::run()
{
    QString path ="";
    QString msg = "sniff...";
    int i=0;
    while(1)
    {
        if(state == START)
        {
            //清空缓存
            bzero(data_li[i], 2048);
            //开始抓包
           n = recvfrom(sock,data_li[i],2048,0,NULL,NULL);
           mheader = (struct MacHeader *) data_li[i];
           ipheader = (struct IpHeader *)( data_li[i] + 14);
           //只抓IP 数据包
           if(mheader->type != 8)   continue;
           //过滤器
           if(ipheader->protocol != filter && filter != ALL) continue;
           //显示源ip和目的ip
           path.append(QString("%1: %2.%3.%4.%5->").arg(getProtocol(ipheader->protocol))
                       .arg(QString::number((int)ipheader->source_ip[0]))
                       .arg(QString::number((int)ipheader->source_ip[1]))
                       .arg(QString::number((int)ipheader->source_ip[2]))
                       .arg(QString::number((int)ipheader->source_ip[3])));
           path.append(QString("%1.%2.%3.%4").arg(QString::number((int)ipheader->dest_ip[0]))
                       .arg(QString::number((int)ipheader->dest_ip[1]))
                       .arg(QString::number((int)ipheader->dest_ip[2]))
                       .arg(QString::number((int)ipheader->dest_ip[3])));
           //获当前时间
           QDateTime current_date_time = QDateTime::currentDateTime();
           QString current_date = current_date_time.toString(" hh:mm:ss yyyy-MM-dd");
           //显示数据包类型+抓取时间
           path.append(QString("\t  (%1)").arg(current_date));
           //显示
           if(i == 0)   list_lw->clear();
           list_lw->addItem(path);
           path.clear();

           /*由于接收双字节的顺序网络序的，需要调整过来*/
           ipheader->tatol_len = (ipheader->tatol_len>>8) + (ipheader->tatol_len<<8);
           ipheader->ident = (ipheader->ident>>8) + (ipheader->ident<<8);
           ipheader->flag_frag = (ipheader->flag_frag>>8) + (ipheader->flag_frag<<8);
           ipheader->check_sum = (ipheader->check_sum>>8) + (ipheader->check_sum<<8);

           struct IcmpHeader *icmpheader = (struct IcmpHeader *)(data_li[i]+14+ipheader->header_len*4);
           struct TcpHeader *tcpheader = (struct TcpHeader *)(data_li[i]+14+ipheader->header_len*4);
           struct UdpHeader *udpheader = (struct UdpHeader *)(data_li[i]+14+ipheader->header_len*4);
           switch(ipheader->protocol)
           {
                case ICMP:
                    /*由于接收双字节的网络序的，需要调整过来*/
                    icmpheader->check_sum = (icmpheader->check_sum>>8) + (icmpheader->check_sum<<8);
                    icmpheader->id = (icmpheader->id>>8) + (icmpheader->id<<8);
                    icmpheader->seq = (icmpheader->seq>>8) + (icmpheader->seq<<8);
                    break;
                case TCP:

                    /*由于接收双字节的网络序的，需要调整过来*/
                    tcpheader->source_port = (tcpheader->source_port>>8) + (tcpheader->source_port<<8);
                    tcpheader->dest_port = (tcpheader->dest_port>>8) + (tcpheader->dest_port<<8);
                    tcpheader->window = (tcpheader->window>>8) + (tcpheader->window<<8);
                    tcpheader->check_sum = (tcpheader->check_sum>>8) + (tcpheader->check_sum<<8);
                    tcpheader->send_num = (tcpheader->send_num>>24) + ((tcpheader->send_num>>8)&0x00ff00)
                                        + ((tcpheader->send_num<<8)&0x00ff0000) + (tcpheader->send_num<<24);
                    tcpheader->recv_num = (tcpheader->recv_num>>24) + ((tcpheader->recv_num>>8)&0x00ff00)
                                        + ((tcpheader->recv_num<<8)&0x00ff0000) + (tcpheader->recv_num<<24);
                    //cout<<"tcp"<<endl;
                    break;
                case UDP:

                    /*由于接收双字节的是网络序的，需要调整过来*/
                    udpheader->source_port = (udpheader->source_port>>8) + (udpheader->source_port<<8);
                    udpheader->dest_port = (udpheader->dest_port>>8) + (udpheader->dest_port<<8);
                    udpheader->len = (udpheader->len>>8) + (udpheader->len<<8);
                    udpheader->check_sum = (udpheader->check_sum>>8) + (udpheader->check_sum<<8);
                    //cout<<"udp"<<endl;
           }
           i++;
           //超最大抓取数，清0
           if(i >= MAXDATAGRAM)
           {
               i = 0;
               msg = "sniff..";
           }
           msg.append(".");
           load_lb->setText(msg);
        }
        else {
            sleep(1);
        }
    }
}

//把类型转成字符串
QString Sniff::getProtocol(int protocol)
{
    switch(protocol)
    {
        case ICMP:
            return "ICMP";
            break;
        case TCP:
            return "TCP";
            break;
        case UDP:
            return "UDP";
    }
    return "UNKNOW";
}

//设置显示控件
void Sniff::setW(QListWidget *_list_lw, QLabel *_load_lb)
{
    list_lw = _list_lw;
    load_lb = _load_lb;
}
//允许抓取
void Sniff::startsniff(int _filter)
{
    setFilter(_filter);
    state = START;
    load_lb->setText("sniff...");
}
//停止抓取
void Sniff::stop()
{
    state = STOP;
    load_lb->setText("stop");
}
//设置过滤器
void Sniff::setFilter(int _filter)
{
    filter = _filter;
}








