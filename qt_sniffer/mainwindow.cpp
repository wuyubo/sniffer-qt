#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    //启动抓取线程
    msniff = new Sniff();
    msniff->setW(ui->listWidget_list, ui->label_load);
    msniff->start();
}

MainWindow::~MainWindow()
{
    delete ui;
}
//设置过滤
int MainWindow::check_filter(QString qf)
{
    if(qf == "ALL") return ALL;
    if(qf == "ICMP") return ICMP;
    if(qf == "TCP")  return TCP;
    if(qf == "UDP") return UDP;
    return ALL;
}

//开始
void MainWindow::on_pushButton_start_clicked()
{
    int filter = ALL;
    filter = check_filter(ui->comboBox_filter->currentText());
    msniff->startsniff(filter);
}

//停止
void MainWindow::on_pushButton_stop_clicked()
{
    msniff->stop();
}

//显示数据
void MainWindow::on_listWidget_list_doubleClicked(const QModelIndex &index)
{
    int i = index.row();
    char c_data[2048];
    char *p = c_data;
    ui->listWidget_show->clear();
    p = msniff->data_li[i];
    showMac((struct MacHeader *) p);
    struct IpHeader *ipheader = (struct IpHeader *)( p + 14);
    showIP(ipheader);

    switch (ipheader->protocol) {
    case ICMP:
        showIcmp((struct IcmpHeader *)(p+14+ipheader->header_len*4));
        break;
    case TCP:
        showTcp((struct TcpHeader *)(p+14+ipheader->header_len*4));
        break;
    case UDP:
        showUdp((struct UdpHeader *)(p+14+ipheader->header_len*4));
        break;
    default:
        break;
    }
}

//显示MAC首部
void MainWindow::showMac(MacHeader *mheader)
{
    QString temp;
    ui->listWidget_show->addItem("****************** DLC HEADER **********************");
    temp.append(QString("源 MAC 地址: %1-%2-%3-%4-%5-%6")
                .arg(QString::number((int)(mheader->source_adr[0]),16))
                .arg(QString::number((int)(mheader->source_adr[1]),16))
                .arg(QString::number((int)(mheader->source_adr[2]),16))
                .arg(QString::number((int)(mheader->source_adr[3]),16))
                .arg(QString::number((int)(mheader->source_adr[4]),16))
                .arg(QString::number((int)(mheader->source_adr[5]),16)));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("目的MAC地址: %1-%2-%3-%4-%5-%6")
                .arg(QString::number((int)mheader->dest_adr[0],16))
                .arg(QString::number((int)mheader->dest_adr[1],16))
                .arg(QString::number((int)mheader->dest_adr[2],16))
                .arg(QString::number((int)mheader->dest_adr[3],16))
                .arg(QString::number((int)mheader->dest_adr[4],16))
                .arg(QString::number((int)mheader->dest_adr[5],16)));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp = "类型：";
    temp.append(QString::number((int)(mheader->type)));
    ui->listWidget_show->addItem(temp);
    temp.clear();
}

//显示IP首部
void MainWindow::showIP(struct IpHeader *ipheader)
{
    QString temp;
    ui->listWidget_show->addItem("****************** IP HEADER  **********************");

    temp.append(QString("版本号： %1")
                .arg(QString::number((ipheader->versoin))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("首部长度： %1")
                .arg(QString::number((ipheader->header_len*4))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("区分服务： %1")
                .arg(QString::number((ipheader->service))));
    ui->listWidget_show->addItem(temp);
    temp.clear();


    temp.append(QString("总长度： %1")
                .arg(QString::number((ipheader->tatol_len))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("标识: %1")
                .arg(QString::number((ipheader->ident))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("标志: %1")
                .arg(QString::number((ipheader->flag_frag>>13))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("片偏移:  %1")
                .arg(QString::number(( ipheader->flag_frag&0x1fff))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("生存时间: %1")
                .arg(QString::number(( ipheader->ttl))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("协议:  %1")
                .arg(QString::number((ipheader->protocol))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("检验和: %1")
                .arg(QString::number((ipheader->check_sum))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

    temp.append(QString("源 IP: %1.%2.%3.%4")
                .arg(QString::number((int)ipheader->source_ip[0]))
                .arg(QString::number((int)ipheader->source_ip[1]))
                .arg(QString::number((int)ipheader->source_ip[2]))
                .arg(QString::number((int)ipheader->source_ip[3])));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("目的IP: %1.%2.%3.%4")
                .arg(QString::number((int)ipheader->dest_ip[0]))
                .arg(QString::number((int)ipheader->dest_ip[1]))
                .arg(QString::number((int)ipheader->dest_ip[2]))
                .arg(QString::number((int)ipheader->dest_ip[3])));
    ui->listWidget_show->addItem(temp);
    temp.clear();
}
//显示ICMP首部
void MainWindow::showIcmp(IcmpHeader *icmpheader)
{
    QString temp;
    ui->listWidget_show->addItem("****************** ICMP HEADER  **********************");
    temp.append(QString("类型： %1")
                .arg(QString::number((icmpheader->type))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("代码： %1")
                .arg(QString::number((icmpheader->code))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((icmpheader->check_sum))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("标识符： %1")
                .arg(QString::number((icmpheader->id))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("序列号： %1")
                .arg(QString::number((icmpheader->seq))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
}
//显示TCP首部
void MainWindow::showTcp(TcpHeader *tcpheader)
{
    QString temp;
    ui->listWidget_show->addItem("****************** TCP HEADER  **********************");
    temp.append(QString("源端口： %1")
                .arg(QString::number((tcpheader->source_port))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("目的端口： %1")
                .arg(QString::number((tcpheader->dest_port))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("序号： %1")
                .arg(QString::number((tcpheader->send_num))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("确认号： %1")
                .arg(QString::number((tcpheader->recv_num))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("数据偏移： %1")
                .arg(QString::number((tcpheader->offset*4))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("标志位：  URG:%1 ACK:%2 PSH:%3 RET:%4 SYN:%5 FIN:%6")
                .arg(QString::number((int)(tcpheader->flag>>5)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>4)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>3&0x01)))
                .arg(QString::number((int)(tcpheader->flag>>2)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>1)&0x01))
                .arg(QString::number((int)(tcpheader->flag>>0)&0x01)));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("窗口： %1")
                .arg(QString::number((tcpheader->window))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((tcpheader->check_sum))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
}
//显示UDP首部
void MainWindow::showUdp(UdpHeader *udpheader)
{
    QString temp;
    ui->listWidget_show->addItem("****************** UDP HEADER  **********************");
    temp.append(QString("源端口： %1")
                .arg(QString::number((udpheader->source_port))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("目的端口： %1")
                .arg(QString::number((udpheader->dest_port))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("长度： %1")
                .arg(QString::number((udpheader->len))));
    ui->listWidget_show->addItem(temp);
    temp.clear();
    temp.append(QString("检验和： %1")
                .arg(QString::number((udpheader->check_sum))));
    ui->listWidget_show->addItem(temp);
    temp.clear();

}


