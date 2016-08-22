#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sniff.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void showMac(struct MacHeader *mheader);
    void showIP(struct IpHeader *ipheader);
    void showIcmp(IcmpHeader *icmpheader);
    void showTcp(struct TcpHeader *tcpheader);
    void showUdp(struct UdpHeader *udpheader);
    int check_filter(QString qf);
private slots:
    void on_pushButton_start_clicked();

    void on_pushButton_stop_clicked();

    void on_listWidget_list_doubleClicked(const QModelIndex &index);

private:
    Ui::MainWindow *ui;
    Sniff *msniff;
};

#endif // MAINWINDOW_H
