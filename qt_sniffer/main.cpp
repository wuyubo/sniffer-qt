#include <QApplication>
#include "mainwindow.h"

/******************主函数*******************/
int main(int argc, char  *argv[])
{
    QApplication app(argc, argv);
    MainWindow mw;
    mw.show();

    return app.exec();
}
