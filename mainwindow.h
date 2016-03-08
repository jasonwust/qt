#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QList>
#include <QTreeWidgetItem>
#include <QTimer>
#include <QObject>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "sniffer.h"
#include "capturethread.h"
#include "debug.h"
#include <QList>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QFileDialog>


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
private slots:
    void updateTreeWidget(Model *);
    void on_device_currentIndexChanged(QString text);

    void on_start_clicked();

    void on_pause_clicked();

    void on_stop_clicked();

    void on_clear_clicked();

    void on_details_itemClicked(QTreeWidgetItem *item, int column);

    void on_potocol_currentIndexChanged(const QString &arg1);

    void on_filter_stateChanged(int arg1);

    void on_actionSave_records_s_triggered(bool checked);

private:
    Ui::MainWindow *ui;
    Sniffer *sniffer=NULL;
    CaptureThread *thread=NULL;
    QList<Model *> *models;
    QStandardItemModel *topModel;
    int count;
protected :
    void showTcp(QTreeWidgetItem *item);
    void showUdp(QTreeWidgetItem *item);
    void showIp(QTreeWidgetItem *item);
    void showIcmp(QTreeWidgetItem *item);
    void showHttp(QTreeWidgetItem *item);
};

#endif // MAINWINDOW_H
