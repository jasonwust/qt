#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->mainToolBar->setVisible(false);
    sniffer = new Sniffer(NULL);
    QStringList list;
    sniffer->getAllDevicesName(list);
    foreach(QString str,list){
       ui->device->addItem(str);
    }
    ui->details->setDragEnabled(false);
    models = new QList<Model *>;
    count=0;
    topModel = new QStandardItemModel();
    topModel->setHorizontalHeaderItem(0,new QStandardItem(""));
    ui->moredetails->setModel(topModel);
    sniffer->openDevice();
    connect((QObject *)sniffer,SIGNAL(getPacket(Model*)),this,SLOT(updateTreeWidget(Model *)));

}
void MainWindow::updateTreeWidget(Model *model)
{

    QTreeWidgetItem *item = new QTreeWidgetItem;
    item->setText(0,QString::number(++count));
    item->setText(1,model->getTime());
    u_char * packet = model->getPacket();
    MACHEADER *mac = (MACHEADER *)packet;
   if(mac->type == htons(IP))
   {
        packet += sizeof(MACHEADER);
        IPHEADER *ip = (IPHEADER *)(packet);
        item->setText(2,QString::fromLatin1(inet_ntoa(ip->saddr)));
        item->setText(3,QString::fromLatin1(inet_ntoa(ip->daddr)));
        if(ip->proto == TCP)
        {
            item->setText(4,"tcp");
            packet += ip->len*4;
            tcphdr * tcp = (tcphdr*)packet;
            item->setText(5,QString::number(ntohs(tcp->source)));
            item->setText(6,QString::number(ntohs(tcp->dest)));
            packet += tcp->doff*4;
            int len = model->getPacketLen() - ip->len*4 - tcp->doff*4 -sizeof(MACHEADER);
            for(int i=0;i<len;i++){
                if(packet[i]=='\r'&& packet[i+1]=='\n'){
                    QString str = QString::fromLatin1((char *)packet,i);
                    if(str.contains("HTTP")){
                        item->setText(4,"http");
                    }
                    break;
                }

            }

        }
        else if(ip->proto == UDP)
        {
           item->setText(4,"udp");
           udphdr * udp = (udphdr*)packet;
           item->setText(5,QString::number(ntohs(udp->uh_sport)));
           item->setText(6,QString::number(ntohs(udp->uh_dport)));
        }
        else if(ip->proto == ICMP)
        {
            item->setText(4,"icmp");
        }
        else{
            item->setText(4,"ip");
        }
   }
   else if(mac->type==htons(ARP))
   {
        item->setText(4,"arp");
   }
   else if(mac->type== htons(RARP))
   {
        item->setText(4,"rarp");
   }

   ui->details->addTopLevelItem(item);
   models->append(model);


}
MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_device_currentIndexChanged(QString text)
{
    sniffer->openDevice(text.toStdString().c_str());
}

void MainWindow::on_start_clicked()
{
    if(thread==NULL){
        thread = new CaptureThread(sniffer);
    }
    thread->start();
}

void MainWindow::on_pause_clicked()
{

    if(thread!=NULL && thread->isRunning())
    {
        sniffer->pausePacket();
        thread->quit();
    }

}

void MainWindow::on_stop_clicked()
{
    sniffer->closeDevice();
}

void MainWindow::on_clear_clicked()
{
    ui->details->clear();
    count=0;
}

void MainWindow::on_details_itemClicked(QTreeWidgetItem *item, int column)
{
   topModel->clear();
   QStandardItem *tem = new QStandardItem("source packet data");
   QString str;
   Model *model = models->at(item->text(0).toInt()-1);
   u_char * packet = model->getPacket();
   for(int i=0;i<model->getPacketLen();i++){
       QString str1;
       str+=str1.sprintf("%.2x ",packet[i]);
       if(i%60==0 && i!=0)
       {
           str+="\n";
       }
   }
   str+="\n";
   tem->appendRow(new QStandardItem(str));
   topModel->appendRow(tem);

   if(item->text(4) == "ip"){
       showIp(item);
   }
   else if(item->text(4) == "tcp"){
       showTcp(item);
   }
   else if(item->text(4) == "icmp"){
       showIcmp(item);
   }
   else if(item->text(4).compare("http")==0){
       showHttp(item);
   }else if(item->text(4) == "udp"){
       showUdp(item);
   }

}
void MainWindow::showIp(QTreeWidgetItem *item)
{
    DEBUG("ip call");
    Model *model = models->at(item->text(0).toInt()-1);
    u_char * packet = model->getPacket();
    packet += sizeof(MACHEADER);
    IPHEADER * ip = (IPHEADER *)packet;
    QString str;
    QStandardItem * topItem = new QStandardItem("Internet Protocol,src "+item->text(2)+",dst "+item->text(3));
    topItem->appendRow(new QStandardItem(str.sprintf("Version:  %d\n",ip->version)));
    topItem->appendRow(new QStandardItem(str.sprintf("Header Length:  %d\n",ip->len*4)));
    topItem->appendRow(new QStandardItem(str.sprintf("Serivice Field:  0x%x\n",ip->tos)));
    topItem->appendRow(new QStandardItem(str.sprintf("Total Length:  %d\n",ntohs(ip->tlen))));
    topItem->appendRow(new QStandardItem(str.sprintf("Itendification:  0x%x(%d)\n",ip->identification,ip->identification)));
    topItem->appendRow(new QStandardItem(str.sprintf("flags:  0x%x(%d)\n",ip->flags_fo&0xe0,ip->flags_fo&0xe0)));
    topItem->appendRow(new QStandardItem(str.sprintf("fragement offest:  0x%x(%d)\n",ip->flags_fo&0x1f,ip->flags_fo&0x1f)));
    topItem->appendRow(new QStandardItem(str.sprintf("time to live:  %d\n",ntohs(ip->ttl))));
    topItem->appendRow(new QStandardItem(str.sprintf("protocol:  %d(%s)\n",ip->proto,item->text(4).toStdString().c_str())));
    topItem->appendRow(new QStandardItem(str.sprintf("check sum:  %d\n",ip->crc)));
    topItem->appendRow(new QStandardItem("source:  "+item->text(2)));
    topItem->appendRow(new QStandardItem("destination:  "+item->text(3)));
    topModel->appendRow(topItem);

}
void MainWindow::showTcp(QTreeWidgetItem *item)
{
    DEBUG("tcp call");
    showIp(item);
    Model *model = models->at(item->text(0).toInt()-1);
    u_char * packet = model->getPacket();
    packet += sizeof(MACHEADER);
    IPHEADER * ip = (IPHEADER *)packet;
    packet += ip->len*4;
    tcphdr * tcp = (tcphdr*)(packet);
    QString str;
    QStandardItem * topItem = new QStandardItem("Transport Control Protocol,src port "+QString::number(ntohs(tcp->source))+",dst port "+QString::number(ntohs(tcp->dest)));
    topItem->appendRow(new QStandardItem("source port:  "+QString::number(ntohs(tcp->source))));
    topItem->appendRow(new QStandardItem("\ndestination port:  "+QString::number(ntohs(tcp->dest))));
    topItem->appendRow(new QStandardItem(str.sprintf("\nsequence number:  %u\n",ntohl(tcp->seq))));
    topItem->appendRow(new QStandardItem(str.sprintf("ack number:  %u\n",ntohl(tcp->ack_seq))));
    topItem->appendRow(new QStandardItem(str.sprintf("data offset:  %d\n",tcp->th_off)));
    QStandardItem *flagsItem = new QStandardItem(str.sprintf("flags :  0x%x\n",ntohl(tcp->th_flags)));
    if(tcp->th_flags&TH_FIN)
        flagsItem->appendRow(new QStandardItem("FIN"));
    if(tcp->th_flags&TH_SYN)
        flagsItem->appendRow(new QStandardItem("SYN"));
    if(tcp->th_flags&TH_RST)
        flagsItem->appendRow(new QStandardItem("RST"));
    if(tcp->th_flags&TH_PUSH)
        flagsItem->appendRow(new QStandardItem("PUSH"));
    if(tcp->th_flags&TH_ACK)
        flagsItem->appendRow(new QStandardItem("ACK"));
    if(tcp->th_flags&TH_URG)
        flagsItem->appendRow(new QStandardItem("URG"));
    topItem->appendRow(flagsItem);
    topItem->appendRow(new QStandardItem(str.sprintf("window :  %d",ntohs(tcp->th_win))));
    topItem->appendRow(new QStandardItem(str.sprintf("checksum:  :  %d",ntohs(tcp->th_sum))));
    topItem->appendRow(new QStandardItem(str.sprintf("urp offset :  0x%x(%d)",ntohs(tcp->th_urp),ntohs(tcp->th_urp))));
    if(item->text(4)!="http")
    {
        int len = model->getPacketLen()-sizeof(MACHEADER)-ip->len*4-tcp->doff*4;
        topItem->appendRow(new QStandardItem("data:"+QString::fromLatin1((char *)(packet+tcp->doff*4),len)));
    }
    topModel->appendRow(topItem);
}
void MainWindow::showUdp(QTreeWidgetItem *item)
{
    DEBUG("udp call");
    showIp(item);
    Model *model = models->at(item->text(0).toInt()-1);
    u_char * packet = model->getPacket();
    packet += sizeof(MACHEADER);
    IPHEADER * ip = (IPHEADER *)packet;
    packet += ip->len*4;
    udphdr * udp = (udphdr*)(packet);
    QString str;
    QStandardItem * topItem = new QStandardItem("User Datagram Protocol,src port "+QString::number(ntohs(udp->uh_sport))+",dst port "+QString::number(ntohs(udp->uh_dport)));
    topItem->appendRow(new QStandardItem("Source Port:"+QString::number(ntohs(udp->uh_sport))));
    topItem->appendRow(new QStandardItem("Destination Port:"+QString::number(ntohs(udp->uh_dport))));
    topItem->appendRow(new QStandardItem(str.sprintf("length :  %d",ntohs(udp->len))));
    topItem->appendRow(new QStandardItem("data : "+QString::fromLatin1((char*)(packet+sizeof(udphdr)),ntohs(udp->len))));
    topModel->appendRow(topItem);
}
void MainWindow::showHttp(QTreeWidgetItem *item)
{

    DEBUG("http call");
    showTcp(item);
    Model *model = models->at(item->text(0).toInt()-1);
    u_char * packet = model->getPacket();
    packet += sizeof(MACHEADER);
    IPHEADER * ip = (IPHEADER *)packet;
    packet += ip->len*4;
    tcphdr * tcp = (tcphdr*)(packet);
    packet += tcp->doff*4;
    QStandardItem * topItem = new QStandardItem("HyperLink Text Transport Protocol");

    int len = model->getPacketLen()-sizeof(MACHEADER)-ip->len*4-tcp->doff*4;
    int index=0,i=0;
    for(i=0;i<len;i++)
    {
        if(packet[i]=='\r' && packet[i+1]=='\n'){
            if(i-index==0){
                break;
            }
            QString str = QString::fromLatin1((char *)packet+index,i-index);
            topItem->appendRow(new QStandardItem(str));
            index=i+2;
            i+=2;
        }
    }
    qDebug()<<len-i<<endl;
    if(i<len){
        topItem->appendRow(new QStandardItem("data:"+ QString::fromLatin1((char*)(packet+i+2),len-i)));
    }
    topModel->appendRow(topItem);
}
void MainWindow::showIcmp(QTreeWidgetItem *item)
{
    DEBUG("icmp call");
    showIp(item);
    Model *model = models->at(item->text(0).toInt()-1);
    u_char * packet = model->getPacket();
    packet += sizeof(MACHEADER);
    IPHEADER * ip = (IPHEADER *)packet;
    packet += ip->len*4;
    struct icmphdr *icmp = (struct icmphdr *)packet;
    QStandardItem * topItem = new QStandardItem("Internet Control Message Protocol,type "+QString::number(ntohs(icmp->type))+",code "+QString::number(ntohs(icmp->code)));
    topItem->appendRow(new QStandardItem("type:"+QString::number(ntohs(icmp->type))));
    topItem->appendRow(new QStandardItem("code:"+QString::number(ntohs(icmp->code))));
    topItem->appendRow(new QStandardItem("checksum:"+QString::number(ntohs(icmp->checksum))));
    topItem->appendRow(new QStandardItem("id:"+QString::number(ntohs(icmp->un.echo.id))));
    topItem->appendRow(new QStandardItem("sequence:"+QString::number(ntohs(icmp->un.echo.sequence))));

    int len = model->getPacketLen()-sizeof(MACHEADER)-ip->len*4-sizeof(struct icmphdr);
    topItem->appendRow(new QStandardItem("options:"+QString::fromLocal8Bit((char *)(packet+sizeof(struct icmphdr)),len)));
    topModel->appendRow(topItem);
}


void MainWindow::on_potocol_currentIndexChanged(const QString &arg1)
{
    QString  expression = arg1;
    /*if(expression == "arp" || expression == "rarp")
         expression.insert(0,"ether proto ");
    else
         expression.insert(0,"ip proto ");
    */
    if(ui->filter->isChecked()){

        sniffer->filter(expression);
    }
}

void MainWindow::on_filter_stateChanged(int arg1)
{
    if(ui->filter->isChecked()){
        QString expression = ui->potocol->currentText();
        sniffer->filter(expression);
    }else{
        QString expression(" ");
        sniffer->filter(expression);
    }
}

void MainWindow::on_actionSave_records_s_triggered(bool checked)
{
    if(checked){
        QFileDialog *fileDialog = new QFileDialog(this);
        fileDialog->setWindowTitle("select a file to save records");
        fileDialog->setDirectory("./");
        if(fileDialog->exec()==QFileDialog::Accepted) // ok
        {
             QStringList files;
             files = fileDialog->selectedFiles();
             sniffer->setFile(files[0]);
         }
    }else{
        sniffer->closeFile();
    }
}
