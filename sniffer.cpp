#include "sniffer.h"

Sniffer::Sniffer(QObject *parent) : QObject(parent)
{
    init();
}
Sniffer::~Sniffer()
{
    if(alldevs!=NULL)
        pcap_freealldevs(alldevs);
    alldevs=NULL;
}
void Sniffer::findDevs()
{
    /*
     * struct pcap_if {
     *      struct pcap_if *next;
     *      char *name;		//name to hand to "pcap_open_live()"
     *      char *description;	//textual description of interface, or NULL
     *      struct pcap_addr *addresses;
     *      bpf_u_int32 flags;	// PCAP_IF_ interface flags
     * };
     */
    int res=-1;
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf,0,PCAP_ERRBUF_SIZE);
    res = pcap_findalldevs(&this->alldevs,errbuf);
    if(res==-1){
       qDebug()<<"find device failed,"<<"errmesg:"<<errbuf<<endl;
    }
}

/**
 * @brief init
 * init pcap and other
 */
void Sniffer::init()
{
    findDevs();
}
/**
 * @brief Sniffer::getAllDevicesDes
 * @param list
 * return alldevs description
 */
void Sniffer::getAllDevicesName(QStringList &list)
{
    if(alldevs==NULL)
        findDevs();
    pcap_if_t *d;
    for(d=alldevs;d;d=d->next){
        list.append(d->name);
    }
}
/**
 * @brief Sniffer::openDevice
 * @param dev
 * give a device name and open the device
 */
void Sniffer::openDevice(const char *dev)
{
     if(opendev!=NULL)
     {
         closeDevice();
     }
     char errbuf[PCAP_ERRBUF_SIZE];
     if(dev==NULL){
        this->dev = pcap_lookupdev(errbuf);
     }else{
        this->dev = QString::fromLatin1(dev);
     }
     memset(errbuf,0,PCAP_ERRBUF_SIZE);
     opendev = pcap_open_live(this->dev.toStdString().c_str(),MAXPACKETSIZE,1,512,errbuf);
     if(opendev==NULL){
         qDebug()<<"open device error,"<<"errmesg:"<<errbuf<<endl;
     }
}
void Sniffer::handlePacket(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char * packet)
{

    Model *model= new Model;
    model->setTime(QString(ctime(&(pkthdr->ts.tv_sec))));
    u_char * str = (u_char *) malloc(sizeof(u_char)*pkthdr->len);
    memcpy(str,packet,sizeof(char)*pkthdr->len);
    if(((Sniffer*)arg)->dump_t!=NULL)
        pcap_dump((uchar *)((Sniffer*)arg)->dump_t,pkthdr,packet);
    model->setPacket(str);
    model->setPacketLen(pkthdr->len);
    emit ((Sniffer*)arg)->getPacket(model);
    /*printf("Packet count:%d\n",++count);
        printf("recive Packet size:%d\n",pkthdr->len);
        for(int i=0;i<pkthdr->len;i++){
            printf("%.2x ",packet[i]);
            if(i%16==0 && i!=0)
            {
                printf("\n");
            }
        }
        printf("\n");

    */
   // QTreeWidgetItem * item = new QTreeWidgetItem;
    //QTreeWidgetItem * childItem = new QTreeWidgetItem;
   // item->setText(0,++count+"");
    //item->setText(1,pkthdr->ts.tv_sec+"");
    /*
    char macstr[17];
    memset(macstr,0,sizeof(macstr));
    sprintf(macstr,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",mac->dst[0],mac->dst[1],mac->dst[2],mac->dst[3],mac->dst[4],mac->dst[5]);
    QString str;
    str.append("dst mac :");
    str.append(macstr);
    childItem->setText(0,str);
    memset(macstr,0,sizeof(macstr));
    sprintf(macstr,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",mac->src[0],mac->src[1],mac->src[2],mac->src[3],mac->src[4],mac->src[5]);
    str="";
    str.append("src mac :");
    str.append(macstr);
    childItem->setText(1,str);
    item->addChild(childItem);*/
}
/**
 * @brief Sniffer::getPackets
 * use pcap_loop to get packet from network card
 */
void Sniffer::getPackets()
{
    if(opendev==NULL){
        DEBUG("please open a device");
        return ;
    }
    pcap_loop(opendev,-1,Sniffer::handlePacket,(u_char *)this);
}
/**
 * @brief Sniffer::closeDevice
 * close the device
 */
void Sniffer::closeDevice()
{
    if(opendev!=NULL)
    {
        pcap_close(opendev);
        opendev = NULL;
    }
}
/**
 * @brief Sniffer::pausePacket
 * pause
 */
void Sniffer::pausePacket()
{
    if(opendev!=NULL)
        pcap_breakloop(opendev);
}

void Sniffer::filter(QString expression)
{
    struct bpf_program fp;		/* The compiled filter */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(dev.toStdString().c_str(), &net, &mask, errbuf) == -1) {
         qDebug()<<"can't get mask and net from"<<dev<<"errmsg:"<<errbuf<<endl;
         net = 0;
         mask = 0;
    }
    if (pcap_compile(opendev, &fp, expression.toStdString().c_str(), 0, net) == -1) {
        QString errMsg;
        errMsg.append("Couldn't parse filter");
        errMsg.append(expression);
        errMsg.append(QString::fromLatin1(pcap_geterr(opendev)));
        qErrnoWarning(errMsg.toStdString().c_str());
        return ;
    }
    if (pcap_setfilter(opendev, &fp) == -1) {
        QString errMsg;
        errMsg.append("Couldn't install filter");
        errMsg.append(expression);
        errMsg.append(QString::fromLatin1(pcap_geterr(opendev)));
        qErrnoWarning(errMsg.toStdString().c_str());
        return ;
    }
}

void Sniffer::setFile(const QString filename)
{
    if(opendev!=NULL)
        dump_t = pcap_dump_open(opendev,filename.toStdString().c_str());
}

void Sniffer::closeFile()
{
    if(dump_t!=NULL)
    {
        pcap_dump_close(dump_t);
        dump_t=NULL;
    }
}
