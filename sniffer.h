#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap/pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <QStringList>
#include <QDebug>
#include <QList>
#include <QTreeWidget>
#include <iostream>
#include <QMessageBox>
#include <time.h>
#include <QTreeWidgetItem>
#include <QObject>
#include "model.h"
#include "debug.h"
#define MAXPACKETSIZE 2048
//mac type
#define IP    0x0800
#define ARP   0x0806
#define RARP  0x8035

//ip type
#define ICMP   0x01
#define TCP    0x06
#define UDP    0x11

/*ip_header*/
typedef struct mac_header{
    u_char dst[6];
    u_char src[6];
    u_short type;
} MACHEADER;
typedef struct ip_header{
    u_char len:4; // Version (4 bits) + Internet header length (4 bits)
    u_char version:4;
    u_char tos; // Type of service
    u_short tlen; // Total length
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl; // Time to live
    u_char proto; // Protocol
    u_short crc; // Header checksum
    in_addr saddr; // Source address
    in_addr daddr; // Destination address
    u_int op_pad; // Option + Padding
}IPHEADER;
/*udp header*/
typedef struct udp_header{
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len; // Datagram length
    u_short crc; // Checksum
}*UDPHEADER;


class Sniffer : public QObject
{
    Q_OBJECT
public:
    explicit Sniffer(QObject *parent = 0 );
    ~Sniffer();
    void getAllDevicesName(QStringList &list);
    void getPackets();
    void openDevice(const char * dev=NULL);
    void closeDevice();
    void pausePacket();
    void filter(QString expression);
    void setFile(const QString filename);
    void closeFile();
signals:
        void getPacket(Model *model);
protected:
    void findDevs();
private:
    pcap_if_t *alldevs=NULL;      //all devs list header,don't move it
    pcap_t *opendev=NULL;
    QString dev=NULL;
    pcap_dumper_t *dump_t=NULL;
    void init();
    static void handlePacket(u_char *, const struct pcap_pkthdr *,const u_char *);
};

#endif // SNIFFER_H
