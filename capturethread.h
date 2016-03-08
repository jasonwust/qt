#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread>
#include "sniffer.h"

class CaptureThread : public QThread
{
public:
    CaptureThread(Sniffer *sniffer);
    void run();
private:
    Sniffer * sniff;
};

#endif // CAPTURETHREAD_H
