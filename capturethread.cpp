#include "capturethread.h"

CaptureThread::CaptureThread(Sniffer *sniffer)
    :sniff(sniffer)
{

}
void CaptureThread::run()
{
    sniff->getPackets();
}

