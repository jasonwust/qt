#ifndef MODEL_H
#define MODEL_H
#include <QString>

class Model
{
public:
    Model(){}
    Model(QString time,int len,u_char * packet){
        this->time = time;
        this->packectLen = len;
        this->packet = packet;
    }
    QString getTime()
    {
        return time;
    }
    void setTime(QString time)
    {
        this->time = time;
    }
    int getPacketLen()
    {
        return packectLen;
    }
    void setPacketLen(int len){
        packectLen=len;
    }
    u_char * getPacket()
    {
        return packet;
    }
    void setPacket(u_char *mpacket){
        packet = mpacket;
    }
    QString getDesc(){
        return desc;
    }
    void setDesc(QString desc){
        this->desc= desc;
    }
private:
    QString time;
    int packectLen;
    u_char * packet;
    QString desc;
};

#endif // MODEL_H
