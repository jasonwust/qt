#ifndef DEBUG_H
#define DEBUG_H

#define DEBUGENABLE

#ifndef DEBUGENABLE
    #define DEBUG(info)
#else
    #define DEBUG(info) qDebug()<<info<<endl
#endif


#endif // DEBUG_H

