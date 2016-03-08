#-------------------------------------------------
#
# Project created by QtCreator 2016-01-19T16:27:17
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = untitled
TEMPLATE = app

SOURCES += main.cpp\
        mainwindow.cpp \
    sniffer.cpp \
    capturethread.cpp

HEADERS  += mainwindow.h \
    sniffer.h \
    capturethread.h \
    model.h \
    debug.h

FORMS    += mainwindow.ui

LIBS += -lpcap
