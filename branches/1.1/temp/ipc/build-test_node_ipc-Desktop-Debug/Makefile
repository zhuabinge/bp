#############################################################################
# Makefile for building: test_node_ipc
# Generated by qmake (3.0) (Qt 5.2.1)
# Project:  ../test_node_ipc/test_node_ipc.pro
# Template: app
# Command: /usr/lib/x86_64-linux-gnu/qt5/bin/qmake -spec linux-g++-64 CONFIG+=debug CONFIG+=declarative_debug CONFIG+=qml_debug -o Makefile ../test_node_ipc/test_node_ipc.pro
#############################################################################


####### Compiler, tools and options

CC            = gcc

####### Output directory

OBJECTS_DIR   = ./

####### Files

SOURCES       = ../test_node_ipc/main.c \
		../test_node_ipc/ipc.c 
OBJECTS       = main.o \
		ipc.o
####### Compile

test_ipc: main.o ipc.o
	$(CC) -o  test_ipc main.o ipc.o

main.o: ../test_node_ipc/main.c ../test_node_ipc/spoofer_main.h
	$(CC) -c  -o main.o ../test_node_ipc/main.c

ipc.o: ../test_node_ipc/ipc.c ../test_node_ipc/spoofer_main.h \
		../test_node_ipc/ipc.h
	$(CC) -c  -o ipc.o ../test_node_ipc/ipc.c

####### Install

install:   FORCE

uninstall:   FORCE

FORCE:

