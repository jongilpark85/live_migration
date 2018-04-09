# Makefile for Live Migration
CC=gcc
CFLAGS=-g -fno-stack-protector -Wall

default: build

rebuild: clean build

build: receiver target libsender.so

clean:
	rm -rf *.o receiver target libsender.so

receiver: Receiver.o 
	$(CC) $(CFLAGS) -static -Wl,-Ttext-segment=5000000 -Wl,-Tdata=5100000 -Wl,-Tbss=5200000 -o receiver Receiver.o -lpthread 

Receiver.o: Receiver.c Common_Header.h
	$(CC) $(CFLAGS) -c Receiver.c

libsender.so: SenderLib.o
	$(CC) $(CFLAGS) -fpic -shared -o libsender.so SenderLib.o

SenderLib.o: SenderLib.c Common_Header.h
	$(CC) $(CFLAGS) -fpic -c SenderLib.c

target:	Target.o
	$(CC) -g -o target Target.o

Target.o: Target.c
	$(CC) -g -Wall -c Target.c

test: build
	python test.py
