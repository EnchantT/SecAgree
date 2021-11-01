#pragma once
#include<sys/socket.h>
#include"TcpSocket.h"
#include<unistd.h>
#include<arpa/inet.h>
#include<iostream>
#include<string>
using namespace std;
class TcpServer
{
public:
	TcpServer();
	~TcpServer();
	int setListen(unsigned short port);
	TcpSocket *acceptConn(struct sockaddr_in*laddr = nullptr);
private:
	int m_fd;
};

