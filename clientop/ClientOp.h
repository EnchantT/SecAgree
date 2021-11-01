#pragma once
#include"SecKeyShm.h"
#include<time.h>
#include"RequestCodec.h"
#include"RequestFactory.h"
#include<openssl/sha.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>
#include"RespondCodec.h"
#include"RespondFactory.h"
#include<iostream>
#include"TcpServer.h"
#include"TcpSocket.h"
using namespace std;
class ClientOp
{
public:
	ClientOp() {
		shm_=new SecKeyShm(0x0018,1);
		cout<<"shm constructed!"<<endl;
		}
	~ClientOp() {
		cout<<"ClientOp destructor...."<<endl;
		shm_->delShm();
		delete shm_;
		}
	int secKeyAgree();
private:
	void getRandString(int len,char*buf);
private:
	TcpSocket socket_;
	SecKeyShm *shm_;
};

