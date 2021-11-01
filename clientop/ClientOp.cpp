#include "ClientOp.h"
#include"xsec.h"
#include<openssl/x509.h>
#include<fstream>
#include<cstring>
void ClientOp::getRandString(int len,char*randBuf)
{
int flag = -1;
	// 靠靠靠
	srand(time(NULL));
	// 靠靠?: A-Z, a-z, 0-9, 靠靠(!@#$%^&*()_+=)
	char chars[] = "!@#$%^&*()_+=";
	for (int i = 0; i < len-1; ++i)
	{
		flag = rand() % 4;
		switch (flag)
		{
		case 0:
			randBuf[i] = rand() % 26 + 'A';
			break;
		case 1:
			randBuf[i] = rand() % 26 + 'a';
			break;
		case 2:
			randBuf[i] = rand() % 10 + '0';
			break;
		case 3:
			randBuf[i] = chars[rand() % strlen(chars)];
			break;
		default:
			break;
		}
	}
	randBuf[len - 1] = '\0';			
}
int ClientOp::secKeyAgree()
{
	//准备给server的数据
	RequestMsg reqMsg;
	memset(&reqMsg, 0x00, sizeof(reqMsg));
	reqMsg.cmdType = RequestCodec::NewOrUpdate;
	strcpy(reqMsg.clientId, "1002");
	strcpy(reqMsg.serverId, "1001");
	char r1tmp[6]={0};
	getRandString(sizeof(r1tmp),r1tmp);
	
	
	//使用hmac函数生成哈希值----消息认证码
	char key[64];
	unsigned int len;
	unsigned char md[SHA256_DIGEST_LENGTH];
	memset(key, 0x00, sizeof(key));
	sprintf(key, "@%s+%s@", reqMsg.serverId, reqMsg.clientId);
	HMAC(EVP_sha256(), key, strlen(key), (unsigned char *)r1tmp, strlen(r1tmp), md, &len);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(&reqMsg.authCode[2 * i], "%02x", md[i]);
	}
	

	////////////////////////////////////开始和服务器连接//////////////////////////////////
	socket_.connectToHost("127.0.0.1", 8888);
	cout << "connect to server successed!" << endl;
	////////////////////////////////////将证书发送给对方//////////////////////////////////
	char crtbuf[4096]={0};
	ifstream ifs("client.crt",ios::binary);
		if(!ifs)
			{
         return -1;
         cout<<"open file error!"<<endl;
				}
	ifs.read(crtbuf,sizeof(crtbuf));
	int readn=ifs.gcount();
	socket_.sendMsg(crtbuf,readn);
	ifs.close();
	
	////////////////////////////////////准备接受server的证书//////////////////////////////////
	char *sercrtbuf=NULL;
	int sercrtbufsize=-1;
	socket_.recvMsg(&sercrtbuf,sercrtbufsize);
	
	ofstream ofs("server.crt",ios::binary);
	if(!ofs)
		{
			cout<<"ofstream failed!"<<endl;
			return -1;
		}
	ofs.write(sercrtbuf,sercrtbufsize);
	ofs.close();
	
////////////////////至此客户端和服务器都拿到了对方的证书///////////////////
////////////////////对r1加密/////////////////
		XSEC sec("server.crt","client.key");
		int r1tmplen=strlen(r1tmp);
		unsigned char r1cipher[1024]={0};
		sec.EnCrypto((unsigned char*)r1tmp,r1tmplen,r1cipher);
		strcpy(reqMsg.r1,(char*)r1cipher);

		
//r1的密文和消息认证码都准备好了开始进行DER编码
int dataLen=-1;
	char *outData = NULL;
	CodecFactory *factory = new RequestFactory(&reqMsg);
	Codec *pCodec = factory->createCodec();
	pCodec->msgEncode(&outData, dataLen);
	
	delete factory;
	delete pCodec;

	//将数据发送给server
	socket_.sendMsg(outData,dataLen);
	
	
	cout << "send to server successed!" << endl;
	
	//等待来自server的数据
	char *indata;
	socket_.recvMsg(&indata,dataLen);

	//解码
	cout<<"start DE DER"<<endl;
	factory = new RespondFactory();
	pCodec = factory->createCodec();
	cout<<"pcode ok"<<endl;
	RespondMsg *pMsg = (RespondMsg *)pCodec->msgDecode(indata, dataLen);
	cout<<"end DE DER"<<endl;
	//判断服务端是否成功
	if (pMsg->rv == -1)
	{
		cout << "秘钥协商失败" << endl;
		return -1;
	}
	else
	{
		cout << "seckey agree successed!" << endl;
	}
	
	/////////解密服务器发送来的r2/////////////////////
	int r2len=sizeof(pMsg->r2);
	unsigned char r2tmp[1024]={0};
	sec.DeCrypto((unsigned char*)pMsg->r2,r2len,r2tmp);
	cout<<"RespondMsg->r2:"<<r2tmp<<endl;
	
	//将服务端的r2和客户端的r1拼接生成秘钥
	char buf[1024];
	unsigned char md1[SHA_DIGEST_LENGTH];
	memset(md1, 0x00, sizeof(md1));
	char seckey[SHA_DIGEST_LENGTH * 2 + 1];
	memset(buf, 0x00, sizeof(buf));
	memset(seckey, 0x00, sizeof(seckey));
	sprintf(buf, "%s%s", r1tmp, r2tmp);
	SHA1((unsigned char *)buf, strlen((char *)buf), md1);
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		sprintf(&seckey[i * 2], "%02x", md1[i]);
	}
	cout << "seckey: " << seckey << endl;
	
///////////////将协商好的密钥存放在共享内存中////////////////////

	NodeSHMInfo node;
	memset(&node,0x00,sizeof(NodeSHMInfo));
	node.status=0;
	strcpy(node.seckey,seckey);
	strcpy(node.clientID,"1002");
	strcpy(node.serverID,"1001");
	node.seckeyID=pMsg->seckeyid;

	shm_->shmWrite(&node);

	getchar();

	//释放资源
	delete factory;
	delete pCodec;
	socket_.disConnect();
	return 0;
}


