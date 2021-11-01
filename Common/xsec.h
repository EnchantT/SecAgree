#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include<openssl/rsa.h>
#include<openssl/evp.h>
#include<openssl/err.h>
#include<openssl/pem.h>
#include<openssl/x509.h>
#include<cstring>
using namespace std;
#include<cstring>
class XSEC
{
public:
	XSEC(const char*crt, const char *pri)
	{
		strcpy(crt_pem_, crt);
		strcpy(pri_key_, pri);
	}
	int EnCrypto(unsigned char *k1, int in_size, unsigned char* out);
	int DeCrypto(unsigned char*cipher, int cipher_size, unsigned char*out);
private:
	char crt_pem_[128] = { 0 };
	char pri_key_[128] = { 0 };
};

