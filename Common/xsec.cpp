#include "xsec.h"

int XSEC::EnCrypto(unsigned char * k1, int in_size, unsigned char * out)
{
	auto b = BIO_new_file(crt_pem_, "r");
	auto x = PEM_read_bio_X509(b, NULL, NULL, NULL);
	auto pkey = X509_get_pubkey(x);
	auto rsa = EVP_PKEY_get1_RSA(pkey);
	//创建加密上下文
	EVP_PKEY_CTX*ctx = nullptr;
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_encrypt_init(ctx);

	int key_size = RSA_size(rsa);
	int block_size = key_size - RSA_PKCS1_PADDING_SIZE;
	

	int out_size = 0;
	for (int i = 0; i < in_size; i += block_size)
	{
		size_t out_len = key_size;
		size_t en_size = block_size;
		if (in_size - i < block_size)
			en_size = in_size - i;
		int ret = EVP_PKEY_encrypt(ctx, out + out_size, &out_len, k1 + i, en_size);
		if (ret < 0)
		{
			cout << "encrypto error!" << endl;
			break;
		}
		out_size += out_len;

	}
	
	EVP_PKEY_CTX_free(ctx);
	return out_size;
}

int XSEC::DeCrypto(unsigned char * cipher, int cipher_size, unsigned char * out)
{
	FILE*fp = fopen(pri_key_, "r");
	if (!fp)
	{
		cout << "fopen error!" << endl;
		fclose(fp);
		return -1;
	}
	RSA *r = NULL;
	//私钥存在R中
	PEM_read_RSAPrivateKey(fp, &r, NULL, NULL);
	if (!r)
	{
		fclose(fp);
		cout << "rsa error" << endl;
	}
	fclose(fp);
	auto pkey = EVP_PKEY_new();
	//将R中的私钥放在evp_pkey中
	EVP_PKEY_set1_RSA(pkey, r);
	//创建上下文
	EVP_PKEY_CTX *ctx = nullptr;
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);
	int key_size = RSA_size(r);
	RSA_free(r);
	int in_len = strlen((char*)cipher);
	//解密
	int out_size = 0;
	EVP_PKEY_decrypt_init(ctx);
	int block_size = key_size;
	for (int i = 0; i < in_len; i += block_size)
	{
		size_t outlen = key_size;//设置输出空间大小；
		if (EVP_PKEY_decrypt(ctx, out + out_size, &outlen, cipher + i, block_size) <= 0)
		{

			cout << "decrpt error" << endl;
			return -1;
		}
		out_size += outlen;

	}
	EVP_PKEY_CTX_free(ctx);

	return out_size;
}
