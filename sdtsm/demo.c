#include <stdio.h>
#include "SdtSM.h"
#include <string.h>

char SeId[17] = "9876543210123456";
unsigned char gmidlen[2] = { 0x00, 0x80 };
unsigned char gmpara[128] =
{
	0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
	0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
	0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
	0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0 };

void ArrayPrint(unsigned char* pp_Val, unsigned int vp_Len)
{
	unsigned i;
	for (i = 0; i < vp_Len; i++)
	{
		printf("%02X", (unsigned)(pp_Val[i]));
	}
	printf("\n\n\n");
}



// gcc demo.c  -L. -lsdtsm && LD_LIBRARY_PATH=. ./a.out
int main()
{
	int vl_Rst;
	unsigned int pk_len = 128;
	unsigned char sk[32]="12513";
	unsigned char pk[64];
	
	printf("\n====Test  GenSm2 Key====\n");
	vl_Rst = sdt_ecc_makekey(sk, 32, pk, &pk_len);
	if(vl_Rst)
	{
		printf("Gen Sm2 Err:%d\n",vl_Rst);
		return 0;
	}
	printf("Priv is:\n");
	ArrayPrint(sk, 32);
	printf("Pubkey is:\n");
	ArrayPrint(pk,64);


	printf("\n\n====Test  Calc Z ====\n");
	unsigned char gmz[32];
	unsigned int gmzlen = 32;
	unsigned char prodata1[512], prodata2[512];
	unsigned int pzLen = 0;

	//  Z = SM3(ENTL || ID || a || b || XG || yG || XA || yA)
	memset(prodata1, 0, 512);
	memcpy(prodata1 + pzLen, gmidlen, 2);// ENTL 为由2个字节标示的ID的比特长度；
	pzLen += 2;
	memcpy(prodata1 + pzLen, SeId, 16);// ID 为用户身份标识
	pzLen += 16;
	memcpy(prodata1 + pzLen, gmpara, 128);// 固定系统参数
	pzLen += 128;
	memcpy(prodata1 + pzLen, pk, 64);// XA、yA 为用户公钥；
	pzLen += 64;

	vl_Rst = sdt_hash(prodata1, pzLen, gmz, &gmzlen);
	if (vl_Rst)
	{
		printf("Hash Sm3 Err:%d\n", vl_Rst);
		return 0;
	}
	printf("Z Hash Success, pzLen:%d, hash data len:%d\n", pzLen, gmzlen);
	ArrayPrint(gmz, 32);

	// H = SM3(Z||M)
	unsigned char gmh[32];
	unsigned int gmhlen = 32;
	unsigned char data[] = { 0x01,0x02,0x03,0x04 };
	memset(prodata2, 0, 512);
	memcpy(prodata2, gmz, 32);
	memcpy(prodata2 + 32, data, 4);

	vl_Rst = sdt_hash(prodata2, 36, gmh, &gmhlen);
	if (vl_Rst)
	{
		printf("Hash Sm3 Err:%d\n", vl_Rst);
		return 0;
	}
	printf("H Hash Success, hash data len:%d\n\n", gmhlen);
	ArrayPrint(gmh, 32);


	printf("\n\n====Test  Sm2Sign====\n");
	unsigned char random[32] = "123456578";
	unsigned char sign[128];
	unsigned int  sign_len = 32;
	vl_Rst = sdt_ecc_sign(gmh, 32, random, 32, sk, 32, sign, &sign_len);
	if (vl_Rst)
	{
		printf("Sign Err:%d\n", vl_Rst);
		return 0;
	}
	printf("Sign Success, signed data len:%d\n", sign_len);
	ArrayPrint(sign, sign_len);


	printf("\n\n====Test  Sm2Verify====\n");
	vl_Rst = sdt_ecc_verify(gmh, 32, pk, 64, sign, sign_len);
	if (vl_Rst)
	{
		printf("Verify Err:%d\n", vl_Rst);
		return 0;
	}
	printf("Verify Success\n");


	//printf("\n\n====Test  Sm2Encrypt====\n");
	//unsigned char plain_data[] = "hello world";
	//unsigned char cipher_data[256];
	//unsigned int  cipher_data_len = 256;
	//vl_Rst = sdt_ecc_encrypt(plain_data, sizeof(plain_data), random, 32, pk, 64, cipher_data, &cipher_data_len);
	//if (vl_Rst)
	//{
	//	printf("Encrypt Err:%d\n", vl_Rst);
	//	return 0;
	//}
	//printf("Encrypt Success, cipher data len:%d\n", cipher_data_len);


	//printf("\n\n====Test  Sm2Decrypt====\n");
	//unsigned char plain_data1[256];
	//unsigned int  plain_data_len1 = 256;
	//vl_Rst = sdt_ecc_decrypt(cipher_data, cipher_data_len, sk, 32, plain_data1, &plain_data_len1);
	//if (vl_Rst)
	//{
	//	printf("Decrypt Err:%d\n", vl_Rst);
	//	return 0;
	//}
	//printf("Decrypt Success, Plain data:%s\n", plain_data);
}
