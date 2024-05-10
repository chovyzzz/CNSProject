#include <string.h>
#include "AES.h"
#include <time.h>
#include <stdlib.h>

int main(/*int argc, char* argv[]*/)
{
	unsigned char input[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
							 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
							 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
							 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	unsigned char iv[]    = {0x60, 0xef, 0x17, 0x10, 0xd7, 0xcc, 0x28, 0xf8,
							0x56, 0xbd, 0xe4, 0x8b, 0xa1, 0xce, 0xb0, 0x87};
	unsigned char key[]   = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
							0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	unsigned char output[100] ={0};
    unsigned char temp[100] = {0};
	clock_t start, end;
    int count=50000;
 //   unsigned char data[count*sizeof(input)];
    unsigned char *data=(unsigned char *)malloc(count*sizeof(input));
    unsigned char *datao=(unsigned char *)malloc(count*sizeof(input));
	for(int i=0;i<count;i++)
	{
		for(int j=0;j<sizeof(input);j++){
			data[i*sizeof(input)+j]=input[j];
		}
	}

//	unsigned char
	//AESModeOfOperation moo;
	AESModeOfOperation();
	AESModeOfOperation_set_key(key);
	AESModeOfOperation_set_iv(iv);
	AESModeOfOperation_set_mode(MODE_CBC);
	printf("\nAES_CIPHER_128 CBC encrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", input, sizeof(input));
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
    memcpy(temp, input, sizeof input);
	int olen = sizeof input;
	int len = AES_Encrypt(temp, olen, output);
	aes_dump("cipher", output, olen);

	printf("\nAES_CIPHER_128 CBC decrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", output, olen);
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
	len = AES_Decrypt(output, len, temp);
	aes_dump("plain", temp, olen);

	AESModeOfOperation_set_mode(MODE_ECB);
	printf("\nAES_CIPHER_128 ECB encrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", input, sizeof(input));
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
    memcpy(temp, input, sizeof input);
	olen = sizeof input;
	len = AES_Encrypt(temp, olen, output);
	aes_dump("cipher", output, olen);

	printf("\nAES_CIPHER_128 ECB decrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", output, olen);
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
	len = AES_Decrypt(output, len, temp);
	aes_dump("plain", temp, olen);

	printf("\nAES_CIPHER_128 CFB encrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", input, sizeof(input));
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
    memcpy(temp, input, sizeof input);
	olen = sizeof input;
	len = AES_Encrypt_CFB(temp, olen, output);
	aes_dump("cipher", output, olen);

	printf("\nAES_CIPHER_128 CFB decrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", output, olen);
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
	len = AES_Decrypt_CFB(output, len, temp);
	aes_dump("plain", temp, olen);

	printf("\nAES_CIPHER_128 OFB encrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", input, sizeof(input));
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
    memcpy(temp, input, sizeof input);
	olen = sizeof input;
	len = AES_Encrypt_OFB(temp, olen, output);
	aes_dump("cipher", output, olen);

	printf("\nAES_CIPHER_128 OFB decrypt test case:\n");
	printf("Input:\n");
	aes_dump("data", output, olen);
	aes_dump("key ", key, sizeof(key));
	aes_dump("IV ", iv, sizeof(iv));
	len = AES_Decrypt_OFB(output, len, temp);
	aes_dump("plain", temp, olen);

	fflush(stdout);


	start=clock();
	len = AES_Encrypt_CFB(data, sizeof(input)*count, datao);
	end=clock();
	printf("\naes_encrypt_CFB_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", datao, 32);

	start=clock();
	len = AES_Decrypt_CFB(datao, sizeof(input)*count, data);
	end=clock();
	printf("\naes_decrypt_CFB_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	start=clock();
	len = AES_Encrypt_OFB(data, sizeof(input)*count, datao);
	end=clock();
	printf("\naes_encrypt_OFB_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", datao, 32);

	start=clock();
	len = AES_Decrypt_OFB(datao, sizeof(input)*count, data);
	end=clock();
	printf("\naes_decrypt_OFB_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	start=clock();
	len = AES_Encrypt_CBC(data, sizeof(input)*count, datao);
	end=clock();
	printf("\naes_encrypt_CBC_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", datao, 32);

	start=clock();
	len = AES_Decrypt_CBC(datao, sizeof(input)*count, data);
	end=clock();
	printf("\naes_decrypt_CBC_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	start=clock();
	len = AES_Encrypt_ECB(data, sizeof(input)*count, datao);
	end=clock();
	printf("\naes_encrypt_ECB_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("cipher", datao, 32);

	start=clock();
	len = AES_Decrypt_ECB(datao, sizeof(input)*count, data);
	end=clock();
	printf("\naes_decrypt_ECB_128 %d bytes time(s): %lf\n", sizeof(input)*count, (double)(end - start) / CLOCKS_PER_SEC);
	aes_dump("plain", data, 32);

	free(data);
	free(datao);
	return 0;
}




