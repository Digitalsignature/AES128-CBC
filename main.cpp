#include <iostream>
#include <NTL/ZZ.h>
#include <gmpxx.h>
#include <sstream>
#include "AES-CBC.h"

using namespace std;
using namespace NTL;
typedef mpz_class ZZZ;
#define _TIME int starts,finishs;
#define STARTS_TIME starts=clock();
#define FINISHS_TIME finishs=clock(); cout<<(double)(finishs-starts)/CLOCKS_PER_SEC<<endl;
void test_decrypt_cbc();
void test_encrypt_cbc();
int main()
{
    test_encrypt_cbc();
    return 0;
}
 void test_decrypt_cbc(uint8_t key[],uint8_t iv[],uint8_t in[])
{
    uint8_t buffers[64];

    AES128_CBC_decrypt_buffer(buffers+0, in+0,  16, key, iv);
    AES128_CBC_decrypt_buffer(buffers+16, in+16, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffers+32, in+32, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffers+48, in+48, 16, 0, 0);
    for(int i=0;i<64;i++)
    {
        cout<<hex<<static_cast<int>(buffers[i]);
    }
}

 void test_encrypt_cbc()
{
 /***********KEY*********************/
    uint8_t key[16];
    ZZ numbersite;
    RandomBits(numbersite,128);
    stringstream buffer;
    buffer<<numbersite;
    ZZZ number;
    number=buffer.str();
    string bitnonce=number.get_str(2);
    int strlen=bitnonce.length();
    for(;strlen<128;strlen++)bitnonce=bitnonce+'1';
    int k=0;
    for(int i=0;i<128;i+=8)
    {
        number.set_str(bitnonce.substr(i,8),2);
        key[k++]=number.get_ui();

    }
    /*******************IV***************/
    uint8_t iv[128];
    RandomBits(numbersite,128);
    buffer<<numbersite;
    number=buffer.str();
    bitnonce=number.get_str(2);
    strlen=bitnonce.length();
    for(;strlen<128;strlen++)bitnonce=bitnonce+'1';
    k=0;
    for(int i=0;i<128;i+=8)
    {
        number.set_str(bitnonce.substr(i,8),2);
        iv[k++]=number.get_ui();

    }

    uint8_t in[]  = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
    uint8_t buffers[64];

    AES128_CBC_encrypt_buffer(buffers, in, 64, key, iv);

    for(int i=0;i<64;i++)
    {
        cout<<hex<<static_cast<int>(buffers[i]);
    }
    cout<<endl;
    test_decrypt_cbc(key,iv,buffers);
}
