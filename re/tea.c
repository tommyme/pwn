#include <stdio.h>
#include <stdlib.h>

void tea_encrypt(uint32_t *v, uint32_t *key, uint32_t delta)
{
    uint32_t l = v[0], r = v[1], sum = 0;
    for (int i = 0; i < 32; i++)
    {
        sum += delta;
        l += ((r << 4) + key[0]) ^ (r + sum) ^ ((r >> 5) + key[1]);
        r += ((l << 4) + key[2]) ^ (l + sum) ^ ((l >> 5) + key[3]);
    }
    v[0] = l;
    v[1] = r;
}

void tea_decrypt(uint32_t *v, uint32_t *key, uint32_t delta)
{
    uint32_t l = v[0], r = v[1], sum = 0;
    sum = delta * 32;
    for (int i = 0; i < 32; i++)
    {
        r -= ((l << 4) + key[2]) ^ (l + sum) ^ ((l >> 5) + key[3]);
        l -= ((r << 4) + key[0]) ^ (r + sum) ^ ((r >> 5) + key[1]);
        sum -= delta;
    }
    v[0] = l;
    v[1] = r;
}

void xtea_encrypt(uint32_t *v, uint32_t *key, uint32_t delta)
{
    uint32_t l = v[0], r = v[1], sum = 0;
    for (size_t i = 0; i < 32; i++)
    {
        l += (((r << 4) ^ (r >> 5)) + r) ^ (sum + key[sum & 3]);
        sum += delta;
        r += (((l << 4) ^ (l >> 5)) + l) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = l;
    v[1] = r;
}

void xtea_decrypt(uint32_t *v, uint32_t *key, uint32_t delta)
{
    uint32_t l = v[0], r = v[1], sum = 0;
    sum = delta * 32;
    for (size_t i = 0; i < 32; i++)
    {
        r -= (((l << 4) ^ (l >> 5)) + l) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        l -= (((r << 4) ^ (r >> 5)) + r) ^ (sum + key[sum & 3]);
    }
    v[0] = l;
    v[1] = r;
}

int main(int argc, char const *argv[])
{
    //test
    uint32_t v[] = {0x67505fd1, 0x0bcdb6aa0, 0x8d6b5ee4, 0x785bf212, 0xc6e4b3c2, 0x39804658};
    uint32_t key1[4]={0x1060308, 0x50e070f+1, 0xa0b0c0d+2, 0xdeadbeef+3};
    uint32_t key2[4]={0x1060308, 0x50e070f+2, 0xa0b0c0d+4, 0xdeadbeef+6};
    uint32_t key3[4]={0x1060308, 0x50e070f+3, 0xa0b0c0d+6, 0xdeadbeef+9};
    
    uint32_t delta = -0x61c88647;
    tea_decrypt(v, key1, delta);
    xtea_decrypt(&v[2], key2, delta);
    xtea_decrypt(&v[4], key3, delta);
    for (uint32_t i = 0; i < 6; i++)
    {
        printf("%x",v[i]);
    }
    return 0;
}