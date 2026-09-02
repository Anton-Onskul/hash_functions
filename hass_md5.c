#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define A0 0x67452301   //1 слово буфера MD
#define B0 0xEFCDAB89   //2 слово буфера MD
#define C0 0x98BADCFE   //3 слово буфера MD
#define D0 0x10325476   //4 слово буфера MD

const uint32_t K[64] = {    //Константы для работы MD5
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

const uint32_t S[64] = {    //Константы сдвига
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static inline uint32_t F  (uint32_t x, uint32_t y, uint32_t z){ //Реализация функции 1 цикла работы MD5
    return (((x) & (y)) | ((~x) & (z)));    
}

static inline uint32_t G  (uint32_t x, uint32_t y, uint32_t z){ //Реализация функции 2 цикла работы MD5
    return (((x) & (z)) | ((y) & (~z)));
}

static inline uint32_t H  (uint32_t x, uint32_t y, uint32_t z){ //Реализация функции 3 цикла работы MD5
    return ((x) ^ (y) ^ (z));
}

static inline uint32_t I  (uint32_t x, uint32_t y, uint32_t z){ //Реализация функции 4 цикла работы MD5
    return ((y) ^ ((x) | (~z)));
}

static inline uint32_t rotate (uint32_t x, int n){  //Сдвиг слова
    return (((x) << (n)) | ((x) >> (32-(n))));
}

void md5 (const unsigned char* block, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D){ //Реализация хэша md5
    uint32_t M[16]; //Создание 16 разрядного массива, в каждой ячейке которого хранится 4 байтное слово 
    for (int i = 0; i < 16; i++){
        M[i] = block[4*i] | (block[(4*i) + 1] << 8) | (block[(4*i) + 2] << 16) | (block[(4*i) + 3] << 24);  //Создание и сохранение слова
    }
    uint32_t a = *A, b = *B, c = *C, d = *D, g = 0, res = 0;
    for (int i = 0; i < 64; i++){   //Цикл замены слов буфера 64 раза по правилам md5
        uint32_t temp = 0;
        if (i <= 15){   // на 1 этапе реализуется через функцию F
            g = i;
            res = F(b, c, d);
        }
        else if (i > 15 && i <= 31){    // на 2 этапе реализуется через функцию G
            g = (5 * i + 1) % 16;
            res = G(b, c, d);
        }
        else if (i > 31 && i <= 47){    // на 3 этапе реализуется через функцию H
            g = (3 * i + 5) % 16;
            res = H(b, c, d);
        }
        else if (i > 47){   // на 4 этапе реализуется через функцию I
            g = (7 * i) % 16;
            res = I(b, c, d);
        }
        temp = d;   // Замена переменных согласно rcf
        d = c;
        c = b;
        b = b + rotate(a + res + K[i] + M[g], S[i]);
        a = temp;
    }
    *A += a; *B += b; *C += c; *D += d;
}

static inline unsigned char* pipeline_line (const char *input, size_t *out_len){
    size_t size = strlen(input);
    size_t start_len = size;
    uint64_t bit_len = (uint64_t)start_len * 8;
    size_t chang_len = ((size + 1 + 8 + 63) / 64) * 64;
    unsigned char* temp = (unsigned char*) malloc(chang_len);
    memset(temp, 0, chang_len);
    memcpy(temp, input, size);
    temp[size] = 0x80;
    size++;
    while (size % 64 != 56){
        temp[size] = '\0';
        size++;
    }
    for (int i = 0; i < 8; i++){
        temp[size+i] = (unsigned char)(bit_len >> (8 * i)) & 0xFF;
    }
    *out_len = chang_len;
    return temp;
}

static inline unsigned char* pipeline_file (const char* filename){
    unsigned char temp[64];
    uint32_t A = A0, B = B0, C = C0, D = D0;
    uint64_t byte_len = 0;
    size_t temp_len = 0;
    FILE *myfile = fopen(filename, "rb");
    if (myfile){
        while ((temp_len = fread(temp, 1, 64, myfile)) == 64){
            md5 (temp, &A, &B, &C, &D);
            byte_len += temp_len;
        }
        byte_len += temp_len;
        temp[temp_len] = 0x80;
        size_t pip_len = temp_len + 1;
        if (pip_len <= 56){
            while (pip_len % 64 != 56){
                temp[pip_len] = '\0';
                pip_len ++;
            }
            for (int i = 0; i < 8; i ++){
                temp[pip_len+i] = (unsigned char)(((uint64_t)byte_len * 8) >> (8 * i)) & 0xFF;
            }
            md5 (temp, &A, &B, &C, &D);
        }

        else {
            while (pip_len % 64 != 0){
                temp[pip_len] = '\0';
                pip_len ++;
            }
            md5 (temp, &A, &B, &C, &D);

            unsigned char extend[64];
            memset (extend, 0, 64);
            for (int i = 0; i < 8; i ++){
                extend[56 + i] = (unsigned char)(((uint64_t)byte_len * 8) >> (8 * i)) & 0xFF;
            }
            md5(extend, &A, &B, &C, &D);
        }
        fclose(myfile);

        unsigned char* result = (unsigned char*) malloc(16);
        uint32_t words[4] = {A, B, C, D};

        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                result[i*4 + j] = (unsigned char)(words[i] >> (8*j)) & 0xFF;
            }
        }
        return result;
    }
    return NULL;
}

int main (){
    char str[100];
    size_t str_len;
    unsigned char* res;

    printf("Ur file: ");
    scanf("%99s", str);
    printf("Ты ввёл: [%s]\n", str);
    res = pipeline_file(str);
    if (res == NULL){
        printf("File error - could not open file\n");
        return 1;
    }
    printf("Results: ");
    for (int i = 0; i < 16; i++){
        printf("%02x", res[i]);
    }
    printf("\n");
    free(res);
    return 0;
}