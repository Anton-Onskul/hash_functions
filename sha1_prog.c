#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define A0 0x67452301
#define B0 0xEFCDAB89
#define C0 0x98BADCFE
#define D0 0x10325476
#define E0 0xC3D2E1F0

const uint32_t K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

static inline uint32_t rotate (uint32_t x, int n){  //Сдвиг слова
    return (((x) << (n)) | ((x) >> (32-(n))));
}

static inline unsigned char* pipeline_line (const char *input, size_t *out_len){    //Функция заполнения введенной строки до станлартной для работы sha1
    size_t size = strlen(input);    //Длина введенной строки(который будет меняться и отображать сколько в блоке заполнено)
    size_t start_len = size;    //Длина начальной строки, которое не меняется (для работы sha1)
    uint64_t bit_len = (uint64_t)start_len * 8; //start_len, только в битной формате (для корректного заполнения в конце блока)
    size_t chang_len = ((size + 1 + 8 + 63) / 64) * 64; //Размер в байтах блока
    unsigned char* temp = (unsigned char*) malloc(chang_len);   //Создание блока для сохранения в правильно формате исходного сообщения
    memset(temp, 0, chang_len);
    memcpy(temp, input, size);  //Копирование исходного сообщения в буфер
    temp[size] = 0x80;  //Добавляем в конец сообщения 0х80 (согласно алгоритму)
    size++; //Увеличиваем размер блока на 1
    while (size % 64 != 56){    //Заполняем '0', пока не дойдем по последних 8 байт (так формируется блок)
        temp[size] = '\0';
        size++;
    }
    for (int i = 0; i < 8; i++){    //Согласно алгоритму, последние 8 байт блока = длина исходного сообщения в битовом формате, записанная от страшего бита к младшему
        temp[size + 7 - i] = (unsigned char)(bit_len >> (8 * i)) & 0xFF;
    }
    *out_len = chang_len;   //Сохраняем индекс последнего элемента блока для дальнейшей работы
    return temp;
}

static inline uint32_t f1 (uint32_t b, uint32_t c, uint32_t d){ //Реализация функции 1 цикла (0<= t <= 19) работы sha1
    return (b & c) | ((~b) & d);     
}

static inline uint32_t f2 (uint32_t b, uint32_t c, uint32_t d){ //Реализация функции 1 цикла (20 <= t <= 39) работы sha1
    return (b ^ c ^ d);     
}
static inline uint32_t f3 (uint32_t b, uint32_t c, uint32_t d){ //Реализация функции 1 цикла (40 <= 59) работы sha1
    return (b & c) | (b & d) | (c & d);     
}

void sha1(const unsigned char* block, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D, uint32_t *E){
    uint32_t a = *A, b = *B, c = *C, d = *D, e = *E, K = 0, res = 0, temp;
    uint32_t M[16], W[80]; //Создание 16 разрядного массива, в каждой ячейке которого хранится 4 байтное слово 
    for (int i = 0; i < 16; i++){
        M[i] = (block[4*i] << 24) | (block[(4*i) + 1] << 16) | (block[(4*i) + 2] << 8) | (block[(4*i) + 3]);  //Создание и сохранение слова
        W[i] = M[i];
    }
    for (int i = 16; i < 80; i++){  //В отличие от md5, в sha1 наш массив слов должен быть 80, причем первые 16 элементов берутся также, как и в md5, остальные по своему правилу
        W[i] = rotate((W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]), 1);
    }
    for (int i = 0; i < 80; i++){   //Присваивание опеределенного значения функции K, в зависимости от цикла
        if (i <= 19){   
            K = 0x5A827999;
            res = f1(b, c, d);
        }
        else    if (i > 19 && i <= 39){
            K = 0x6ED9EBA1;
            res = f2(b, c, d);
        }
        else    if (i > 39 && i <= 59){
            K = 0x8F1BBCDC;
            res = f3(b, c, d);
        }
        else    if (i > 59){
            K = 0xCA62C1D6;
            res = f2(b, c, d);
        }
        temp = rotate(a, 5) + res + e + K + W[i];   //Замены переменных, согласно алгоритму
        e = d;
        d = c;
        c = rotate(b, 30);
        b = a;
        a = temp;
    }
    *A += a;
    *B += b;
    *C += c;
    *D += d;
    *E += e;
}

static inline unsigned char* pipeline_file (const char* filename){
    unsigned char temp[64]; //Тут включено и использование sha1, так что эта функция берет файл и считает для него sha1
    uint32_t A = A0, B = B0, C = C0, D = D0, E = E0;    //Начальные слова для sha1
    uint64_t byte_len = 0;
    size_t temp_len = 0;
    FILE *myfile = fopen(filename, "rb");   //Открывает файл
    if (myfile){
        while ((temp_len = fread(temp, 1, 64, myfile)) == 64){  //Считает sha1 для полных блоков
            sha1 (temp, &A, &B, &C, &D, &E);
            byte_len += temp_len;
        }
        byte_len += temp_len;
        temp[temp_len] = 0x80;
        size_t pip_len = temp_len + 1;
        if (pip_len <= 56){ //Считает sha1 для неполных блоков, заполняя его, эта часть когда не надо создавать отдельный блок
            while (pip_len % 64 != 56){
                temp[pip_len] = '\0';
                pip_len ++;
            }
            for (int i = 0; i < 8; i ++){
                temp[pip_len + 7 - i] = (unsigned char)(((uint64_t)byte_len * 8) >> (8 * i)) & 0xFF;
            }
            sha1 (temp, &A, &B, &C, &D, &E);
        }

        else {  //Считает sha1 для неполных блоков, заполняет его, затем создает нулевой отдельный блок, в 8 байт которых кладется по правилу (64 - последний бит битовой длины)
            while (pip_len % 64 != 0){
                temp[pip_len] = '\0';
                pip_len ++;
            }
            sha1 (temp, &A, &B, &C, &D, &E);

            unsigned char extend[64];
            memset (extend, 0, 64);
            for (int i = 0; i < 8; i ++){
                extend[56 + 7 - i] = (unsigned char)(((uint64_t)byte_len * 8) >> (8 * i)) & 0xFF;
            }
            sha1 (extend, &A, &B, &C, &D, &E);
        }
        fclose(myfile);

        unsigned char* result = (unsigned char*) malloc(20);    //Создание отдельного блока для вывода 5 слов хэша
        uint32_t words[5] = {A, B, C, D, E};

        for (int i = 0; i < 5; i++){
            for (int j = 0; j < 4; j++){
                result[i*4 + j] = (unsigned char)(words[i] >> (8*(3 - j))) & 0xFF;
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

    printf("Ur file: ");    //Чтение названия файла
    scanf("%99s", str);
    res = pipeline_file(str);
    if (res == NULL){
        printf("File error - could not open file\n");
        return 1;
    }
    printf("Results: ");
    for (int i = 0; i < 20; i++){   //Вывод хэша
        printf("%02x", res[i]);
    }
    printf("\n");
    free(res);
    return 0;
}