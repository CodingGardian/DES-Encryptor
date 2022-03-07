#include <iostream>
#include <string>
#include <array>
#include <chrono>

// Hello my name is matthew and I have N O  H A N D S
// thanks mainly to: http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
// small thanks to Cryptography and network security by Behrouz A. Fourouzan

namespace DEAcrypt {
    typedef uint8_t byte;
    typedef std::array<byte, 8> key_64;
    typedef std::array<byte, 7> key_56;
    typedef std::array<byte, 6> key_48;

    typedef std::array<byte, 4> block_32;
    typedef std::array<byte, 6> block_48;
    typedef std::array<byte, 7> block_56;
    typedef std::array<byte, 8> block_64;

    typedef block_32 (*FeistelFunc_32)(block_32, key_48);

    // :/
    byte fcexp[48] = {32,  1,  2,  3,  4,  5, 4,  5,  6,  7,  8,  9, 8,  9, 
                      10, 11, 12, 13, 12, 13, 14, 15, 16, 17,16, 17, 18, 19, 
                      20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 
                      28, 29, 30, 31, 32, 01};

    byte sbox1[4][16] = {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, 
                         {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                         {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                         {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};

    byte sbox2[4][16] = {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                         {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                         {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                         {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};

    byte sbox3[4][16] = {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                         {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                         {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                         {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};

    byte sbox4[4][16] = {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                         {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                         {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                         {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};

    byte sbox5[4][16] = {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                         {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                         {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                         {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};

    byte sbox6[4][16] = {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                         {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                         {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                         {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};

    byte sbox7[4][16] = {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                         {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                         {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                         {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};

    byte sbox8[4][16] = {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                         {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                         {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                         {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

    byte ip[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                   62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                   57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                   61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
    
    byte ipr[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

    byte pc1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,
                    11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,
                    61,53,45,37,29,21,13,5,28,20,12,4};

    byte pc2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
                    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,
                    36,29,32};

    byte endp[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 
                     5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 
                     13, 30, 6, 22, 11, 4, 25};

    // >:( -> :o
    block_32 fc_byteXOR32(block_32 l, block_32 r) {
        block_32 returnVal;
        for (int i=0; i<4; i++) {
            returnVal[i] = l[i] ^ r[i];
        }

        return returnVal;
    }
    
    block_48 fc_byteXOR48(block_48 l, block_48 r) {
        block_48 returnVal;
        for (int i=0; i<6; i++) {
            returnVal[i] = l[i] ^ r[i];
        }

        return returnVal;
    }

    std::string fc_arrtohex(byte* block, size_t size) {
        char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        
        std::string returnVal;
        for(int i=0; i<size; ++i) {
            byte b = block[i];

            returnVal += hex_chars[ ( b & 0xF0 ) >> 4 ];
            returnVal += hex_chars[ ( b & 0x0F ) >> 0 ];
            returnVal += " ";
        }
        return returnVal;
    }

    std::string fc_block32tohex(block_32 block) {
        char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        
        std::string returnVal;
        for(int i=0; i<4; ++i) {
            byte b = block[i];

            returnVal += hex_chars[ ( b & 0xF0 ) >> 4 ];
            returnVal += hex_chars[ ( b & 0x0F ) >> 0 ];
            returnVal += " ";
        }
        return returnVal;
    }

    std::string fc_block48tohex(block_48 block) {
        char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        
        std::string returnVal;
        for(int i=0; i<6; ++i) {
            byte b = block[i];

            returnVal += hex_chars[ ( b & 0xF0 ) >> 4 ];
            returnVal += hex_chars[ ( b & 0x0F ) >> 0 ];
            returnVal += " ";
        }
        return returnVal;
    }

    std::string fc_block56tohex(block_56 block) {
        char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        
        std::string returnVal;
        for(int i=0; i<7; ++i) {
            byte b = block[i];

            returnVal += hex_chars[ ( b & 0xF0 ) >> 4 ];
            returnVal += hex_chars[ ( b & 0x0F ) >> 0 ];
            returnVal += " ";
        }
        return returnVal;
    }

    std::string fc_block64tohex(block_64 block) {
        char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        
        std::string returnVal;
        for(int i=0; i<8; ++i) {
            byte b = block[i];

            returnVal += hex_chars[ ( b & 0xF0 ) >> 4 ];
            returnVal += hex_chars[ ( b & 0x0F ) >> 0 ];
            returnVal += " ";
        }
        return returnVal;
    }

    std::string fc_block32tostring(block_32 block) {
        std::string returnVal;
        for (int i=0; i<4; i++) {
            returnVal.push_back(block[i]);
        }
        return returnVal;
    }

    std::string fc_block64tostring(block_64 block) {
        std::string returnVal;
        for (int i=0; i<8; i++) {
            returnVal.push_back(block[i]);
        }
        return returnVal;
    }

    class DEA64 {
    private:
        key_48 roundkeys[16];
    public:

        // OH BOY ANOTHER LONG FUNCTION
        DEA64(key_64 basekey) {
            // initialize with zero
            for (int i=0; i<16; i++) {
                roundkeys[i] = {0, 0, 0, 0, 0, 0};
            }

            // Permutation choice 1
            key_56 newkey = {0, 0, 0, 0, 0, 0, 0};

            for (int i=0; i<7; i++) {
                for (int i2=0; i2<8; i2++) {
                    byte temp = pc1[i2 + (i * 8)] - 1;
                    int remainder = temp % 8;
                    int div = temp / 8;

                    byte mask = ( ( basekey[div] << remainder ) & (0x01 << 7 ) ) >> i2;
                    newkey[i] ^= mask;
                }
            }

            // divide the key into two 28 bit halves
            byte half1[4];
            byte half2[4];
            
            half1[0] = newkey[0];
            half1[1] = newkey[1];
            half1[2] = newkey[2];
            half1[3] = ( newkey[3] & (0xff << 4) );

            half2[0] = ( newkey[3] & (0xff >> 4) );
            half2[1] = newkey[4];
            half2[2] = newkey[5];
            half2[3] = newkey[6];

            // do for 16 rounds:
            for (int i=1; i<17; i++) { // >:(
                key_56 tempblock = {0, 0, 0, 0, 0, 0, 0};

                //std::cout << fc_block56tohex(tempblock) << std::endl;
                
                // rotate
                if (i == 1 || i == 2 || i == 9 || i == 16) {
                    // shift once

                    // first half xxxxxxxx xxxxxxxx xxxxxxxx xxxx0000
                    byte tempmask1 = half1[0] & (0x01 << 7);
                    half1[0] <<= 1;
                    half1[0] ^= ( ( half1[1] & (0x01 << 7) ) >> 7 );

                    half1[1] <<= 1;
                    half1[1] ^= ( ( half1[2] & (0x01 << 7) ) >> 7 );

                    half1[2] <<= 1;
                    half1[2] ^= ( ( half1[3] & (0x01 << 7) ) >> 7 );

                    half1[3] <<= 1;
                    half1[3] ^= (tempmask1 >> 3);

                    // second half 0000xxxx xxxxxxx xxxxxxxx xxxxxxxx
                    tempmask1 = (half2[0] << 4) & (0x01 << 7);
                    half2[0] <<= 1;
                    half2[0] &= (0xff >> 4);
                    half2[0] ^= ( ( half2[1] & (0x01 << 7) ) >> 7 );

                    half2[1] <<= 1;
                    half2[1] ^= ( ( half2[2] & (0x01 << 7) ) >> 7 );

                    half2[2] <<= 1;
                    half2[2] ^= ( ( half2[3] & (0x01 << 7) ) >> 7 );

                    half2[3] <<= 1;
                    half2[3] ^= ( tempmask1 >> 7 );

                }
                else {
                    // shift twice

                    // first half xxxxxxxx xxxxxxxx xxxxxxxx xxxx0000
                    byte tempmask1 = half1[0] & (0x03 << 6);
                    half1[0] <<= 2;
                    half1[0] ^= ( ( half1[1] & (0x03 << 6) ) >> 6 );

                    half1[1] <<= 2;
                    half1[1] ^= ( ( half1[2] & (0x03 << 6) ) >> 6 );

                    half1[2] <<= 2;
                    half1[2] ^= ( ( half1[3] & (0x03 << 6) ) >> 6 );

                    half1[3] <<= 2;
                    half1[3] ^= (tempmask1 >> 2);

                    // second half 0000xxxx xxxxxxxx xxxxxxxx xxxxxxxxx
                    tempmask1 = (half2[0] << 4) & (0x03 << 6);
                    half2[0] <<= 2;
                    half2[0] &= (0xff >> 4);
                    half2[0] ^= ( ( half2[1] & (0x03 << 6) ) >> 6 );

                    half2[1] <<= 2;
                    half2[1] ^= ( ( half2[2] & (0x03 << 6) ) >> 6 );

                    half2[2] <<= 2;
                    half2[2] ^= ( ( half2[3] & (0x03 << 6) ) >> 6 );

                    half2[3] <<= 2;
                    half2[3] ^= ( tempmask1 >> 6 );
                }

                // combine
                tempblock[0] = half1[0];
                tempblock[1] = half1[1];
                tempblock[2] = half1[2];
                tempblock[3] ^= half1[3];

                tempblock[3] ^= half2[0];
                tempblock[4] = half2[1];
                tempblock[5] = half2[2];
                tempblock[6] = half2[3];

               // std::cout << fc_block56tohex(tempblock) << std::endl;

                // permutation choice 2
                for (int i2=0; i2<6; i2++) {
                    for (int i3=0; i3<8; i3++) {
                        byte temp = pc2[i3 + (i2 * 8)] - 1;
                        int remainder = temp % 8;
                        int div = temp / 8;

                        byte mask = ( ( tempblock[div] << remainder ) & (0x01 << 7 ) ) >> i3;
                        roundkeys[i-1][i2] ^= mask;
                    }
                }

            }
            
        }
        // its over for now


        ~DEA64() {}

        std::string hexoriginaltext;
        std::string hexcyphertext;

        // !! LONG FUNCTION INCOMING !!
        block_32 fc_func(block_32 block, key_48 roundkey) {
            // expansion permutation
            block_48 xorblock = {0, 0, 0, 0, 0, 0};
            // std::cout << fc_block32tohex(block) << std::endl;

            { // blocks to get rid of temporaries
                block_48 tempblock = {0, 0, 0, 0, 0, 0};
                for (int i=0; i<6; i++) {
                    for (int i2=0; i2<8; i2++) {
                        byte temp = fcexp[i2 + (i * 8)] - 1;
                        int remainder = temp % 8;
                        int div = temp / 8;

                        byte mask = ( ( block[div] << remainder ) & (0x01 << 7 ) ) >> i2;
                        tempblock[i] ^= mask;
                    }
                }

                //std::cout << fc_block48tohex(tempblock) << std::endl;

                // xor with round key
                xorblock = fc_byteXOR48(tempblock, roundkey);
                //std::cout << fc_block48tohex(xorblock) << std::endl;
            }

            // Substitution with round boxes
            block_32 subBlock = {0, 0, 0, 0};

            { // blocks to get rid of nasty temporaries
                byte group6[8];
                
                // split into six again
                group6[0] = ( xorblock[0] >> 2 );
                group6[1] = ( ( ( ( xorblock[0] & (0x03) ) << 4 ) ^ ( xorblock[1] >> 4 ) ) );
                group6[2] = ( ( ( xorblock[1] << 2 ) ^ ( xorblock[2] >> 6 ) ) & (0xff >> 2) );
                group6[3] = ( xorblock[2] & (0xff >> 2) );

                group6[4] = ( xorblock[3] >> 2 );
                group6[5] = ( ( ( ( xorblock[3] & (0x03) ) << 4 ) ^ ( xorblock[4] >> 4 ) ) & (0xff >> 2) );
                group6[6] = ( ( ( xorblock[4] << 2 ) ^ ( xorblock[5] >> 6 ) ) & (0xff >> 2) );
                group6[7] = ( xorblock[5] & (0xff >> 2) );

                //std::cout << fc_arrtohex(group6, 8) << std::endl;

                byte group4[8];

                // substitution with sboxes
                group4[0] = sbox1[ ( ( group6[0] & (0x01) ) ^ ( ( group6[0] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[0] & ( 0x1e ) ) >> 1) ];
                group4[1] = sbox2[ ( ( group6[1] & (0x01) ) ^ ( ( group6[1] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[1] & ( 0x1e ) ) >> 1) ];
                group4[2] = sbox3[ ( ( group6[2] & (0x01) ) ^ ( ( group6[2] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[2] & ( 0x1e ) ) >> 1) ];
                group4[3] = sbox4[ ( ( group6[3] & (0x01) ) ^ ( ( group6[3] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[3] & ( 0x1e ) ) >> 1) ];
                group4[4] = sbox5[ ( ( group6[4] & (0x01) ) ^ ( ( group6[4] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[4] & ( 0x1e ) ) >> 1) ];
                group4[5] = sbox6[ ( ( group6[5] & (0x01) ) ^ ( ( group6[5] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[5] & ( 0x1e ) ) >> 1) ];
                group4[6] = sbox7[ ( ( group6[6] & (0x01) ) ^ ( ( group6[6] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[6] & ( 0x1e ) ) >> 1) ];
                group4[7] = sbox8[ ( ( group6[7] & (0x01) ) ^ ( ( group6[7] & (0x01 << 5) ) >> 4 ) ) ][ ( ( group6[7] & ( 0x1e ) ) >> 1) ];

                //std::cout << fc_arrtohex(group4, 8) << std::endl;

                // back into 32 bits!
                for (int i=0; i<4; i++) {
                    subBlock[i] = (group4[i * 2] << 4) ^ (group4[i * 2 + 1]);
                }

                //std::cout << fc_block32tohex(subBlock) << std::endl;

            }

            // permutation with p box (TODO: me angy. fix.) <-- no longer angy, but still fix <--- not really fixed <-- gotta fix
            block_32 returnBlock = {0, 0, 0, 0};

            for (int i=0; i<4; i++) {
                for (int i2=0; i2<8; i2++) {
                    byte temp = endp[i2 + (i * 8)] - 1;
                    int remainder = temp % 8;
                    int div = temp / 8;

                    byte mask = ( ( subBlock[div] << remainder ) & (0x01 << 7 ) ) >> i2;
                    returnBlock[i] ^= mask;
                }
            }

            //std::cout << fc_block32tohex(returnBlock) << std::endl;

            return returnBlock;
        }
        // its safe now :)
        
        std::string encrypt(std::string str) {
            block_32 l, r;
            block_32 r2, l2;
            std::string returnVal;

            int loop = str.length() / 8;
            if  (str.length() % 8 != 0) {loop++;}
            for (int i=0; i<str.length() % 8; i++) {
                str.push_back('0');
            }

            hexcyphertext = "";

            for (int i=0; i<loop; i++) {

                block_64 ipblock = {0, 0, 0, 0, 0, 0, 0, 0};
                // initial permutation
                for (int i2=0; i2<8; i2++) {
                    for (int i3=0; i3<8; i3++) {
                        byte temp = ip[i3 + (i2 * 8)] - 1;
                        int remainder = temp % 8;
                        int div = temp / 8;

                        byte mask = ( ( str[div + (i * 8)] << remainder ) & (0x01 << 7 ) ) >> i3;
                        ipblock[i2] ^= mask;
                    }
                }

                // fill l and r
                l[0] = ipblock[0];
                l[1] = ipblock[1];
                l[2] = ipblock[2];
                l[3] = ipblock[3];

                r[0] = ipblock[4];
                r[1] = ipblock[5];
                r[2] = ipblock[6];
                r[3] = ipblock[7];

                for (int i2=0; i2<16; i2++) {
                    r2 = fc_byteXOR32(l, fc_func(r, roundkeys[i2]));
                    l = r; 
                    r = r2;
                    //std::cout << fc_block32tohex(l) << ' ' << fc_block32tohex(r) << ' ' << fc_block48tohex(roundkeys[i2]) << std::endl;
                }
                

                // combine in reverse
                ipblock[0] = r[0];
                ipblock[1] = r[1];
                ipblock[2] = r[2];
                ipblock[3] = r[3];
                
                ipblock[4] = l[0];
                ipblock[5] = l[1];
                ipblock[6] = l[2];
                ipblock[7] = l[3];
                
                //std::cout << fc_block64tohex(ipblock) << std::endl;

                block_64 cypherblock = {0, 0, 0, 0, 0, 0, 0, 0};
                // reverse
                for (int i2=0; i2<8; i2++) {
                    for (int i3=0; i3<8; i3++) {
                        byte temp = ipr[i3 + (i2 * 8)] - 1;
                        int remainder = temp % 8;
                        int div = temp / 8;

                        byte mask = ( ( ipblock[div] << remainder ) & (0x01 << 7 ) ) >> i3;
                        cypherblock[i2] ^= mask;
                    }
                }

                hexcyphertext += fc_block64tohex(cypherblock);
                
                returnVal += fc_block64tostring(cypherblock);
            }

            return returnVal;
        }

        std::string decrypt(std::string str) {
           block_32 l, r;
            block_32 r2, l2;
            std::string returnVal;

            int loop = str.length() / 8;

            for (int i=0; i<loop; i++) {

                block_64 ipblock = {0, 0, 0, 0, 0, 0, 0, 0};
                // initial permutation
                for (int i2=0; i2<8; i2++) {
                    for (int i3=0; i3<8; i3++) {
                        byte temp = ip[i3 + (i2 * 8)] - 1;
                        int remainder = temp % 8;
                        int div = temp / 8;

                        byte mask = ( ( str[div + (i * 8)] << remainder ) & (0x01 << 7 ) ) >> i3;
                        ipblock[i2] ^= mask;
                    }
                }

                //std::cout << fc_block64tohex(ipblock) << std::endl;

                // fill l and r
                l[0] = ipblock[0];
                l[1] = ipblock[1];
                l[2] = ipblock[2];
                l[3] = ipblock[3];

                r[0] = ipblock[4];
                r[1] = ipblock[5];
                r[2] = ipblock[6];
                r[3] = ipblock[7];

                for (int i2=15; i2>=0; i2--) {
                    r2 = fc_byteXOR32(l, fc_func(r, roundkeys[i2]));
                    l = r; 
                    r = r2;
                    //std::cout << fc_block32tohex(l) << ' ' << fc_block32tohex(r) << ' ' << fc_block48tohex(roundkeys[i2]) << std::endl;
                }
                

                // combine in reverse
                ipblock[0] = r[0];
                ipblock[1] = r[1];
                ipblock[2] = r[2];
                ipblock[3] = r[3];
                
                ipblock[4] = l[0];
                ipblock[5] = l[1];
                ipblock[6] = l[2];
                ipblock[7] = l[3];
                
                //std::cout << fc_block64tohex(ipblock) << std::endl;

                block_64 cypherblock = {0, 0, 0, 0, 0, 0, 0, 0};
                // reverse
                for (int i2=0; i2<8; i2++) {
                    for (int i3=0; i3<8; i3++) {
                        byte temp = ipr[i3 + (i2 * 8)] - 1;
                        int remainder = temp % 8;
                        int div = temp / 8;

                        byte mask = ( ( ipblock[div] << remainder ) & (0x01 << 7 ) ) >> i3;
                        cypherblock[i2] ^= mask;
                    }
                }

                hexoriginaltext += fc_block64tohex(cypherblock);
                
                returnVal += fc_block64tostring(cypherblock);
            }

            return returnVal;
        }
    };
};


int main() 
{   
    DEAcrypt::key_64 testkey = {170, 187, 9, 24, 39, 54, 204, 221};
    DEAcrypt::key_64 key2 = {10, 53, 33, 45, 112, 77, 190, 23};
    DEAcrypt::key_64 key3 = {72, 16, 35, 145, 65, 10, 29, 114};
    DEAcrypt::block_64 toencrypt = {18, 52, 86, 171, 205, 19, 37, 54};
    //DEAcrypt::block_64 test64 = {'d', 'i', 's', 'a', 'g', 'r', 'e', 'e'};

    std::string strenc = "Hello World!";

    DEAcrypt::DEA64 dea(testkey);
    DEAcrypt::DEA64 dea2(key2);
    DEAcrypt::DEA64 dea3(key3);

    /*std::cout << DEAcrypt::fc_block64tohex(testkey) << std::endl;
    std::cout << DEAcrypt::fc_block64tohex(key2) << std::endl;
    std::cout << DEAcrypt::fc_block64tohex(key3) << std::endl;
    std::cout << DEAcrypt::fc_block64tohex(toencrypt) << std::endl;*/

    /*for (int i=0; i<16; i++) {
        std::cout << DEAcrypt::fc_block48tohex(dea.roundkeys[i]) << std::endl;
    }*/

    std::string ec = dea3.encrypt(dea2.decrypt(dea.encrypt(strenc)));
    //std::cout << dea3.hexcyphertext << std::endl;

    std::string de = dea.decrypt(dea2.encrypt(dea3.decrypt(ec)));
    //std::cout << de << std::endl;
 
    return 0;
}
