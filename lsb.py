#!/usr/bin/env python

## @file lsb.py
#  @title Least Significant Bit Algorithm
#  @author Karim El Shenawy
#  @date  19/07/2019

import cv2
import numpy as np
import binascii
import optparse

## @brief Least Significant Bit in Steganography is an information hiding algorithm in which information is hidden
# throught replacing pixel bits of an image.
class lsb:
    ## @brief global variables
    global z
    z = "111111111111111111111111111111111111111111111111111111111111111111111111111111110"

    ## @brief Converts ASCII characters to Binary
    #  @param s ASCII character
    #  @return Binary represenation
    def convASC2BIN(self, s):
        return str((8 - len(bin(int(binascii.hexlify(s), 16))[2:])) * 0 ) + bin(int(binascii.hexlify(s), 16))[2:]

    ## @brief Converts Binary to ASCII characters
    #  @param b Binary represenation
    #  @return ASCII character
    def convBIN2ASC(self, b):
        return binascii.unhexlify('%x' % int(b, 2))

    ## @brief Converts RBG pixel representation to Binary
    #  @param rbg RBG pixel representation
    #  @return Binary Representation
    def convRBG2BIN(self, rbg):
        return [bin(rbg[0])[2:], bin(rbg[1])[2:], bin(rbg[2])[2:]]

    ## @brief Converts Binary represenatation to RBG
    #  @param b Binary representation
    #  @return RBG pixel representation
    def convBIN2RBG(self, b):
        return [int(b[0] ,2), int(b[1], 2), int(b[2] ,2)]

    ## @brief Changes image pixel bit
    #  @param rbg RBG pixel to be modified
    #  @param c Bits to be inputted in RBG pixel
    #  @return Encrypted pixel in RBG representation
    def change_rbg(self, rbg, c):
        r = []; t = self.convRBG2BIN(rbg)
        for i in range(len(t)): r.append(t[i][0:len(t[i])-len(c[i])] + c[i]) # changes the the last bits
        return self.convBIN2RBG(r)

    ## @brief Encryption process
    #  @param text The text to be encrypted into image
    #  @param image The image file name
    #  @param key The key or number of bits to be encrypted per pixel
    #  @exception LargeKey occurs when the key is larger than 7
    #  @exception NotEnoughPixels occurs when Text is too big for image or when key is too small
    def encrypt(self, text, image, key = 1):
        if key > 7: raise LargeKey("Key is large.")
        img = cv2.imread(image); height, width, channels = img.shape; h, w = 0, 0
        bintext = "11111111111111111111111111111111"+ self.convASC2BIN(text) + (key - (len(self.convASC2BIN(text) + z)   %key))*'1' + z
        p = [bintext[i:i+key] for i in range(0, len(bintext), key)]
        l = [p[i:i+3] for i in range(0,len(p), 3)]
        for i in range(3-len(l[-1])): l[-1].append("")
        if len(l) > height*width: raise NotEnoughPixels("Not enough Pixels: Try a larger image or a bigger key")

        for i in l:
            if width <= w: h += 1; w = 0
            img[h][w] = self.change_rbg(img[h][w], i)
            w += 1

        cv2.imwrite("image.png", img)
        return "Encryption Succesfull"

    ## @brief Decryption Process
    #  @param image The image file name
    #  @param key The key or number of bits to be encrypted per pixel
    #  @exception LargeKey occurs when the key is larger than 7
    def decrypt(self, image, key = 1):
        if key > 7: raise LargeKey("Key is large.")
        img = cv2.imread(image); height, width, channels = img.shape; h, w = 0, 0
        text = ""; check = True
        while ((text.find(z) < 0) and check) :
            if width <= w: h += 1; w = 0
            text  += self.convRBG2BIN(img[h][w])[0][-key:] + self.convRBG2BIN(img[h][w])[1][-key:] + self.convRBG2BIN(img[h][w])[2][-key:]
            w += 1
            if(h >= height-1 and w >= width): check = False

        if check:
            decode = [self.convBIN2ASC((8-len(text[i:i+8]))*'0'+text[i:i+8]) for i in range(0, len(text)-20, 8)]
            return "Decryption successfull\nDecoded Message: \n" + ''.join(decode)
        else:
            return "Decryption Unsuccessfull"


speChar = [ ('1', 'xxxsxdxonexxxsxdx'), ('2', 'xxxsxdxtwoxxxsxdx'), ('3', 'xxxsxdxthreexxxsxdx'), ('4', 'xxxsxdxfourxxxsxdx'),
            ('5', 'xxxsxdxfivexxxsxdx'), ('6', 'xxxsxdxsixxxsxdxx'), ('7', 'xxxsxdxsevenxxxsxdx'), ('8', 'xxxsxdxeightxxxsxdx'),
            ('9', 'xxxsxdxninexxxsxdx'), ('0', 'xxxsxdxzeroxxxsxdx'), ('`', 'xxxsxdxgravexxxsxdx'), ('~', 'xxxsxdxtildexxxsxdx'),
            ('!', 'xxxsxdxexclamxxxsxdx'), ('@', 'xxxsxdxatxxxsxdx'), ('#', 'xxxsxdxhashtagxxxsxdx'), ('$', 'xxxsxdxdollarxxxsxdx'),
            ('%', 'xxxsxdxpercxxxsxdx'), ('^', 'xxxsxdxcircumxxxsxdx'), ('&', 'xxxsxdxandxxxsxdx'), ('*', 'xxxsxdxasteriskxxxsxdx'),
            ('(', 'xxxsxdxlparenxxxsxdx'), (')', 'xxxsxdxrparenxxxsxdx'), ('-', 'xxxsxdxdashxxxsxdx'), ('_', 'xxxsxdxunderxxxsxdx'),
            ('=', 'xxxsxdxequalxxxsxdx'), ('+', 'xxxsxdxplusxxxsxdx'), ('[', 'xxxsxdxlbracketxxxsxdx'), (']', 'xxxsxdxrbracketxxxsxdx'),
            ('{', 'xxxsxdxlcurlxxxsxdx'), ('}', 'xxxsxdxrcurlxxxsxdx'), ('\\', 'xxxsxdxlslashxxxsxdx'), ('|', 'xxxsxdxstraightxxxsxdx'),
            ('/', 'xxxsxdxrslashxxxsxdx'), ('?', 'xxxsxdxquestxxxsxdx'), (';', 'xxxsxdxsemixxxsxdx'), (':', 'xxxsxdxcolonxxxsxdx'),
            ('<', 'xxxsxdxlarrowxxxsxdx'), ('>', 'xxxsxdxrarrowxxxsxdx'), (',', 'xxxsxdxcommaxxxsxdx'), ('.', 'xxxsxdxperiodxxxsxdx'),
            ("'", 'xxxsxdxquotexxxsxdx'), ('"', 'xxxsxdxdquotexxxsxdx')]

## @brief convSpetoWrd converts special charcacters to string
#  @param txt string with special characters
def convSpetoWrd(txt):
    for i in range(len(speChar)):
        txt  = txt.replace(speChar[i][0], speChar[i][1])
    return txt

## @brief convWrstoSpe converts string to special charcacters
#  @param txt string with special characters
def convWrdtoSpe(txt):
    for i in range(len(speChar)):
        txt  = txt.replace(speChar[i][1], speChar[i][0])
    return txt

## @brief Interface method
def interface():
    parser = optparse.OptionParser('lsb '  + '-e/-d <target file>')
    parser.add_option('-e', dest='encrypt', type='string', help='Picture path')
    parser.add_option('-d', dest='decrypt', type='string', help='Picture path')
    a = lsb(); (opt, args) = parser.parse_args()
    if (opt.encrypt != None):
        text = raw_input("Enter message to encrypt: ")
        while text == "": text = raw_input("Enter message to encrypt: ")
        key = raw_input("Enter a key (Default key = 1): ")
        if key == '': key = 1
        text = convSpetoWrd(text)
        if (type(text) == type(123)): text = "N" + text
        print a.encrypt(str(text), opt.encrypt, int(key))
    elif (opt.decrypt != None):
        key = raw_input("Enter a key (press enter for Unknown key): ")
        if key == '':
            for i in range(1,8):
                result = convWrdtoSpe(a.decrypt(opt.decrypt, i))
                if(result[11] == "s"):
                    print result + "\n Key used is", i
                    break;
                else:
                    print result + " with Key", i

        else: print convWrdtoSpe(a.decrypt(opt.decrypt, int(key)))
    else: print parser.usage; exit(0)

if __name__ == '__main__':
    interface()
