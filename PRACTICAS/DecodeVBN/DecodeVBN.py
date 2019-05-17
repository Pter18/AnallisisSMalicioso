#!/usr/bin/python
#!# -*- coding: utf-8 -*-

import sys
import string
# Para obtenr la fecha y hora, la cual ocuparemos para nombrar a los nuevo archivo VBN creados
import datetime
# Modulo que contiene metodos para convertir representaciones binarias
import binascii
# Devuelve la representación hexadecimal a binario y viseversa
from binascii import hexlify,unhexlify

def readFile(file):
    '''
    Funcion que nos ayuda a leer los archivos con los que vamos a tarabajar ya sea para decifrar como para cifrar
    '''
    archivo = open(file,'rb').read()
    return archivo

def fileOriginalType(archivo):
    '''
    Recortamos la cabeceza agregada por SYMANTEC para encontrar el tipo de archivo original con su extension
    rfind nos regresa el index mas alto donde se encuentra la coincidencia.
    c:\users\user2\desktop\sample1.exe
    #                     ^
    '''
    temp = archivo[4:100]
    temp = temp[temp.rfind("\\")+1:]
    # Quitamos los caracteres inecesarios del nombre del archivo
    fileName = temp.rstrip(' \t\r\n\0')
    temp = temp[temp.find("."):]
    fileType = filter(str.isalnum, temp)

    return fileType, fileName

def fileType(archivo):
    '''
    Funcion que nos devuelve el tipo de archivo que se va a cifrar,
    a traves de la busqueda del numero maxico para tipo .exe MZ
    '''
    temp = archivo[0:100]
    if temp.find("MZ") != -1:
        fileType = "exe"
    return fileType

def xorOper(archivo,key=None):
    '''
    Funcion que realiza la operacion XOR entre la llave y todo el archivo,
    nos devuelve el criptograma o el archivo en claro, ya que la funcion XOR
    es reversible
    '''
    ciphertext = ''
    for i in range(len(archivo)):
        ciphertext += chr(key ^ ord(archivo[i]))

    return ciphertext

def findMZ(plaintext):
    '''
    Funcion que realiza la busqueda de los numeros magicos una vez que se
    realizo la operacion XOR por cada intento con la llave en turno por medio
    de fuerza bruta, la busqueda se realiza a traves de su representacion en
    hexadecinal de la cadena MZ que equivale a 4D5A
    '''
    fileHexTemp = conversion_bin_hex(plaintext)
    match = fileHexTemp.find("4D5A900003")
    if match != -1:
        #print "Se encontro el numero magico 4D5A900003 en index: %s" %str(match)
        return 0
    return 1

def break_xor( ciphertext ):
    '''
    Funcion que nos ayuda a romper el algoritmo de cifrado de la XOR a traves de la fuerza bruta
    realiza la operacion XOR con la llave en turno y en su resultado busca los numeros magicos.
    nos devuelve el texto en claro junto con la llave encontrada.
    '''
    for key in range(256):
        text = xorOper(ciphertext, key)
        match = findMZ(text)
        if match == 0:
            print "La llave encontrada: %s" %hex(key)
            break
    return text, key

def conversion_bin_hex(xor):
    '''
    Funcion que nos ayuda a convertir de binario a hexadecimal
    '''
    valorhex = hexlify(xor).upper()

    return valorhex

def archivoOriginal(valorhex,tipoArchivo):
    '''
    Funcion que tiene como proposito quitar la cabecera colocada por Symantec,
    con ayuda de la busqueda de los numeros magicos para .exe en hexadecimal
    MZ = 4D5A.
    Ademas Symantec agrega secuencias de distorsion que son F6C6F4FFFF y F6FFEFFFFF,
    esta funcion nos ayuda a eliminar estos caracteres inecesarios
    '''
    if tipoArchivo == 'exe':
        valorhex = (valorhex[valorhex.find("4D5A"):])
	valorhex = valorhex.replace("F6C6F4FFFF",'')
	valorhex = valorhex.replace("F6FFEFFFFF",'')

	return valorhex

def conversion_hex_bin(valorhex):
    '''
    Funcion que nos ayuda a convertir de hexadecimal a binario
    '''
    operxor = bytes(valorhex)
    operxor = (binascii.unhexlify(operxor))

    return operxor

def writeOriginalFile(fileBin,fileName):
    '''
    Funcion que nos ayuda a escribir el archivo original despues de decifrarlo.
    '''
    malware = open(fileName,'wb')
    malware.write(fileBin)
    malware.close()

def writeFileVBN(fileBin,fileName):
    '''
    Funcion que nos ayuda a escribir el archivo .VBN con el proceso de cifrado,
    en este nuevo archivo se agrega una cabecera que contiene el nombre original
    del archivo, parecida a la cabecera de Symantec. Al nombre del archivo se
    agreda la fecha y hora se su creacion.
    '''
    date = dateNow()
    malware = open("57"+date+".VBN",'wb')
    malware.write("....\\"+fileName)
    malware.write("                                                                                                                                               ")
    malware.write(fileBin)
    malware.close()

def checkKey(input_key):
    '''
    Funcion que nos ayuda a validar la longitud de la llave, la cual no debe ser mayor a 1 Byte = 256
    '''
    input_key = int(input_key,16)
    if input_key > 255:
      raise "Longitud de llave incorecta: La llave no debe ser mayor a 1 byte"
    return input_key

def dateNow():
    '''
    Funcion que nos devuelve la hora actual con el siguiente formato DMYHMS => 051719001111
    '''
    x = datetime.datetime.now()
    x = x.strftime("%x%X")
    date = filter(str.isalnum, x)
    return date

def modeDK(argv):
    '''
    Funcion que tiene la secuencia para trabajar en modo de Decifrado "D" con llave "K"
    de alli el nombre.
    '''
    key = checkKey(argv[3])
    file = readFile(argv[2])
    typeFile, fileName = fileOriginalType(file)
    result_xor = xorOper(file,key)
    fileHex = conversion_bin_hex(result_xor)
    fileHex = archivoOriginal(fileHex,typeFile)
    fileBin = conversion_hex_bin(fileHex)
    fileVBN = writeOriginalFile(fileBin,fileName)

def modeD(argv):
    '''
    Funcion que tiene la secuencia para trabajar en modo de Decifrado "D" sin llave,
    la cual se ocupa para realizar fuerza bruta a la llave.
    '''
    file = readFile(argv[2])
    typeFile, fileName = fileOriginalType(file)
    result_xor, key = break_xor(file)
    fileHex = conversion_bin_hex(result_xor)
    fileHex = archivoOriginal(fileHex,typeFile)
    fileBin = conversion_hex_bin(fileHex)
    fileVBN = writeOriginalFile(fileBin,fileName)

def modeCK(argv):
    '''
    Funcion que tiene la secuencia para trabajar en modo de Cifrado "C" cin llave "K",
    '''
    key = checkKey(argv[3])
    file = readFile(argv[2])
    fileName = argv[2]
    typeFile = fileType(file)
    result_xor = xorOper(file,key)
    fileVBN = writeFileVBN(result_xor,fileName)

def checkArgv(argv):
    '''
    Funcion valida los argumentos pasados por terminal, dependiendo de los argumentos colocados
    y el modo de funcion -d o -c, el programa se dirige a la funcion que tiene cada secuencia de
    trabajo de cada modo, en caso de no colocar los argumentos como es debido el programa se
    dirige a la funcion usage() de ayuda para el modo de uso correcto.
    '''
    if len(argv) == 4 and argv[1] == '-d':
        print "Modo Decifrado con llave"
        modeDK(argv)

    elif len(argv) == 3 and argv[1] == '-d':
        print "Modo Decifrado sin llave \"BruteForce\""
        modeD(argv)

    elif len(argv) == 4 and argv[1] == '-c':
        print "Modo Cifrado con llave"
        modeCK(argv)

    else:
        usage()

def main(argv):
    '''
    Funcion principal del programa u inicial
    '''
    checkArgv(argv)

def usage():
    '''
    Funcion que imprime en terminal la ayuda, la cual tiene la foema correcta de usar el programa
    '''
    print "Modo de uso para %s\n" %sys.argv[0]
    print "=== Decifrado ===\n"
    print "%s -d <file.VBN> <key>\n" %sys.argv[0]
    print "Ejemplo con llave:\n"
    print "\t%s -d <file.VBN> 0xFF\n" %sys.argv[0]
    print "Ejemplo con Fuerza Bruta:\n"
    print "\t%s -d <file.VBN>\n" %sys.argv[0]
    print "=== Cifrado ===\n"
    print "%s -c <file> <key>\n" %sys.argv[0]
    print "Ejemplo:\n"
    print "%s -c <file> 0xA5\n" %sys.argv[0]

if __name__ == "__main__":
    main(sys.argv)
