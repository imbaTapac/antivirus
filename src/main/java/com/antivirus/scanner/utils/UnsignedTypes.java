package com.antivirus.scanner.utils;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.util.Arrays;

public class UnsignedTypes {
    private RandomAccessFile file;

    public UnsignedTypes(RandomAccessFile randomAccessFile) {
        this.file = randomAccessFile;
    }

    public int readWORD(long seekPos) throws IOException {
        byte[] buffer = new byte[2];
        file.seek(seekPos);
        file.readFully(buffer, 0, 2);
        return read(buffer);
    }

    public int readDWORD(long seekPos) throws IOException {
        byte[] buffer = new byte[4];
        file.seek(seekPos);
        file.readFully(buffer, 0, 4);
        return read(buffer);
    }

    public char[] readChars(long seekPos, int bytesToRead) throws IOException {
        char[] buffer = new char[bytesToRead];
        int count = 0;
        byte b;
        file.seek(seekPos);
        for (int i = 0; i < bytesToRead; i++) {
            b = file.readByte();
            if(String.format("%02X",b).equals("00"))
                continue;
            buffer[i] = (char) b;
            count++;
        }
        return Arrays.copyOfRange(buffer,0,count);
    }

    private int read(byte[] mas) {
        int var1 = 0;
        String hex = "";
        for (int i = 0; i < mas.length; i++) {
            hex = String.format("%02X", mas[i]);
            var1 += new BigInteger(hex, 16).intValue();
        }
        return var1;
    }

    public int readFullyDWORD(long seekPos) throws IOException {
        byte[] buffer = new byte[4];
        file.seek(seekPos);
        file.readFully(buffer,0,4);
        StringBuilder hex = new StringBuilder();
        for(int i = 0; i< buffer.length ; i++){
            hex.append(String.format("%02X",buffer[i]));
        }
        hex.reverse();
        System.out.println(hex.toString());
        return Integer.parseUnsignedInt(hex.toString(),16);
    }

    public byte[] readByte(long seekPos, int bytesToRead) throws IOException {
        byte[] buffer = new byte[bytesToRead];
        file.seek(seekPos);
        file.readFully(buffer, 0, bytesToRead);
        return buffer;
    }

   /* public char[] readAddress(long seekPos,int bytesToRead){
        char[] buffer = new char[bytesToRead];
        file.seek(seekPos);
        for (int i = 0; i< bytesToRead;i++){
            buffer[i] =
        }
    }*/
}
