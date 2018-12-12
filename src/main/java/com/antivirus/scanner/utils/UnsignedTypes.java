package com.antivirus.scanner.utils;

import org.apache.commons.lang3.ArrayUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


/**
 * @author Taras Danylchenko
 * class for work with unsignedTypes such as WORD and DWORD
 * all values which returns is seek pos in the file (except for methods which return char[])
 */

public class UnsignedTypes {
    private RandomAccessFile file;
    private static final HashMap<String, Integer> hexAlphabet = new HashMap<String, Integer>() {{
        put("A", 10);
        put("B", 11);
        put("C", 12);
        put("D", 13);
        put("E", 14);
        put("F", 15);
    }};

    public UnsignedTypes(RandomAccessFile randomAccessFile) {
        this.file = randomAccessFile;
    }

    public int readWORD(long seekPos) throws IOException {
        return this.readFullyWORD(seekPos);
    }

    public int readDWORD(long seekPos) throws IOException {
        return this.readFullyDWORD(seekPos);
    }

    public char[] readChars(long seekPos, int bytesToRead) throws IOException {
        char[] buffer = new char[bytesToRead];
        int count = 0;
        byte b;
        file.seek(seekPos);
        for (int i = 0; i < bytesToRead; i++) {
            b = file.readByte();
            if (String.format("%02X", b).equals("00"))
                continue;
            buffer[i] = (char) b;
            count++;
        }
        return Arrays.copyOfRange(buffer, 0, count);
    }

    public byte[] readByte(long seekPos, int bytesToRead) throws IOException {
        byte[] buffer = new byte[bytesToRead];
        file.seek(seekPos);
        file.readFully(buffer, 0, bytesToRead);
        return buffer;
    }

    public String[] readCharacteristics(long seekPos, int bytesToRead) throws IOException {
        byte[] buffer = new byte[bytesToRead];
        String[] strings = new String[bytesToRead];
        file.seek(seekPos);
        file.readFully(buffer, 0, bytesToRead);
        ArrayUtils.reverse(buffer);
        for (int i = 0; i < buffer.length; i++) {
            strings[i] = String.format("%02X", buffer[i]);
        }
        return strings;
    }

    public static boolean checkCharacteristic(@NotNull String[] characteristics, int toMatch) {
        //TODO algorithm to check characteristic
        String characteristic[] = String.format("%08X", toMatch).split("(?<=\\G.{2})");
        int i = 0;
        for (String s : characteristics) {
            if (!characteristic[i].equals("00")) {
                String var0 = characteristics[i].substring(0, 1);
                if (s.equals(characteristic[i])) {
                    return true;
                }
                if (hexAlphabet.containsKey(var0)) {
                    int var1 = hexAlphabet.get(var0);
                    int var2 = Integer.parseInt(characteristic[i].substring(0, 1));
                    if ((var2 + 4) == var1 || (var2 + 8) == var1){
                        return true;
                    }
                } else {
                    int var1 = Integer.parseInt(var0);
                    int var2 = Integer.parseInt(characteristic[i].substring(0, 1));
                    if (var1 % 2 != 0 && var2!=0) {
                        if ((var2 + 1) == var1 || (var2 + 4) == var1) {
                            return true;
                        }
                    } else {
                        if ((var2 + 2) == var1 || (var2 + 4) == var1 && var2!=0) {
                            return true;
                        }
                    }
                }
            }
            i++;
        }
        return false;
    }

    private int readFullyWORD(long seekPos) throws IOException {
        byte[] buffer = new byte[2];
        file.seek(seekPos);
        file.readFully(buffer, 0, 2);
        return this.read(buffer);
    }

    private int readFullyDWORD(long seekPos) throws IOException {
        byte[] buffer = new byte[4];
        file.seek(seekPos);
        file.readFully(buffer, 0, 4);
        return this.read(buffer);
    }

    private int read(byte[] buffer) {
        ArrayUtils.reverse(buffer);
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < buffer.length; i++) {
            hex.append(String.format("%02X", buffer[i]));
        }
        return Integer.parseUnsignedInt(hex.toString(), 16);
    }

}
