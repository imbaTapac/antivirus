package com.antivirus.scanner;

import java.util.Arrays;

public class PEHeader {
    public static final long PEHeaderSize = 248;
    private final byte[] signatureExpected = new byte[]{0x50, 0x45, 0x00, 0x00};
    private final byte[] magic32 = new byte[]{11, 1};
    private final byte[] magic64 = new byte[]{11, 2};

    private byte[] signature;
    private int numberOfSections;
    private int NTHeaderSize;
    private byte[] magic;
    private int entryPointRVA;
    private int sectionAlignment;
    private int fileAlignment;
    private int headerSize;

    public PEHeader() {

    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public int getNumberOfSections() {
        return numberOfSections;
    }

    public void setNumberOfSections(int numberOfSections) {
        this.numberOfSections = numberOfSections;
    }

    public byte[] getMagic() {
        return magic;
    }

    public void setMagic(byte[] magic) {
        this.magic = magic;
    }

    public int getNTHeaderSize() {
        return NTHeaderSize;
    }

    public void setNTHeaderSize(int NTHeaderSize) {
        this.NTHeaderSize = NTHeaderSize;
    }

    public int getEntryPointRVA() {
        return entryPointRVA;
    }

    public void setEntryPointRVA(int entryPointRVA) {
        this.entryPointRVA = entryPointRVA;
    }

    public int getSectionAlignment() {
        return sectionAlignment;
    }

    public void setSectionAlignment(int sectionAlignment) {
        this.sectionAlignment = sectionAlignment;
    }

    public int getFileAlignment() {
        return fileAlignment;
    }

    public void setFileAlignment(int fileAlignment) {
        this.fileAlignment = fileAlignment;
    }

    public int getHeaderSize() {
        return headerSize;
    }

    public void setHeaderSize(int headerSize) {
        this.headerSize = headerSize;
    }

    public boolean isValid() {
        return Arrays.equals(signature, signatureExpected);
    }

    public boolean isMagic() {
        return Arrays.equals(magic,magic64) || Arrays.equals(magic,magic32);
    }

    public boolean isPE64(){
        return Arrays.equals(magic,magic64);
    }
}