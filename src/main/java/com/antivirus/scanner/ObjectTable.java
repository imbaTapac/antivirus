package com.antivirus.scanner;

public class ObjectTable {
    public static final long objectTableSize = 40;

    private char[] objectName;
    private int virtualSize;
    private int sectionRVA;
    private int physicalSize;
    private int physicalOffset;
    private char reserved;
    private int objectFlags;

    public ObjectTable(){

    }

    public char[] getObjectName() {
        return objectName;
    }

    public void setObjectName(char[] objectName) {
        this.objectName = objectName;
    }

    public int getVirtualSize() {
        return virtualSize;
    }

    public void setVirtualSize(int virtualSize) {
        this.virtualSize = virtualSize;
    }

    public int getSectionRVA() {
        return sectionRVA;
    }

    public void setSectionRVA(int sectionRVA) {
        this.sectionRVA = sectionRVA;
    }

    public int getPhysicalSize() {
        return physicalSize;
    }

    public void setPhysicalSize(int physicalSize) {
        this.physicalSize = physicalSize;
    }

    public int getPhysicalOffset() {
        return physicalOffset;
    }

    public void setPhysicalOffset(int physicalOffset) {
        this.physicalOffset = physicalOffset;
    }

    public char getReserved() {
        return reserved;
    }

    public void setReserved(char reserved) {
        this.reserved = reserved;
    }

    public int getObjectFlags() {
        return objectFlags;
    }

    public void setObjectFlags(int objectFlags) {
        this.objectFlags = objectFlags;
    }
}
