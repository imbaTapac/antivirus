package com.antivirus.scanner;

import com.antivirus.scanner.entity.Malware;
import com.antivirus.scanner.repository.MalwareRepository;
import com.antivirus.scanner.utils.MalwareUtils;
import com.antivirus.scanner.utils.SignatureUtils;
import com.antivirus.scanner.utils.StaticDataEngine;
import com.antivirus.scanner.utils.UnsignedTypes;
import com.github.junrar.Archive;
import com.github.junrar.exception.RarException;
import com.github.junrar.impl.FileVolumeManager;
import com.github.junrar.rarfile.FileHeader;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class FileScanner {
    private final long MAX_FILE_SIZE = 25000000; //MB
    private final String MD5 = "MD5";
    private final int FILE_OR_FOLDER = 1;
    private final int RAR_ARCHIVE = 2;
    private final int ZIP_ARCHIVE = 3;
    public static Logger log = LoggerFactory.getLogger(FileScanner.class);
    private List<Malware> malwares;
    private List<File> exeFiles = new ArrayList<>();
    private int lastObjectEntry = 0;
    private final MalwareRepository malwareRepository;

    @Autowired
    public FileScanner(MalwareRepository malwareRepository) {
        this.malwareRepository = malwareRepository;
        this.malwares = StaticDataEngine.MALWARE_LIST;
    }

    public void startScan(String dir) throws IOException, NoSuchAlgorithmException, RarException {
        if (checkFolderType(dir) == FILE_OR_FOLDER) {
            folderScanner(dir);
        }
        if (checkFolderType(dir) == RAR_ARCHIVE) {
            rarScanner(dir);
        }
    }

    private void folderScanner(String dir) throws IOException, NoSuchAlgorithmException {
        File folder = new File(dir);
        listFilesForFolder(folder);
        log.info("List file size : " + exeFiles.size());
        MessageDigest digest = MessageDigest.getInstance(MD5);
        for (File file : exeFiles) {
            log.info("Open file : " + file.getName());
            checkPE(file);
        }
        //updateBase();
    }

    private void rarScanner(String dir) throws IOException, RarException, NoSuchAlgorithmException {
        Archive archive = new Archive(new FileVolumeManager(new File(dir)));
        MessageDigest digest = MessageDigest.getInstance(MD5);
        for (FileHeader fh : archive.getFileHeaders()) {
            System.out.println(fh.getFileNameString());
            byte[] bytes = fh.getFileNameByteArray();
            digest.digest(bytes);
            StringBuilder hashSum = new StringBuilder();
            for (byte b : digest.digest()) {
                hashSum.append(String.format("%02X", b));
            }
            System.out.println(hashSum);
        }
    }

    private void listFilesForFolder(File folder) throws IOException {
        log.info("Trying to open path : " + folder.getPath());
        if (folder.exists()) {
            if (folder.listFiles() != null) {
                for (File fileEntry : folder.listFiles()) {
                    // TODO do not forget to remove this
                    if (fileEntry.getName().equals("node_modules")) continue;
                    if (fileEntry.isDirectory()) {
                        listFilesForFolder(fileEntry);
                    } else {
                        if (fileEntry.getName().toLowerCase().endsWith(".exe")
                                && fileEntry.length() <= MAX_FILE_SIZE) {
                            log.info("Adding file to exeList : " + fileEntry.getName());
                            exeFiles.add(fileEntry);
                        }
                    }
                }
            }
        } else {
            throw new FileNotFoundException("File/Directory does not exist");
        }
    }

    private int checkFolderType(String dir) throws FileNotFoundException {
        if (dir.endsWith(".rar")) {
            return RAR_ARCHIVE;
        }
        if (dir.endsWith(".zip")) {
            return ZIP_ARCHIVE;
        }
        if (new File(dir).exists()) {
            return FILE_OR_FOLDER;
        } else {
            throw new FileNotFoundException("Unable to open file or folder");
        }
    }

    private void updateBase() throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance(MD5);
        List<Malware> malwares = new ArrayList<>();
        for (File file : exeFiles) {
            Malware malware = new Malware();
            malware.setMalwareName(FilenameUtils.getBaseName(file.getName()));
            malware.setByteSignature(SignatureUtils.byteSignature(file));

            String checksum = SignatureUtils.checksum(malware.getByteSignature(), digest);
            malware.setMD5hash(checksum);

            malwares.add(malware);
        }
        malwareRepository.saveAll(malwares);
    }

    private void checkPE(File file) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(file, "r");
        UnsignedTypes ut = new UnsignedTypes(raf);
        DOSHeader dosHeader = new DOSHeader();
        DOSStub dosStub = new DOSStub();
        PEHeader peHeader = new PEHeader();
        PE pe = new PE(dosHeader, dosStub, peHeader);

        dosHeader.setDOSSignature(ut.readByte(0, 2));

        if (dosHeader.isValid()) {
            log.info("This is PE file");

            dosHeader.setPEOffset(ut.readDWORD(0x3C));

            log.info("PE Offset is " + dosHeader.getPEOffset());

            peHeader.setSignature(ut.readByte(dosHeader.getPEOffset(), 4));

            if (peHeader.isValid()) {
                dosStub.setStub(ut.readByte(0x40, dosHeader.getPEOffset() - 0x40));
                log.info("PE Header Founded");
                scanPEHeader(ut, pe);

                log.info("Scanning free PEHeader space in  " + file.getName());
                MalwareUtils.checkInHead(raf, pe.getSectionTable().get(0).getVirtualAddress(), lastObjectEntry);

                log.info("Scanning free space between sections");
                MalwareUtils.checkSectionTail(raf, pe.getSectionTable(), pe.getPeHeader().getFileAlignment());
            }
        }
    }

    private void scanPEHeader(UnsignedTypes ut, PE pe) throws IOException {
        PEHeader peHeader = pe.getPeHeader();
        List<SectionTable> sectionTables = new ArrayList<>();
        long PEOffset = pe.getDosHeader().getPEOffset();
        long objectEntry = PEOffset + PEHeader.PEHeaderSize;
        boolean alignmentFlag = false;

        peHeader.setNumberOfSections(ut.readWORD(PEOffset + 0x6));
        peHeader.setNTHeaderSize(ut.readWORD(PEOffset + 0x14));
        peHeader.setMagic(ut.readByte(PEOffset + 0x18, 2));
        peHeader.setEntryPointRVA(ut.readDWORD(PEOffset + 0x28));
        peHeader.setSectionAlignment(ut.readDWORD(PEOffset + 0x38));
        peHeader.setFileAlignment(ut.readDWORD(PEOffset + 0x3C));
        peHeader.setHeaderSize(ut.readDWORD(PEOffset + 0x54));

        log.info("Num of sections " + peHeader.getNumberOfSections());
        log.info("NTHeader size " + peHeader.getNTHeaderSize());
        log.info("Entry Point " + peHeader.getEntryPointRVA());
        log.info("Object Align " + peHeader.getSectionAlignment());
        log.info("File Align " + peHeader.getFileAlignment());
        log.info("HeaderSize " + peHeader.getHeaderSize());

        if (peHeader.getSectionAlignment() >= 0x1000 && peHeader.getFileAlignment() >= 0x200 && peHeader.getSectionAlignment() >= peHeader.getFileAlignment()) {
            log.info("Alignment is right");
            alignmentFlag = true;
        }

        if (peHeader.isMagic() && !peHeader.isPE64()) {
            log.info("This is PE32 file");

            for (int i = 0; i < peHeader.getNumberOfSections(); i++) {
                SectionTable sectionTable = new SectionTable();
                sectionTable.setObjectName(ut.readChars(objectEntry, 0x8));
                sectionTable.setVirtualSize(ut.readDWORD(objectEntry + 0x8));
                sectionTable.setVirtualAddress(ut.readDWORD(objectEntry + 0xC));
                sectionTable.setPhysicalSize(ut.readDWORD(objectEntry + 0x10));
                sectionTable.setPhysicalOffset(ut.readDWORD(objectEntry + 0x14));
                sectionTable.setSectionFlags(ut.readCharacteristics(objectEntry + 0x24, 4));

                sectionTables.add(sectionTable);

                log.info("Object Name " + String.valueOf(sectionTable.getObjectName()));
                log.info("Virtual size " + sectionTable.getVirtualSize());
                log.info("Virtual address " + sectionTable.getVirtualAddress());
                log.info("Physical Size " + sectionTable.getPhysicalSize());
                log.info("Physical Offset " + sectionTable.getPhysicalOffset());
                log.info("Section flags " + Arrays.toString(sectionTable.getSectionFlags()));

                if(!alignmentFlag){
                    log.info("This is non alignmented file, checking virtual and physical address of sections");
                    if(sectionTable.getVirtualAddress() == sectionTable.getPhysicalOffset() && peHeader.getSectionAlignment() == peHeader.getFileAlignment()){
                        alignmentFlag = true;
                        log.info("Section alignment is right");
                    }
                }

                objectEntry += SectionTable.objectTableSize;
            }
        }

        pe.setPeHeader(peHeader);
        pe.setSectionTable(sectionTables);
        lastObjectEntry = (int) objectEntry;
    }
}

