package com.antivirus.scanner;

import com.antivirus.scanner.entity.Malware;
import com.antivirus.scanner.repository.MalwareRepository;
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

import java.io.*;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

@Component
public class FileScanner {
    private final long MAX_FILE_SIZE = 25000000; //MB
    private final String MD5 = "MD5";
    private final int FILE_OR_FOLDER = 1;
    private final int RAR_ARCHIVE = 2;
    private final int ZIP_ARCHIVE = 3;
    private static Logger log = LoggerFactory.getLogger(FileScanner.class);
    private List<Malware> malwares;
    private List<File> exeFiles = new ArrayList<>();

    private final MalwareRepository malwareRepository;

    @Autowired
    public FileScanner(MalwareRepository malwareRepository) {
        this.malwareRepository = malwareRepository;
        this.malwares = StaticDataEngine.MALWARE_LIST;
    }

    public void startScan(String dir) throws IOException, NoSuchAlgorithmException, RarException {
        if (checkFolderType(dir) == FILE_OR_FOLDER) {
            folderSignatureScanner(dir);
        }
        if (checkFolderType(dir) == RAR_ARCHIVE) {
            rarSignatureScanner(dir);
        }
    }

    private void folderSignatureScanner(String dir) throws IOException, NoSuchAlgorithmException {
        File folder = new File(dir);
        listFilesForFolder(folder);
        log.info("List file size : " + exeFiles.size());
        MessageDigest digest = MessageDigest.getInstance(MD5);
        for (File file : exeFiles) {
            log.info("Open file : " + file.getName());
            //checkMalware(file, digest);
            checkPEHeader(file);
        }
        //updateBase();
    }

    private void rarSignatureScanner(String dir) throws IOException, RarException, NoSuchAlgorithmException {
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
                    log.info("Open : " + fileEntry.getName());
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
            malware.setByteSignature(byteSignature(file));

            String checksum = checksum(malware.getByteSignature(), digest);
            malware.setMD5hash(checksum);

            malwares.add(malware);
        }
        malwareRepository.saveAll(malwares);
    }

    private byte[] byteSignature(File file) throws IOException {
        byte[] signature = new byte[64];
        boolean isSignature = false;
        boolean endOfFile = false;
        long pointer = (long) Math.abs(file.length() / 1.5);
        long fileLength = file.length();
        RandomAccessFile raf = new RandomAccessFile(file, "r");
        while (!isSignature) {
            log.info("Read malware " + file.getName());
            int freeSpace = 0;
            raf.seek(pointer);
            raf.readFully(signature, 0, signature.length);
            for (int i = 0; i < 8; i++) {
                if (freeSpace > 4) {
                    break;
                }
                if (signature[i] == 0 || signature[i] == -112) {
                    freeSpace++;
                }
            }
            if (freeSpace <= 4) {
                isSignature = true;
            } else {
                if (pointer + 128 <= fileLength - signature.length && !endOfFile) {
                    pointer += 128;
                } else if (endOfFile) {
                    pointer -= 128;
                } else {
                    endOfFile = true;
                }

            }
        }
        return signature;
    }

    private String checksum(byte[] signature, MessageDigest md) {
        StringBuilder hashSum = new StringBuilder();
        for (byte b : md.digest(signature)) {
            hashSum.append(String.format("%02X", b));
        }

        return hashSum.toString();
    }

    private void checkMalware(File file, MessageDigest digest) {
        for (Malware malware : malwares) {
            log.info("Scanning file " + file.getName() + " for malware entry : " + malware.getMalwareName());
            byte[] malwareSignature = malware.getByteSignature();
            int pos = 0;
            int byteReaded = 0;
            try {
                DigestInputStream dis = new DigestInputStream(new FileInputStream(file), digest);
                while (dis.read() != -1) {
                    digest = dis.getMessageDigest();
                }
                //log.info(""+file.length());
                //log.info(""+digest.digest().length);
                while (byteReaded + malwareSignature.length < file.length()) {
                    for (byte b : digest.digest()) {
                        if (b == malwareSignature[pos]) {
                            pos++;
                        } else {
                            pos = 0;
                        }
                        byteReaded++;
                    }
                    if (pos == malwareSignature.length) {
                        log.info("In file " + file.getName() + " detected " + malware.getMalwareName());
                        break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void checkPEHeader(File file) throws IOException {
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
            }
        }
    }

    private void scanPEHeader(UnsignedTypes ut, PE pe) throws IOException {
        PEHeader peHeader = pe.getPeHeader();
        List<ObjectTable> objectTables = new ArrayList<>();
        long PEOffset = pe.getDosHeader().getPEOffset();
        long objectEntry = PEOffset + PEHeader.PEHeaderSize;

        peHeader.setNumberOfSections(ut.readWORD(PEOffset + 0x6));
        peHeader.setNTHeaderSize(ut.readWORD(PEOffset + 0x14));
        peHeader.setMagic(ut.readByte(PEOffset + 0x18, 2));
        peHeader.setEntryPointRVA(ut.readDWORD(PEOffset + 0x28));
        peHeader.setObjectAlign(ut.readDWORD(PEOffset + 0x38));
        peHeader.setFileAlign(ut.readDWORD(PEOffset + 0x3C));
        peHeader.setHeaderSize(ut.readDWORD(PEOffset + 0x54));

        log.info("Num of sections " + peHeader.getNumberOfSections());
        log.info("NTHeader size " + peHeader.getNTHeaderSize());
        log.info("Entry Point " + peHeader.getEntryPointRVA());
        log.info("Object Align " + peHeader.getObjectAlign());
        log.info("File Align " + peHeader.getFileAlign());
        log.info("HeaderSize " + peHeader.getHeaderSize());

        if(peHeader.isMagic() && !peHeader.isPE64()) {
            log.info("This is PE32 file");


            for (int i = 0; i < peHeader.getNumberOfSections(); i++) {
                ObjectTable objectTable = new ObjectTable();
                objectTable.setObjectName(ut.readChars(objectEntry, 0x8));
                objectTable.setVirtualSize(ut.readFullyDWORD(objectEntry + 0x8));
                objectTable.setSectionRVA(ut.readFullyDWORD(objectEntry + 0xC));
                objectTable.setPhysicalSize(ut.readFullyDWORD(objectEntry + 0x10));
                objectTable.setPhysicalOffset(ut.readFullyDWORD(objectEntry + 0x14));

                objectTables.add(objectTable);

                log.info("Object Name " + String.valueOf(objectTable.getObjectName()));
                log.info("Virtual size " + objectTable.getVirtualSize());
                log.info("Section RVA " + objectTable.getSectionRVA());
                log.info("Physical Size " + objectTable.getPhysicalSize());
                log.info("Physical Offset " + objectTable.getPhysicalOffset());

                objectEntry += ObjectTable.objectTableSize;
            }
        }

        pe.setPeHeader(peHeader);
        pe.setObjectTable(objectTables);

    }
}

