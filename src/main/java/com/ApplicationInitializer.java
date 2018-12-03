package com;

import com.antivirus.scanner.FileScanner;
import com.antivirus.scanner.repository.MalwareRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableJpaRepositories(basePackages = "com.antivirus.scanner.repository")
@EnableTransactionManagement
public class ApplicationInitializer implements CommandLineRunner {

    @Autowired
    MalwareRepository malwareRepository;

    public static void main(String[] args) {
        SpringApplication.run(ApplicationInitializer.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        String dir = "/home/tarasii/Документы/Viruses-for-Anti-Virus17999/";
        String test = "/media/sf_Documents";
        FileScanner scanner = new FileScanner(malwareRepository);
        scanner.startScan(test);
    }
}

