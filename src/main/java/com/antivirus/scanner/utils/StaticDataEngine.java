package com.antivirus.scanner.utils;

import com.antivirus.scanner.entity.Malware;
import com.antivirus.scanner.repository.MalwareRepository;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public final class StaticDataEngine {
    private static Logger log = LoggerFactory.getLogger(StaticDataEngine.class);

    public static List<Malware> MALWARE_LIST;

    private final MalwareRepository malwareRepository;

    private StaticDataEngine(MalwareRepository malwareRep) {
        this.malwareRepository = malwareRep;
        log.info("Loading static data ...");

        long start = DateTime.now().getMillis();
        MALWARE_LIST = malwareRepository.findAll();
        long time = DateTime.now().getMillis() - start;
        log.info("Loaded " + MALWARE_LIST.size() + " malwares");
        long seconds = time / 1000;
        String timeMsg = seconds > 0 ? seconds + " seconds" : time + "milliseconds";
        log.info("Static data loaded in : " + timeMsg);
    }
}
