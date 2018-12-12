import com.antivirus.scanner.Constant;
import com.antivirus.scanner.utils.UnsignedTypes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
public class CharacteristicsTest {

    @Test
    public void testCharacteristics(){
        String[] characteristic = new String[]{"40","00","00","40"};

        assertFalse(UnsignedTypes.checkCharacteristic(characteristic, Constant.IMAGE_SCN_MEM_DISCARDABLE));
        assertFalse(UnsignedTypes.checkCharacteristic(characteristic, Constant.IMAGE_SCN_MEM_SHARED));

        assertTrue(UnsignedTypes.checkCharacteristic(characteristic, Constant.IMAGE_SCN_MEM_READ));
        assertTrue(UnsignedTypes.checkCharacteristic(characteristic, Constant.IMAGE_SCN_CNT_INITIALIZED_DATA));

    }
}
