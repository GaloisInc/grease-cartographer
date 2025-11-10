package cartographer;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.TreeMap;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

public class GREASECovJson {
    private HashMap<Long, TreeMap<Long, MemoryBlock>> regionToBlockOffset;

    public GREASECovJson(String section_infos, Program prog) {
        parseSectionInfos(section_infos);
    }

    public static class GREASEMemAddr {
        public Long region_index;
        public Long region_offset;
    }

    public static class GREASESectionInfo {
        public Long section_index;
        public GREASEMemAddr section_mem_addr;
    }

    public static GREASEMemAddr parseAddr(String json_arg) {
        return parseMappaeble(json_arg);
    }

    public static List<GREASESectionInfo> parseSectionInfos(String json_arg) {
        return parseMappaeble(json_arg);
    }

    public static <T> T parseMappaeble(String json_arg) {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json_arg, new TypeReference<>() {
        });
    }
}
