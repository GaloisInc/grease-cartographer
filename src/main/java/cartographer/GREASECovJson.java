package cartographer;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.AccessMode;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import ghidra.program.model.address.Address;

public class GREASECovJson {
    private HashMap<Long, TreeMap<Long, MemoryBlock>> regionToBlockOffset;

    private static HashMap<Long, String> sectionNameToIndex(Program prog) throws IOException, ElfException {
        var pth = prog.getExecutablePath();
        // TODO: There ought to be a way to get the FSRL
        var flBts = new FileByteProvider(new File(pth), null, AccessMode.READ);
        var header = new ElfHeader(flBts, null);
        HashMap<Long, String> mp = new HashMap<>();
        Long ind = 0L;
        for (var sec : header.getSections()) {
            mp.put(ind++, sec.getNameAsString());
        }

        return mp;
    }

    public GREASECovJson(String section_infos, Program prog) throws IOException, ElfException {
        var sections = parseSectionInfos(section_infos);
        // TODO: this relies on looking up block by name matching the section name which
        // is usually true
        // but we should use the byte source + section offset to do a more precise
        // mapping to the loaded memory block
        var sectionIndexToName = sectionNameToIndex(prog);
        for (var sinfo : sections) {
            if (sectionIndexToName.containsKey(sinfo.section_index)) {
                var targetSectionName = sectionIndexToName.get(sinfo.section_index);
                var potentialBlock = prog.getMemory().getBlock(targetSectionName);
                if (potentialBlock != null) {
                    var offMap = regionToBlockOffset.putIfAbsent(sinfo.section_mem_addr.region_index, new TreeMap<>());
                    offMap.put(sinfo.section_mem_addr.region_offset, potentialBlock);
                }
            }
        }
    }

    public Optional<Address> GREASEMemAddrToMaybeAddr(GREASEMemAddr gaddr) {
        if (!regionToBlockOffset.containsKey(gaddr.region_index)) {
            return Optional.empty();
        }

        var offMap = regionToBlockOffset.get(gaddr.region_index);
        var ent = offMap.floorEntry(gaddr.region_offset);
        if (ent == null) {
            return Optional.empty();
        }

        // We need to compute the offset into the block. That is the
        // (region_offset-section_mem_addr)
        // We add that to the base of the block to get the Ghidra address
        // Then we need to check that the address is in bounds
        var maybeAddress = ent.getValue().getStart().add(gaddr.region_offset - ent.getKey());
        if (ent.getValue().contains(maybeAddress)) {
            return Optional.of(maybeAddress);
        }

        return Optional.empty();
    }

    public static class BlockInfo {
        public MemoryBlock block;

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
