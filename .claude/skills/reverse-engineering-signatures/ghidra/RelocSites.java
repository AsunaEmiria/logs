// Ghidra Java post-script: for each NAME=0xRVA of a data global (or function reached
// RIP-relatively) in the OLD analyzed DB, emit one sigscan pattern per referencing
// function: the instructions around the xref site with EVERY rel32 / RIP-relative
// disp32 wildcarded and the cursor (') placed on the disp32 that reaches the
// target. Scan the NEW exe with each pattern; new_rva = cursor_rva + 4 + k + disp,
// where k is the count of immediate bytes trailing the disp32 (printed per site).
//
// Args: NAME:0xRVA ... e.g. -postScript RelocSites.java SAVE_ROOT:0x7c22e40
// Filter with: grep 'RelocSites.java>'
//
// @category GBFR
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RelocSites extends GhidraScript {
    long base;
    static int MAX_SITES = 6; // override with a leading `max:N` arg
    static final int PRE_INSNS = 3;
    static final int POST_BYTES = 20;

    @Override
    public void run() throws Exception {
        base = currentProgram.getImageBase().getOffset();
        Listing listing = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        for (String arg : getScriptArgs()) {
            String[] kv = arg.split(":"); // '=' is an argument delimiter for analyzeHeadless.bat
            String name = kv[0];
            if (name.equals("max")) { MAX_SITES = Integer.parseInt(kv[1]); continue; }
            long rva = Long.parseLong(kv[1].replaceFirst("^0[xX]", ""), 16);
            Address target = currentProgram.getImageBase().add(rva);
            ReferenceIterator it = rm.getReferencesTo(target);
            Set<Long> seenFns = new HashSet<>();
            int emitted = 0, total = 0;
            while (it.hasNext()) {
                Reference r = it.next();
                total++;
                if (emitted >= MAX_SITES) continue;
                Address from = r.getFromAddress();
                Instruction ins = listing.getInstructionAt(from);
                if (ins == null) continue;
                Function f = fm.getFunctionContaining(from);
                long fkey = f == null ? -1 : f.getEntryPoint().getOffset() - base;
                if (!seenFns.add(fkey)) continue;
                String pat = buildPattern(listing, ins, target);
                if (pat == null) continue;
                println(String.format("%s old=0x%x site=0x%x fn=0x%x %s", name, rva, from.getOffset() - base, fkey, pat));
                emitted++;
            }
            println(String.format("%s old=0x%x refs=%d emitted=%d", name, rva, total, emitted));
        }
    }

    // Returns "k=<n> <pattern>" or null if the target disp could not be located.
    String buildPattern(Listing listing, Instruction site, Address target) throws Exception {
        List<Instruction> insns = new ArrayList<>();
        Instruction cur = site;
        for (int i = 0; i < PRE_INSNS; i++) {
            Instruction prev = listing.getInstructionBefore(cur.getAddress());
            if (prev == null || !prev.getMaxAddress().add(1).equals(cur.getAddress())) break;
            insns.add(0, prev);
            cur = prev;
        }
        insns.add(site);
        cur = site;
        int post = 0;
        while (post < POST_BYTES) {
            Instruction next = listing.getInstructionAfter(cur.getAddress());
            if (next == null || !cur.getMaxAddress().add(1).equals(next.getAddress())) break;
            insns.add(next);
            post += next.getLength();
            cur = next;
        }
        StringBuilder sb = new StringBuilder();
        int targetK = -1;
        for (Instruction ins : insns) {
            byte[] b = ins.getBytes();
            boolean[] wild = new boolean[b.length];
            int cursorAt = -1;
            long insEnd = ins.getAddress().getOffset() + b.length;
            for (Reference ref : ins.getReferencesFrom()) {
                Address to = ref.getToAddress();
                if (!to.isMemoryAddress()) continue;
                boolean found = false;
                for (int k : new int[] {0, 1, 4}) {
                    long disp = to.getOffset() - (insEnd - k);
                    if (disp > Integer.MAX_VALUE || disp < Integer.MIN_VALUE) continue;
                    int d = (int) disp;
                    for (int p = 0; p + 4 + k <= b.length && !found; p++) {
                        if ((b[p] & 0xff) == (d & 0xff) && (b[p + 1] & 0xff) == ((d >> 8) & 0xff)
                                && (b[p + 2] & 0xff) == ((d >> 16) & 0xff) && (b[p + 3] & 0xff) == ((d >>> 24) & 0xff)) {
                            for (int q = p; q < p + 4; q++) wild[q] = true;
                            if (to.equals(target) && ins == site) { cursorAt = p; targetK = k; }
                            found = true;
                        }
                    }
                    if (found) break;
                }
            }
            for (int i = 0; i < b.length; i++) {
                if (i == cursorAt) sb.append("' ");
                sb.append(wild[i] ? "? " : String.format("%02x ", b[i]));
            }
        }
        if (targetK < 0) return null;
        return "k=" + targetK + " " + sb.toString().trim();
    }
}
