// Exports a binary's facts to JSON for Thanos (RF-13).
// Usage (analyzeHeadless post-script): -postScript ExportFacts.java <output.json>
// Keys = those of the P1 bundle summary + COMPLETE lists of function and
// export names (P1 only listed part of them).
//@category Thanos
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ExportFacts extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: ExportFacts.java <output.json>");
            return;
        }

        List<String> functions = new ArrayList<>();
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext() && !monitor.isCancelled()) {
            functions.add(fit.next().getName());
        }

        SymbolTable st = currentProgram.getSymbolTable();
        List<String> exports = new ArrayList<>();
        AddressIterator eps = st.getExternalEntryPointIterator();
        while (eps.hasNext()) {
            Address addr = eps.next();
            Symbol sym = st.getPrimarySymbol(addr);
            if (sym != null) {
                exports.add(sym.getName());
            }
        }

        ExternalManager em = currentProgram.getExternalManager();
        int libraries = em.getExternalLibraryNames().length;
        int imports = 0;
        SymbolIterator ext = st.getExternalSymbols();
        while (ext.hasNext()) {
            ext.next();
            imports++;
        }

        int strings = 0;
        DataIterator dit = currentProgram.getListing().getDefinedData(true);
        while (dit.hasNext() && !monitor.isCancelled()) {
            Data d = dit.next();
            if (d.hasStringValue()) {
                strings++;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"library_count\": ").append(libraries).append(",\n");
        sb.append("  \"total_imports\": ").append(imports).append(",\n");
        sb.append("  \"export_count\": ").append(exports.size()).append(",\n");
        sb.append("  \"function_count\": ").append(functions.size()).append(",\n");
        sb.append("  \"string_count\": ").append(strings).append(",\n");
        sb.append("  \"functions\": ").append(toJson(functions)).append(",\n");
        sb.append("  \"exports\": ").append(toJson(exports)).append(",\n");
        sb.append("  \"image_base\": \"").append(currentProgram.getImageBase()).append("\",\n");
        sb.append("  \"language\": \"").append(escape(currentProgram.getLanguageID().toString())).append("\"\n");
        sb.append("}\n");

        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            w.write(sb.toString());
        }
        println("ExportFacts: " + functions.size() + " functions, " + exports.size() + " exports -> " + args[0]);
    }

    private static String toJson(List<String> values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append('"').append(escape(values.get(i))).append('"');
        }
        return sb.append(']').toString();
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
