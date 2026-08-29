import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.PrintWriter;

public class DecompileDump extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/decompiled.txt";

        Address entry = currentProgram.getMinAddress();
        Function func = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (func == null) {
            func = createFunction(entry, "FUN_" + entry);
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        PrintWriter pw = new PrintWriter(outPath);
        pw.println("// ==== " + func.getName() + " @ " + func.getEntryPoint() + " ====");
        DecompileResults res = ifc.decompileFunction(func, 60, new ConsoleTaskMonitor());
        if (res.decompileCompleted()) {
            pw.println(res.getDecompiledFunction().getC());
        } else {
            pw.println("// decompile failed: " + res.getErrorMessage());
        }
        pw.close();
        println("WROTE: " + outPath);
    }
}
