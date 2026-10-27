// Decode every slot of a raw image and record which SLEIGH constructors (by source line) appear in
// the decoded parse trees: the "every entry is reachable" check.
// Output, one line each: "S <file>:<line>" a constructor seen in a parse tree, "T <file>:<line>" every constructor of the
// compiled language (reach_check.py compares the two sets after merging the pieces of the corpus).
// Script args: <outfile> <slot-size>
//@category Testing

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.ProgramProcessorContext;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;

public class Reach extends GhidraScript {

	private final TreeSet<String> seen = new TreeSet<>();

	private void walk(ConstructState st) {
		if (st.getConstructor() != null) {
			seen.add(st.getConstructor().getSourceFile() + ":" + st.getConstructor().getLineno());
		}
		for (int i = 0; i < st.getNumSubStates(); i++) {
			ConstructState sub = st.getSubState(i);
			if (sub != null) {
				walk(sub);
			}
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int slot = Integer.parseInt(args[1]);
		MemoryBlock block = currentProgram.getMemory().getBlocks()[0];
		Address base = block.getStart();
		long n = block.getSize() / slot;
		Language lang = currentProgram.getLanguage();
		Field fld = lang.getClass().getDeclaredField("instructProtoMap");
		fld.setAccessible(true);
		Map<?, ?> protoCache = (Map<?, ?>) fld.get(lang);
		for (long i = 0; i < n; i++) {
			Address a = base.add(i * slot);
			try {
				ProcessorContext ctx = new ProgramProcessorContext(currentProgram.getProgramContext(), a);
				MemBuffer buf = new MemoryBufferImpl(currentProgram.getMemory(), a);
				InstructionPrototype p = lang.parse(buf, ctx, false);
				walk(((SleighInstructionPrototype) p).getRootState());
			}
			catch (Exception e) {
				// not an instruction
			}
			protoCache.clear();
		}
		PrintStream out = new PrintStream(args[0]);
		for (String l : seen) {
			out.println("S " + l);
		}
		Field sf = lang.getClass().getDeclaredField("symtab");
		sf.setAccessible(true);
		ghidra.app.plugin.processors.sleigh.symbol.SymbolTable tab =
			(ghidra.app.plugin.processors.sleigh.symbol.SymbolTable) sf.get(lang);
		for (ghidra.app.plugin.processors.sleigh.symbol.Symbol sym : tab.getSymbolList()) {
			if (sym instanceof ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol) {
				ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol st =
					(ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol) sym;
				for (int i = 0; i < st.getNumConstructors(); i++) {
					out.println("T " + st.getConstructor(i).getSourceFile() + ":" + st.getConstructor(i).getLineno() + " " +
						st.getName());
				}
			}
		}
		out.close();
	}
}
