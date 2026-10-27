// MOVX @Ri takes its page from the context register xpage (language default 0x50).  This script checks the default and a changed
// value: it disassembles MOVX @R0,A (F2) twice, once at an address with the default context and once where xpage was set to 0x51,
// and looks for the page constant (shifted left by 8) in the p-code.
// Script args: <outfile>
//@category Testing

import java.io.PrintStream;
import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class XpageCheck extends GhidraScript {

	// the page is the constant that is shifted left by 8 before it is added to the register
	private boolean hasPage(Address a, long page) {
		Instruction ins = getInstructionAt(a);
		for (PcodeOp op : ins.getPcode()) {
			if (op.getOpcode() == PcodeOp.INT_LEFT && op.getInput(0).isConstant() && op.getInput(0).getOffset() == page &&
				op.getInput(1).getOffset() == 8) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected void run() throws Exception {
		PrintStream out = new PrintStream(getScriptArgs()[0]);
		Register xpage = currentProgram.getRegister("xpage");
		Address def = toAddr(0x100), changed = toAddr(0x200);
		currentProgram.getProgramContext().setValue(xpage, changed, changed.add(0xff), BigInteger.valueOf(0x51));
		disassemble(def);
		disassemble(changed);
		int bad = 0;
		boolean a = hasPage(def, 0x50), b = hasPage(changed, 0x51);
		out.println("default context: page 0x50 " + (a ? "found" : "MISSING"));
		out.println("xpage=0x51:      page 0x51 " + (b ? "found" : "MISSING"));
		out.println("default value of xpage: " + currentProgram.getProgramContext().getDefaultValue(xpage, def));
		out.println(a && b ? "xpage check passed" : "xpage check FAILED");
		out.close();
	}
}
