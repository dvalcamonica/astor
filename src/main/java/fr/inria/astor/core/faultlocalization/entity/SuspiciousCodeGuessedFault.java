package fr.inria.astor.core.faultlocalization.entity;

import java.util.Map;

import fr.inria.astor.core.faultlocalization.except.RepairTarget.GuessedFault;

public class SuspiciousCodeGuessedFault extends SuspiciousCode {

	GuessedFault guessedFault;

	public SuspiciousCodeGuessedFault() {
		super();
		// TODO Auto-generated constructor stub
	}

	public SuspiciousCodeGuessedFault(String className, String methodName, double susp, GuessedFault guessedFault) {
		super(className, methodName, susp);
		if (guessedFault != null)
			this.guessedFault = guessedFault;
		else
			this.guessedFault = GuessedFault.NOT_AVAILABLE;
		// TODO Auto-generated constructor stub
	}

	public SuspiciousCodeGuessedFault(String className, String methodName, int lineNumber, double susp,
			Map<Integer, Integer> frequency, GuessedFault guessedFault) {
		super(className, methodName, lineNumber, susp, frequency);
		if (guessedFault != null)
			this.guessedFault = guessedFault;
		else
			this.guessedFault = GuessedFault.NOT_AVAILABLE;
		// TODO Auto-generated constructor stub
	}

	public GuessedFault getGuessedFault() {
		if (guessedFault != null)
			return guessedFault;
		else
			return GuessedFault.NOT_AVAILABLE;
	}

	public void setGuessedFault(GuessedFault guessedFault) {
		this.guessedFault = guessedFault;
	}

}
