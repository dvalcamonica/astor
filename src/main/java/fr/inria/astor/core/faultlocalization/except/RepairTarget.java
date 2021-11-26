package fr.inria.astor.core.faultlocalization.except;


public class RepairTarget {

	private SuspiciousLocation suspiciousLocation;
	private GuessedFault guessedFault;
	private double suspiciousnessScore;

	public RepairTarget(SuspiciousLocation suspiciousLocation, GuessedFault guessedFault, double suspiciousnessScore) {
		this.suspiciousLocation = suspiciousLocation;
		this.guessedFault = guessedFault;
		this.suspiciousnessScore = suspiciousnessScore;
	}

	public enum GuessedFault {
		ARRAY_VARIABLE_IS_WRONG, ARRAY_INDEX_IS_WRONG, ARRAY_INITIALIZATION_IS_WRONG,
		ARRAY_INDEX_INITIALIZATION_IS_WRONG, MISSING_CONDITION, STRING_VARIABLE_IS_WRONG,
		STRING_INITIALIZATION_IS_WRONG, VARIABLE_IS_WRONG, VARIABLE_INITIALIZATION_IS_WRONG,
		VARIABLE_ASSIGNMENT_IS_WRONG, PARAMETER_VALUE_IS_WRONG, STRING_INDEX_IS_WRONG, METHOD_PARAMETER_IS_WRONG,
		NOT_AVAILABLE;
	}

	public SuspiciousLocation getSuspiciousLocation() {
		return suspiciousLocation;
	}

	public void setSuspiciousLocation(SuspiciousLocation suspiciousLocation) {
		this.suspiciousLocation = suspiciousLocation;
	}

	public GuessedFault getGuessedFault() {
		return guessedFault;
	}

	public void setGuessedFault(GuessedFault guessedFault) {
		this.guessedFault = guessedFault;
	}

	public double getSuspiciousnessScore() {
		return suspiciousnessScore;
	}

	public void setSuspiciousnessScore(double suspiciousnessScore) {
		this.suspiciousnessScore = suspiciousnessScore;
	}

	public String toStringWithoutSuspiciousnessScore() {
		return "RepairTarget [suspiciousLocation=" + suspiciousLocation + ", guessedFault=" + guessedFault + "]";
	}

	@Override
	public String toString() {
		return "RepairTarget [suspiciousLocation=" + suspiciousLocation + ", guessedFault=" + guessedFault
				+ ", suspiciousnessScore=" + suspiciousnessScore + "]";
	}
}
