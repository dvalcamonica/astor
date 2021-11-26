package fr.inria.astor.core.faultlocalization.except;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import fr.inria.astor.core.faultlocalization.except.RepairTarget.GuessedFault;
import fr.inria.astor.core.faultlocalization.except.SuspiciousLocation.LocationType;

public class RepairTargetGenerator {

	private static double maxSusp = 2.00;
	private static double decreasingFactor = 0.05;

	private static final String ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION = "java.lang.ArrayIndexOutOfBoundsException";
	private static final String STRING_INDEX_OUT_OF_BOUNDS_EXCEPTION = "java.lang.StringIndexOutOfBoundsException";
	private static final String NULL_POINTER_EXCEPTION = "java.lang.NullPointerException";
	private static final String ILLEGAL_ARGUMENT_EXCEPTION = "java.lang.IllegalArgumentException";

	public static List<RepairTarget> generateRepairTarget(FailureInfo failureInfo, String programSourceCodePath) {

		FailureDrivenLocalizer failureDrivenLocalizer = null;
		List<SuspiciousLocation> suspiciousLocationList = null;
		List<RepairTarget> repairTargetList = null;

		if (failureInfo.getExceptionType().equals(ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION)) {
			failureDrivenLocalizer = new ArrayIndexOutOfBoundsExceptionFailureDrivenLocalizer(programSourceCodePath);
			suspiciousLocationList = failureDrivenLocalizer.getSuspiciousLocations(failureInfo);
		} else if (failureInfo.getExceptionType().equals(STRING_INDEX_OUT_OF_BOUNDS_EXCEPTION)) {
			failureDrivenLocalizer = new StringIndexOutOfBoundsExceptionFailureDrivenLocalizer(programSourceCodePath);
			suspiciousLocationList = failureDrivenLocalizer.getSuspiciousLocations(failureInfo);
		} else if (failureInfo.getExceptionType().equals(NULL_POINTER_EXCEPTION)) {
			failureDrivenLocalizer = new NullPointerExceptionFailureDrivenLocalizer(programSourceCodePath);
			suspiciousLocationList = failureDrivenLocalizer.getSuspiciousLocations(failureInfo);
		} else if (failureInfo.getExceptionType().equals(ILLEGAL_ARGUMENT_EXCEPTION)) {
			failureDrivenLocalizer = new IllegalArgumentExceptionFailureDrivenLocalizer(programSourceCodePath);
			suspiciousLocationList = failureDrivenLocalizer.getSuspiciousLocations(failureInfo);
		} else {
			return null;
		}

		if (suspiciousLocationList != null) {
			repairTargetList = new ArrayList<RepairTarget>();

			for (SuspiciousLocation suspiciousLocation : suspiciousLocationList) {
				repairTargetList.add(new RepairTarget(suspiciousLocation,
						formulateHypothesis(suspiciousLocation.getLocationType()), 0));
			}
		}

		Map<Integer, Double> suspMapping = new HashMap<Integer, Double>();

		if (repairTargetList == null) {
			return null;
		}

		repairTargetList.forEach((e) -> {
			if (!suspMapping.containsKey(e.getSuspiciousLocation().getLineNumber())) {
				suspMapping.put(e.getSuspiciousLocation().getLineNumber(), maxSusp);
				maxSusp = maxSusp - decreasingFactor;
				maxSusp = Math.floor(maxSusp * 100) / 100;
			}
		});

		for (int i = 0; i < repairTargetList.size(); i++) {
			repairTargetList.get(i).setSuspiciousnessScore(
					suspMapping.get(repairTargetList.get(i).getSuspiciousLocation().getLineNumber()));
		}

		return repairTargetList;
	}

	private static GuessedFault formulateHypothesis(LocationType locationType) {

		switch (locationType) {
		case ARRAY_VARIABLE:
			return GuessedFault.ARRAY_VARIABLE_IS_WRONG;
		case ARRAY_INDEX:
			return GuessedFault.ARRAY_INDEX_IS_WRONG;
		case INDEX_USED_FOR_ARRAY_INITIALIZATION:
			return GuessedFault.ARRAY_INDEX_IS_WRONG;
		case ARRAY_INDEX_VARIABLE_ASSIGNMENT:
			return GuessedFault.ARRAY_INDEX_INITIALIZATION_IS_WRONG;
		case ARRAY_INITIALIZATION:
			return GuessedFault.ARRAY_INITIALIZATION_IS_WRONG;
		case ARRAY_INITIALIZATION_ASSIGNMENT:
			return GuessedFault.ARRAY_INITIALIZATION_IS_WRONG;
		case BEFORE_ARRAY_ACCESS:
			return GuessedFault.MISSING_CONDITION;
		case VARIABLE_ACCESS:
			return GuessedFault.VARIABLE_IS_WRONG;
		case BEFORE_VARIABLE_ACCESS:
			return GuessedFault.MISSING_CONDITION;
		case VARIABLE_DECLARATION:
			return GuessedFault.VARIABLE_INITIALIZATION_IS_WRONG;
		case VARIABLE_ASSIGNMENT:
			return GuessedFault.VARIABLE_ASSIGNMENT_IS_WRONG;
		case METHOD_INVOCATION:
			return GuessedFault.PARAMETER_VALUE_IS_WRONG;
		case INDEX_USED_FOR_VARIABLE_ACCESS:
			return GuessedFault.STRING_INDEX_IS_WRONG;
		case METHOD_PARAMETER:
			return GuessedFault.METHOD_PARAMETER_IS_WRONG;
		}

		return null;
	}
}
