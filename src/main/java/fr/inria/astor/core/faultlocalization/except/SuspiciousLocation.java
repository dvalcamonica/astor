package fr.inria.astor.core.faultlocalization.except;


import spoon.reflect.declaration.CtElement;

//meglio come terzo param

public class SuspiciousLocation {

	private String className;
	private String methodName;
	private String fileName;
	private int lineNumber;
	private CtElement suspiciousExpression;
	private LocationType locationType;

	public enum LocationType {
		ARRAY_VARIABLE, ARRAY_INDEX, INDEX_USED_FOR_ARRAY_INITIALIZATION, ARRAY_INDEX_VARIABLE_ASSIGNMENT,
		ARRAY_INITIALIZATION, ARRAY_INITIALIZATION_ASSIGNMENT, BEFORE_ARRAY_ACCESS, BEFORE_VARIABLE_ACCESS,
		VARIABLE_DECLARATION, VARIABLE_ASSIGNMENT, VARIABLE_ACCESS, INDEX_USED_FOR_VARIABLE_ACCESS, METHOD_PARAMETER,
		METHOD_INVOCATION, NOT_AVAILABLE;
	}

	public SuspiciousLocation(String className, String fileName, String methodName, int lineNumber,
			CtElement suspiciousExpression, LocationType locationType) {
		this.className = className;
		this.fileName = fileName;
		this.lineNumber = lineNumber;
		this.suspiciousExpression = suspiciousExpression;
		this.locationType = locationType;
		this.methodName = methodName;
	}

	// da commentare
	/**
	 * public SuspiciousLocation(String className, String fileName, int lineNumber,
	 * CtElement suspiciousExpression, LocationType locationType) { this.className =
	 * className; this.fileName = fileName; this.lineNumber = lineNumber;
	 * this.suspiciousExpression = suspiciousExpression; this.locationType =
	 * locationType; }
	 */

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public void setLineNumber(int lineNumber) {
		this.lineNumber = lineNumber;
	}

	public CtElement getSuspiciousExpression() {
		return suspiciousExpression;
	}

	public void setSuspiciousExpression(CtElement suspiciousExpression) {
		this.suspiciousExpression = suspiciousExpression;
	}

	public LocationType getLocationType() {
		return locationType;
	}

	public void setLocationType(LocationType locationType) {
		this.locationType = locationType;
	}

	public String getMethodName() {
		return methodName;
	}

	public void setMethodName(String methodName) {
		this.methodName = methodName;
	}

	@Override
	public String toString() {
		return "SuspiciousLocation [className=" + className + ", methodName=" + methodName + ", fileName=" + fileName
				+ ", lineNumber=" + lineNumber + ", suspiciousExpression=" + suspiciousExpression + ", locationType="
				+ locationType + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((className == null) ? 0 : className.hashCode());
		result = prime * result + ((fileName == null) ? 0 : fileName.hashCode());
		result = prime * result + lineNumber;
		result = prime * result + ((locationType == null) ? 0 : locationType.hashCode());
		result = prime * result + ((suspiciousExpression == null) ? 0 : suspiciousExpression.toString().hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SuspiciousLocation other = (SuspiciousLocation) obj;
		if (className == null) {
			if (other.className != null)
				return false;
		} else if (!className.equals(other.className))
			return false;
		if (fileName == null) {
			if (other.fileName != null)
				return false;
		} else if (!fileName.equals(other.fileName))
			return false;
		if (lineNumber != other.lineNumber)
			return false;
		if (locationType != other.locationType)
			return false;
		if (suspiciousExpression == null) {
			if (other.suspiciousExpression != null)
				return false;
		} else if (!suspiciousExpression.toString().equals(other.suspiciousExpression.toString()))
			return false;
		return true;
	}
}
