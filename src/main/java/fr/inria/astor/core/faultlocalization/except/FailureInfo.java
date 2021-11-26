package fr.inria.astor.core.faultlocalization.except;


import java.util.ArrayList;
import java.util.List;

public class FailureInfo {

	private String exceptionType;
	private String exceptionMessage;
	private List<StackTracePOI> stackTracePOIList;

	public FailureInfo() {
		this.stackTracePOIList = new ArrayList<StackTracePOI>();
	}
	


	public FailureInfo(String exceptionType, String exceptionMessage, List<StackTracePOI> stackTracePOIList) {
		super();
		this.exceptionType = exceptionType;
		this.exceptionMessage = exceptionMessage;
		this.stackTracePOIList = stackTracePOIList;
	}



	public String getExceptionType() {
		return exceptionType;
	}

	public String getExceptionMessage() {
		return exceptionMessage;
	}

	public void setExceptionType(String exceptionType) {
		this.exceptionType = exceptionType;
	}

	public void setExceptionMessage(String exceptionMessage) {
		this.exceptionMessage = exceptionMessage;
	}

	public void addStackTracePOI(StackTracePOI stackTracePOI) {
		this.stackTracePOIList.add(stackTracePOI);
	}

	public void removeStackTracePOI(int position) {
		if (stackTracePOIList != null && position >= 0 && position < stackTracePOIList.size()) {
			stackTracePOIList.remove(position);
		}
	}

	public List<StackTracePOI> getStackTracePOIList() {
		return this.stackTracePOIList;
	}

	@Override
	public String toString() {
		return "FailureInfo [exceptionType=" + exceptionType + ", exceptionMessage=" + exceptionMessage
				+ ", stackTracePOIList=" + stackTracePOIList + "]";
	}

	public String toStringPOIList() {
		return "stackTracePOIList=" + stackTracePOIList;
	}
}
