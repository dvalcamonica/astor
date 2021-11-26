package fr.inria.astor.core.faultlocalization.except;

import org.junit.runner.notification.Failure;

public final class FailureAnalyzer {

	private static final String JDK_CLASS_PREFIX = "jdk.";
	private static final String JAVA_CLASS_PREFIX = "java.";
	private static final String JUNIT_CLASS_PREFIX = "org.junit.";
	private static final String JUNIT_FRAMEWORK_PREFIX = "junit.framework.";
	private static final String EXCEPT = "qrs2021";
	private static final String ASTOR = "fr.inria.";

	private FailureAnalyzer() {
	}

	public static FailureInfo analyzeFailure(Failure failure, String classTestToExecute) {

		if (failure == null) {
			return null;
		}

		// System.out.println(failure.getTrace());

		FailureInfo failureInfo = new FailureInfo();
		failureInfo.setExceptionType(failure.getException().getClass().getCanonicalName());
		failureInfo.setExceptionMessage(failure.getMessage());

		StackTraceElement[] stackTraceElements = failure.getException().getStackTrace();

		for (int i = 0; i < stackTraceElements.length; i++) {

			/*
			 * To be excluded: jdk.internal.reflect.NativeMethodAccessorImpl To be excluded:
			 * java.lang.reflect.Method To be excluded: org.junit To be excluded:
			 * junit.framework To be excluded: qrs2021 To be excluded: test case class
			 */
			String className = stackTraceElements[i].getClassName();

			if (!className.startsWith(JDK_CLASS_PREFIX) && !className.startsWith(JAVA_CLASS_PREFIX)
					&& !className.startsWith(JUNIT_CLASS_PREFIX) && !className.startsWith(JUNIT_FRAMEWORK_PREFIX)
					&& !className.startsWith(EXCEPT) && !className.startsWith(classTestToExecute)
					&& !className.startsWith(ASTOR)) {
				failureInfo.addStackTracePOI(
						new StackTracePOI(stackTraceElements[i].getClassName(), stackTraceElements[i].getMethodName(),
								stackTraceElements[i].getFileName(), stackTraceElements[i].getLineNumber()));
			}
		}

		failureInfo.removeStackTracePOI(failureInfo.getStackTracePOIList().size());

		return failureInfo;
	}
}
