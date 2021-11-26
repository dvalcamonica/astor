package fr.inria.astor.core.faultlocalization.except;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.junit.runner.JUnitCore;
import org.junit.runner.Request;
import org.junit.runner.Result;

public final class TestSuiteExecutor {

	private TestSuiteExecutor() {
	}

	public static List<FailureInfo> getFailure(String programClassesPath, String testClassesPath, String dependencies,
			String classTestToExecute, String failingTestCase) {

		ClassLoader currentClassLoader = Thread.currentThread().getContextClassLoader();
		ClassLoader newClassLoader = null;
		List<FailureInfo> failureInfoList = new ArrayList<FailureInfo>();

		URL[] faultyProgramClassPath = null;

		if (dependencies != null) {

			if (dependencies.substring(dependencies.length() - 1).equals("/")) {
				dependencies = dependencies.substring(0, dependencies.length() - 1);
			}

			File f = new File(dependencies);
			String[] pathnames = f.list();

			try {
				faultyProgramClassPath = new URL[2 + pathnames.length];
				faultyProgramClassPath[0] = Paths.get(programClassesPath).toUri().toURL();
				faultyProgramClassPath[1] = Paths.get(testClassesPath).toUri().toURL();

				for (int i = 0; i < pathnames.length; i++) {
					faultyProgramClassPath[2 + i] = Paths.get(dependencies + File.separator + pathnames[i]).toUri()
							.toURL();
				}
			} catch (MalformedURLException e) {
				e.printStackTrace();
			}
		} else {
			faultyProgramClassPath = new URL[2];
			try {
				faultyProgramClassPath[0] = Paths.get(programClassesPath).toUri().toURL();
				faultyProgramClassPath[1] = Paths.get(testClassesPath).toUri().toURL();
			} catch (MalformedURLException e) {
				e.printStackTrace();
			}

		}

		// Create class loader using given codebase
		// Use currentClassLoader as parent to maintain current visibility
		newClassLoader = URLClassLoader.newInstance(faultyProgramClassPath, currentClassLoader);

		try {
			// Save class loader so that we can restore later
			Thread.currentThread().setContextClassLoader(newClassLoader);
			Request request = Request.method(newClassLoader.loadClass(classTestToExecute), failingTestCase);
			Result testExecutionResult = new JUnitCore().run(request);

			testExecutionResult.getFailures().forEach((e) -> {
				failureInfoList.add(FailureAnalyzer.analyzeFailure(e, classTestToExecute));
			});

			/*
			 * failureInfoList.forEach((e) -> { System.out.println("Stack trace line: " +
			 * e); });
			 */
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} finally {
			// Restore
			Thread.currentThread().setContextClassLoader(currentClassLoader);
		}

		if (failureInfoList.isEmpty()) {
			return null;
		} else {
			return failureInfoList;
		}
	}
}
