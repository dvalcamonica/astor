package fr.inria.astor.core.faultlocalization.except;

import java.util.List;


import spoon.Launcher;

public abstract class FailureDrivenLocalizer {
	
	protected Launcher launcher;
	
	public FailureDrivenLocalizer(String programSourceCodePath) {
		launcher = new Launcher();
		launcher.addInputResource(programSourceCodePath);
		launcher.getEnvironment().setCommentEnabled(false);
		launcher.buildModel();
	}
	
	public abstract List<SuspiciousLocation> getSuspiciousLocations(FailureInfo failureInfo);
}
