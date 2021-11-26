package fr.inria.astor.core.faultlocalization.except;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import fr.inria.astor.core.entities.ProgramVariant;
import fr.inria.astor.core.faultlocalization.FaultLocalizationResult;
import fr.inria.astor.core.faultlocalization.FaultLocalizationStrategy;
import fr.inria.astor.core.faultlocalization.entity.SuspiciousCode;
import fr.inria.astor.core.faultlocalization.entity.SuspiciousCodeGuessedFault;
import fr.inria.astor.core.setup.ConfigurationProperties;
import fr.inria.astor.core.setup.FinderTestCases;
import fr.inria.astor.core.setup.ProjectRepairFacade;

public class exceptFaultLocalizationStrategy implements FaultLocalizationStrategy {
	public Logger log = Logger.getLogger(exceptFaultLocalizationStrategy.class.getName());

	public FaultLocalizationResult searchSuspicious(ProjectRepairFacade projectToRepair, List<String> testToRun)
			throws Exception {

		String programSourceCodePath = ConfigurationProperties.getProperty("location") + File.separator
				+ ConfigurationProperties.getProperty("srcjavafolder");
		String programClassesPath = projectToRepair.getOutDirWithPrefix(ProgramVariant.DEFAULT_ORIGINAL_VARIANT);
		String testClassesPath = ConfigurationProperties.getProperty("bintestfolder");
		// Aggiunto in AbstractMain, in parametri opzionali
		String classTestToExecute = ConfigurationProperties.getProperty("failingTestClass");
		// Aggiunto in AbstractMain, in parametri opzionali
		String failingTestName = ConfigurationProperties.getProperty("failingTestName");
		String dependencies = ConfigurationProperties.getProperty("dependencies");
		String sbflRankFile = ConfigurationProperties.getProperty("sbflRanking");

		return this.calculateFLResult(programSourceCodePath, programClassesPath, testClassesPath, classTestToExecute,
				failingTestName, dependencies, sbflRankFile);
	}

	public List<String> findTestCasesToExecute(ProjectRepairFacade projectFacade) {
		List<String> testCasesToRun = FinderTestCases.findJUnit4XTestCasesForRegression(projectFacade);
		return testCasesToRun;
	}

	/*
	 * @needed List<SuspiciousCode> candidates
	 * 
	 * @needed List<String> failingTestCases
	 * 
	 * Manipola dati di ConfigurationProperties Esecuzione Exception - like da riga
	 * 41 - 59
	 * 
	 * Tratto dati che andrebbero in output sul CSV per generare
	 * FaultLocalizationResult
	 * 
	 * In AbstractMain è possibile configuare nuove opzioni di input da riga di
	 * comando (addOption)
	 * 
	 * Estendere SuspiciousCode con parametro per GuessedFault, per righe senza
	 * campo, inserire banalmente null
	 */
	private FaultLocalizationResult calculateFLResult(String programSourceCodePath, String programClassesPath,
			String testClassesPath, String classTestToExecute, String failingTestName, String dependencies,
			String sbflRankFile) {
		// ConfigurationProperties per estrapolare informazioni riga di comando
		List<FailureInfo> failureInfoList = TestSuiteExecutor.getFailure(programClassesPath, testClassesPath,
				dependencies, classTestToExecute, failingTestName);

		Map<FailureInfo, List<RepairTarget>> repairTargetByFailureInfo = new HashMap<FailureInfo, List<RepairTarget>>();

		for (FailureInfo failureInfo : failureInfoList) {
			List<RepairTarget> repairTargetList = RepairTargetGenerator.generateRepairTarget(failureInfo,
					programSourceCodePath);

			System.out.println("Repair Target list: " + repairTargetList);

			repairTargetByFailureInfo.put(failureInfo, repairTargetList);
		}

		// Parte con GuessedFault
		List<RepairTarget> repairTargetList2 = repairTargetByFailureInfo.get(failureInfoList.get(0));

		List<RepairTarget> repairTargetList1 = SbflRankMergingUtil.mergeAstor(repairTargetList2, sbflRankFile);
		if (repairTargetList2 != null)
			repairTargetList2.addAll(repairTargetList1);
		else
			repairTargetList2 = repairTargetList1;

		List<SuspiciousCode> candidates = new ArrayList<SuspiciousCode>();
		List<String> failingTest = new ArrayList<String>();

		failingTest.add(failingTestName);

		for (RepairTarget repairTarget : repairTargetList2) {
			SuspiciousCode tmp = new SuspiciousCodeGuessedFault(repairTarget.getSuspiciousLocation().getClassName(),
					repairTarget.getSuspiciousLocation().getMethodName(),
					repairTarget.getSuspiciousLocation().getLineNumber(), repairTarget.getSuspiciousnessScore(), null,
					repairTarget.getGuessedFault());
			candidates.add(tmp);
		}

		FaultLocalizationResult r = new FaultLocalizationResult(candidates, failingTest);
		return r;

	}

}
