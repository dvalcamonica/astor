package fr.inria.astor.core.faultlocalization.except;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.opencsv.CSVParser;
import com.opencsv.CSVParserBuilder;
import com.opencsv.CSVReader;
import com.opencsv.CSVReaderBuilder;
import com.opencsv.CSVWriter;
import com.opencsv.exceptions.CsvException;

import fr.inria.astor.core.faultlocalization.except.RepairTarget.GuessedFault;
import fr.inria.astor.core.faultlocalization.except.SuspiciousLocation.LocationType;
import spoon.reflect.declaration.CtElement;

public final class SbflRankMergingUtil {

	private static final String OUTPUT_FILENAME = "except_ranking.csv";

	public SbflRankMergingUtil() {
	}

	public static void merge(List<RepairTarget> repairTargetList, String sbflRankFile, String output) {

		CSVParser csvParser = new CSVParserBuilder().withSeparator(';').build(); // custom separator

		CSVReader reader;

		try {
			reader = new CSVReaderBuilder(new FileReader(sbflRankFile)).withCSVParser(csvParser) // custom CSV parser
					.withSkipLines(1) // skip the first line, header info
					.build();

			List<String[]> content = reader.readAll();

			List<String[]> filteredContent = new ArrayList<String[]>();

			for (int i = 0; i < content.size(); i++) {
				if (content.get(i) != null) {
					if (Double.valueOf(content.get(i)[1]) > 0) {
						filteredContent.add(new String[] { content.get(i)[0], content.get(i)[1] });
					} else {
						break;
					}
				}
			}

			if (repairTargetList != null) {
				for (int i = 0; i < repairTargetList.size(); i++) {
					for (int j = 0; j < filteredContent.size(); j++) {
						if (filteredContent.get(j) != null) {
							String sbflClassName = StringUtils.substringBefore(filteredContent.get(j)[0], "#")
									.replace("$", ".");
							if (repairTargetList.get(i).getSuspiciousLocation().getClassName().equals(sbflClassName)) {
								String sbflLine = StringUtils.substringAfter(filteredContent.get(j)[0], ":");

								if (repairTargetList.get(i).getSuspiciousLocation().getLineNumber() == Integer
										.valueOf(sbflLine)) {
									filteredContent.set(j, null);
									break;
								}
							}
						}
					}
				}

				File directory = new File(output);
				if (!directory.exists()) {
					directory.mkdirs();
				}

				CSVWriter writer = new CSVWriter(new FileWriter(output + File.separator + OUTPUT_FILENAME, false), ';',
						CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.DEFAULT_ESCAPE_CHARACTER, CSVWriter.RFC4180_LINE_END);

				List<String[]> finalOutput = new ArrayList<String[]>();
				finalOutput.add(new String[] { "name", "suspiciousness_value" });

				for (int i = 0; i < repairTargetList.size(); i++) {
					finalOutput.add(new String[] { repairTargetList.get(i).toStringWithoutSuspiciousnessScore(),
							String.valueOf(repairTargetList.get(i).getSuspiciousnessScore()) });
				}

				finalOutput.addAll(filteredContent);

				writer.writeAll(finalOutput);
				writer.close();
			} else {
				File directory = new File(output);
				if (!directory.exists()) {
					directory.mkdirs();
				}

				CSVWriter writer = new CSVWriter(new FileWriter(output + File.separator + OUTPUT_FILENAME, false), ';',
						CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.DEFAULT_ESCAPE_CHARACTER, CSVWriter.RFC4180_LINE_END);

				List<String[]> finalOutput = new ArrayList<String[]>();
				finalOutput.add(new String[] { "name", "suspiciousness_value" });
				finalOutput.addAll(filteredContent);

				writer.writeAll(finalOutput);
				writer.close();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CsvException e) {
			e.printStackTrace();
		}
	}

	public static List<RepairTarget> mergeAstor(List<RepairTarget> repairTargetList, String sbflRankFile) {

		CSVParser csvParser = new CSVParserBuilder().withSeparator(';').build(); // custom separator

		CSVReader reader;

		List<RepairTarget> sbflTarget = new ArrayList<RepairTarget>();

		try {
			reader = new CSVReaderBuilder(new FileReader(sbflRankFile)).withCSVParser(csvParser) // custom CSV parser
					.withSkipLines(1) // skip the first line, header info
					.build();

			List<String[]> content = reader.readAll();

			List<String[]> filteredContent = new ArrayList<String[]>();

			for (int i = 0; i < content.size(); i++) {
				if (content.get(i) != null) {
					if (Double.valueOf(content.get(i)[1]) > 0) {
						filteredContent.add(new String[] { content.get(i)[0], content.get(i)[1] });
					} else {
						break;
					}
				}
			}

			if (repairTargetList != null) {
				for (int i = 0; i < repairTargetList.size(); i++) {
					for (int j = 0; j < filteredContent.size(); j++) {
						if (filteredContent.get(j) != null) {
							String sbflClassName = StringUtils.substringBefore(filteredContent.get(j)[0], "#")
									.replace("$", ".");
							if (repairTargetList.get(i).getSuspiciousLocation().getClassName().equals(sbflClassName)) {
								String sbflLine = StringUtils.substringAfter(filteredContent.get(j)[0], ":");

								if (repairTargetList.get(i).getSuspiciousLocation().getLineNumber() == Integer
										.valueOf(sbflLine)) {
									filteredContent.set(j, null);
									break;
								}
							}
						}
					}
				}
			}

			/**
			 * REPAIR TARGET private String className; private String methodName; private
			 * String fileName; private int lineNumber; private CtElement
			 * suspiciousExpression; private LocationType locationType;
			 */

			/**
			 * STACKTRACEPOI private String className; private String methodName; private
			 * String fileName; private int lineNumber;
			 * 
			 */

			for (int i = 0; i < filteredContent.size(); ++i) {
				if (filteredContent.get(i) != null)
					for (int j = 0; j < filteredContent.get(i).length; ++j) {
						if (filteredContent.get(i)[j] != null) {
							String sbflClassName = StringUtils.substringBefore(filteredContent.get(i)[0], "#")
									.replace("$", ".");

							String methodName = StringUtils.substringAfter(filteredContent.get(i)[0], "#");
							methodName = StringUtils.substringBefore(methodName, "(");

							String fileName = StringUtils.substringAfter(filteredContent.get(i)[0], "$");
							fileName = StringUtils.substringBefore(filteredContent.get(i)[0], "#") + ".java";

							int lineNumber = Integer
									.parseInt(StringUtils.substringAfter(filteredContent.get(i)[0], ":"));

							double score = Double.parseDouble(filteredContent.get(i)[1]);

							CtElement suspiciousExpression = null;

							LocationType locationType = LocationType.NOT_AVAILABLE;

							SuspiciousLocation s = new SuspiciousLocation(sbflClassName, fileName, methodName,
									lineNumber, suspiciousExpression, locationType);

							RepairTarget t = new RepairTarget(s, GuessedFault.NOT_AVAILABLE, score);

							sbflTarget.add(t);
						}
					}
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CsvException e) {
			e.printStackTrace();
		}
		return sbflTarget;
	}
}