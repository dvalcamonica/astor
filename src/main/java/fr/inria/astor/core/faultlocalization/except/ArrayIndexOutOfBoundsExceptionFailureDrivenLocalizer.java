package fr.inria.astor.core.faultlocalization.except;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import fr.inria.astor.core.faultlocalization.except.SuspiciousLocation.LocationType;
import spoon.reflect.code.CtAssignment;
import spoon.reflect.code.CtExpression;
import spoon.reflect.code.CtLocalVariable;
import spoon.reflect.code.CtStatement;
import spoon.reflect.declaration.CtClass;
import spoon.reflect.declaration.CtElement;
import spoon.reflect.declaration.CtExecutable;
import spoon.reflect.declaration.CtField;
import spoon.reflect.declaration.CtMethod;
import spoon.reflect.visitor.filter.TypeFilter;
import spoon.support.reflect.code.CtArrayReadImpl;
import spoon.support.reflect.code.CtArrayWriteImpl;
import spoon.support.reflect.code.CtBinaryOperatorImpl;
import spoon.support.reflect.code.CtFieldReadImpl;
import spoon.support.reflect.code.CtFieldWriteImpl;
import spoon.support.reflect.code.CtLiteralImpl;
import spoon.support.reflect.code.CtNewArrayImpl;
import spoon.support.reflect.code.CtVariableReadImpl;

public final class ArrayIndexOutOfBoundsExceptionFailureDrivenLocalizer extends FailureDrivenLocalizer {

	private static final String THIS_KEYWORD = "this.";

	public ArrayIndexOutOfBoundsExceptionFailureDrivenLocalizer(String programSourceCodePath) {
		super(programSourceCodePath);
	}

	@Override
	public List<SuspiciousLocation> getSuspiciousLocations(FailureInfo failureInfo) {

		List<SuspiciousLocation> suspiciousLocationList = new ArrayList<SuspiciousLocation>();

		StackTracePOI stackTracePOI = failureInfo.getStackTracePOIList().get(0);

		List<CtStatement> suspiciousStatementList = getSuspiciousStatementList(stackTracePOI);

		List<CtArrayReadImpl<?>> suspiciousArrayReadImplList = getSuspiciousArrayReadImpl(
				suspiciousStatementList.get(0));
		List<CtArrayWriteImpl<?>> suspiciousArrayWriteImplList = getSuspiciousArrayWriteImpl(
				suspiciousStatementList.get(0));
		List<CtFieldReadImpl<?>> suspiciousArrayCtFieldReadImplList = getSuspiciousArrayCtFieldReadImpl(
				suspiciousStatementList.get(0));

		CtStatement suspiciousStatement = suspiciousStatementList.get(0);

		suspiciousArrayReadImplList.forEach((e) -> {
			suspiciousLocationList.add(new SuspiciousLocation(stackTracePOI.getClassName(), stackTracePOI.getFileName(),
					stackTracePOI.getMethodName(), stackTracePOI.getLineNumber(), e.getTarget(),
					LocationType.ARRAY_VARIABLE));

			suspiciousLocationList.add(new SuspiciousLocation(stackTracePOI.getClassName(), stackTracePOI.getFileName(),
					stackTracePOI.getMethodName(), stackTracePOI.getLineNumber(), e.getIndexExpression(),
					LocationType.ARRAY_INDEX));

			suspiciousLocationList.addAll(getSuspicousArrayInitialization(e.getTarget(), failureInfo, null));
			suspiciousLocationList.addAll(getSuspicousArrayInitialization(e.getIndexExpression(), failureInfo, null));

			suspiciousLocationList
					.add(new SuspiciousLocation(suspiciousStatement.getParent(CtClass.class).getQualifiedName(),
							suspiciousStatement.getPosition().getFile().getName(), stackTracePOI.getMethodName(),
							suspiciousStatement.getPosition().getLine(), suspiciousStatement,
							LocationType.BEFORE_ARRAY_ACCESS));
		});

		suspiciousArrayWriteImplList.forEach((e) -> {
			suspiciousLocationList.add(new SuspiciousLocation(stackTracePOI.getClassName(), stackTracePOI.getFileName(),
					stackTracePOI.getMethodName(), stackTracePOI.getLineNumber(), e.getTarget(),
					LocationType.ARRAY_VARIABLE));

			suspiciousLocationList.add(new SuspiciousLocation(stackTracePOI.getClassName(), stackTracePOI.getFileName(),
					stackTracePOI.getMethodName(), stackTracePOI.getLineNumber(), e.getIndexExpression(),
					LocationType.ARRAY_INDEX));

			suspiciousLocationList.addAll(getSuspicousArrayInitialization(e.getTarget(), failureInfo, null));
			suspiciousLocationList.addAll(getSuspicousArrayInitialization(e.getIndexExpression(), failureInfo, null));

			suspiciousLocationList
					.add(new SuspiciousLocation(suspiciousStatement.getParent(CtClass.class).getQualifiedName(),
							suspiciousStatement.getPosition().getFile().getName(), stackTracePOI.getMethodName(),
							suspiciousStatement.getPosition().getLine(), suspiciousStatement,
							LocationType.BEFORE_ARRAY_ACCESS));
		});

		suspiciousArrayCtFieldReadImplList.forEach((e) -> {
			suspiciousLocationList.add(new SuspiciousLocation(stackTracePOI.getClassName(), stackTracePOI.getFileName(),
					stackTracePOI.getMethodName(), stackTracePOI.getLineNumber(), e, LocationType.ARRAY_VARIABLE));

			suspiciousLocationList.addAll(getSuspicousArrayInitialization(e.getTarget(), failureInfo, null));

			suspiciousLocationList
					.add(new SuspiciousLocation(suspiciousStatement.getParent(CtClass.class).getQualifiedName(),
							suspiciousStatement.getPosition().getFile().getName(), stackTracePOI.getMethodName(),
							suspiciousStatement.getPosition().getLine(), suspiciousStatement,
							LocationType.BEFORE_ARRAY_ACCESS));
		});

		if (suspiciousLocationList.isEmpty()) {
			return null;
		} else {
			return suspiciousLocationList.stream().distinct().collect(Collectors.toList());
		}
	}

	private List<SuspiciousLocation> getSuspicousArrayInitialization(CtExpression<?> ctArrayReadImpl,
			FailureInfo failureInfo, List<SuspiciousLocation> suspiciousLocationList) {

		if (suspiciousLocationList == null) {
			suspiciousLocationList = new ArrayList<SuspiciousLocation>();
		}

		boolean isClassFieldVariable = false;

		if (ctArrayReadImpl instanceof CtFieldReadImpl<?>) {
			isClassFieldVariable = true;
		}

		CtElement ctMethod = ctArrayReadImpl.getParent(CtMethod.class);

		// It means that the found variable is an instance variable and thus it is not
		// defined in a method
		if (ctMethod == null) {

			ctMethod = ctArrayReadImpl.getParent(CtClass.class);
			assert (((CtMethod<?>) ctMethod).getSignature() != null);
			// 1) CtField

			CtClass<?> ctClass = ctArrayReadImpl.getParent(CtClass.class);
			List<CtField<?>> ctFieldList = ctClass.getElements(new TypeFilter<CtField<?>>(CtField.class));

			for (CtField<?> ctField : ctFieldList) {
				if (ctField.getAssignment() != null) {
					if (ctField.getReference().toString().replace(THIS_KEYWORD, "")
							.equals(ctArrayReadImpl.toString().replace(THIS_KEYWORD, ""))
							&& ctField.getType().equals(ctArrayReadImpl.getType())) {

						// Array initialization found -> Check the expression used to define the size

						/*
						 * 1.1 - CtNewArrayImpl: int[] array = new int[1]; 1.2 - CtNewArrayImpl: int[]
						 * array = new int[i]; 1.3 - CtNewArrayImpl: int[] array = new int[i+1];
						 */
						if (ctField.getAssignment() instanceof CtNewArrayImpl) {

							CtNewArrayImpl<?> arrayInitialization = (CtNewArrayImpl<?>) ctField.getAssignment();

							List<CtExpression<Integer>> arrayInitializationExpressionList = arrayInitialization
									.getDimensionExpressions();

							if (arrayInitializationExpressionList.size() == 1) {

								CtExpression<Integer> arrayInitializationExpression = arrayInitializationExpressionList
										.get(0);

								// Integer constant expression (CtLiteralImpl) or complex expression
								// (CtBinaryOperatorImpl)
								if (arrayInitializationExpression instanceof CtLiteralImpl
										|| arrayInitializationExpression instanceof CtBinaryOperatorImpl) {

									suspiciousLocationList.add(new SuspiciousLocation(
											arrayInitialization.getParent(CtClass.class).getQualifiedName(),
											arrayInitialization.getPosition().getFile().getName(),
											((CtMethod<?>) ctMethod).getSignature(),
											arrayInitialization.getPosition().getLine(), arrayInitialization,
											LocationType.ARRAY_INITIALIZATION));

									suspiciousLocationList.add(new SuspiciousLocation(
											arrayInitializationExpression.getParent(CtClass.class).getQualifiedName(),
											arrayInitializationExpression.getPosition().getFile().getName(),
											((CtMethod<?>) ctMethod).getSignature(),
											arrayInitializationExpression.getPosition().getLine(),
											arrayInitializationExpression,
											LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

								} else if (arrayInitializationExpression instanceof CtFieldReadImpl) { // Expression
																										// with single
																										// variable:
																										// CtFieldReadImp

									// Find the variable
									suspiciousLocationList.add(new SuspiciousLocation(
											arrayInitialization.getParent(CtClass.class).getQualifiedName(),
											arrayInitialization.getPosition().getFile().getName(),
											((CtMethod<?>) ctMethod).getSignature(),
											arrayInitialization.getPosition().getLine(), arrayInitialization,
											LocationType.ARRAY_INITIALIZATION));

									suspiciousLocationList.add(new SuspiciousLocation(
											arrayInitialization.getDimensionExpressions().get(0)
													.getParent(CtClass.class).getQualifiedName(),
											arrayInitialization
													.getDimensionExpressions().get(0).getPosition().getFile().getName(),
											((CtMethod<?>) ctMethod).getSignature(),
											arrayInitialization.getDimensionExpressions().get(0).getPosition()
													.getLine(),
											arrayInitialization.getDimensionExpressions().get(0),
											LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

									getSuspicousArrayInitialization(
											arrayInitialization.getDimensionExpressions().get(0), failureInfo,
											suspiciousLocationList);
								}
							}
						} else if (ctField.getAssignment() instanceof CtFieldReadImpl) { // 1.4 CtVariableReadImpl:
																							// int[] array = array2;
							CtFieldReadImpl<?> arrayInitialization = (CtFieldReadImpl<?>) ctField.getAssignment();

							// Recursion
							suspiciousLocationList.add(new SuspiciousLocation(
									arrayInitialization.getParent(CtClass.class).getQualifiedName(),
									arrayInitialization.getPosition().getFile().getName(),
									((CtMethod<?>) ctMethod).getSignature(),
									arrayInitialization.getPosition().getLine(), arrayInitialization,
									LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT));

							getSuspicousArrayInitialization(arrayInitialization, failureInfo, suspiciousLocationList);
						} else if (ctField.getAssignment() instanceof CtLiteralImpl) {

							CtLiteralImpl<?> arrayInitialization = (CtLiteralImpl<?>) ctField.getAssignment();

							LocationType locationType = null;

							if (ctField.getType().isArray()) {
								locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
							} else {
								locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
							}

							suspiciousLocationList.add(new SuspiciousLocation(
									arrayInitialization.getParent(CtClass.class).getQualifiedName(),
									arrayInitialization.getPosition().getFile().getName(),
									((CtMethod<?>) ctMethod).getSignature(),
									arrayInitialization.getPosition().getLine(), arrayInitialization, locationType));
						}
					}
				}
			}
		} else {
			if (!isClassFieldVariable) {
				List<CtLocalVariable<?>> ctLocalVariableList = ctMethod
						.getElements(new TypeFilter<CtLocalVariable<?>>(CtLocalVariable.class));

				// boolean isLocalVariableFound = false;

				for (CtLocalVariable<?> ctLocalVariable : ctLocalVariableList) {
					if (ctLocalVariable.getAssignment() != null) {
						if (ctLocalVariable.getReference().toString().replace(THIS_KEYWORD, "")
								.equals(ctArrayReadImpl.toString().replace(THIS_KEYWORD, ""))
								&& ctLocalVariable.getType().equals(ctArrayReadImpl.getType())) {

							// isLocalVariableFound = true;

							// Array initialization found -> Check the expression used to define its size

							/*
							 * 1.1 - CtNewArrayImpl: int[] array = new int[1]; 1.2 - CtNewArrayImpl: int[]
							 * array = new int[i]; 1.3 - CtNewArrayImpl: int[] array = new int[i+1];
							 */
							if (ctLocalVariable.getAssignment() instanceof CtNewArrayImpl) {
								CtNewArrayImpl<?> arrayInitialization = (CtNewArrayImpl<?>) ctLocalVariable
										.getAssignment();

								List<CtExpression<Integer>> arrayInitializationExpressionList = arrayInitialization
										.getDimensionExpressions();

								if (arrayInitializationExpressionList.size() == 1) {

									CtExpression<Integer> arrayInitializationExpression = arrayInitializationExpressionList
											.get(0);

									// Integer constant expression (CtLiteralImpl) or complex expression
									// (CtBinaryOperatorImpl)
									if (arrayInitializationExpression instanceof CtLiteralImpl
											|| arrayInitializationExpression instanceof CtBinaryOperatorImpl) {

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitializationExpression.getParent(CtClass.class)
														.getQualifiedName(),
												arrayInitializationExpression.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitializationExpression.getPosition().getLine(),
												arrayInitializationExpression,
												LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

									} else if (arrayInitializationExpression instanceof CtVariableReadImpl) { // Expression
																												// with
																												// single
																												// variable:
																												// CtVariableReadImpl
										// Find the variable

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitializationExpression.getParent(CtClass.class)
														.getQualifiedName(),
												arrayInitializationExpression.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitializationExpression.getPosition().getLine(),
												arrayInitializationExpression,
												LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

										getSuspicousArrayInitialization(arrayInitializationExpression, failureInfo,
												suspiciousLocationList);
									} else if (arrayInitializationExpression instanceof CtFieldReadImpl) { // Expression
																											// with
																											// single
																											// variable:
																											// CtFieldReadImp
										// Find the variable

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList
												.add(new SuspiciousLocation(
														arrayInitialization.getDimensionExpressions().get(0)
																.getParent(CtClass.class).getQualifiedName(),
														arrayInitialization.getDimensionExpressions().get(0)
																.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitialization.getDimensionExpressions().get(0)
																.getPosition().getLine(),
														arrayInitialization.getDimensionExpressions().get(0),
														LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

										getSuspicousArrayInitialization(arrayInitializationExpression, failureInfo,
												suspiciousLocationList);
									}
								}
							} else if (ctLocalVariable.getAssignment() instanceof CtVariableReadImpl) { // 1.4
																										// CtVariableReadImpl:
																										// int[] array =
																										// array2;
								CtVariableReadImpl<?> arrayInitialization = (CtVariableReadImpl<?>) ctLocalVariable
										.getAssignment();

								// Ricorsione

								LocationType locationType = null;

								if (arrayInitialization.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										arrayInitialization.getParent(CtClass.class).getQualifiedName(),
										arrayInitialization.getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										arrayInitialization.getPosition().getLine(), arrayInitialization,
										locationType));

								getSuspicousArrayInitialization(arrayInitialization, failureInfo,
										suspiciousLocationList);

							} else if (ctLocalVariable.getAssignment() instanceof CtFieldReadImpl) { // 1.4
																										// CtVariableReadImpl:
																										// int[] array =
																										// array2;
								CtFieldReadImpl<?> arrayInitialization = (CtFieldReadImpl<?>) ctLocalVariable
										.getAssignment();

								// Ricorsione

								LocationType locationType = null;

								if (arrayInitialization.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										arrayInitialization.getParent(CtClass.class).getQualifiedName(),
										arrayInitialization.getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										arrayInitialization.getPosition().getLine(), arrayInitialization,
										locationType));

								getSuspicousArrayInitialization(arrayInitialization, failureInfo,
										suspiciousLocationList);
							} else if (ctLocalVariable.getAssignment() instanceof CtLiteralImpl) {

								LocationType locationType = null;

								if (ctLocalVariable.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										ctLocalVariable.getAssignment().getParent(CtClass.class).getQualifiedName(),
										ctLocalVariable.getAssignment().getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										ctLocalVariable.getAssignment().getPosition().getLine(),
										ctLocalVariable.getAssignment(), locationType));
							}
						}
					}
				}
			}

			// 2) CtAssignment

			List<CtAssignment<?, ?>> ctAssignmentList = ctMethod
					.getElements(new TypeFilter<CtAssignment<?, ?>>(CtAssignment.class));

			for (CtAssignment<?, ?> ctAssignment : ctAssignmentList) {

				if (ctAssignment.getAssignment() != null) {
					if (ctAssignment.getAssigned().toString().replace(THIS_KEYWORD, "")
							.equals(ctArrayReadImpl.toString().replace(THIS_KEYWORD, ""))
							&& ctAssignment.getAssigned().getType().equals(ctArrayReadImpl.getType())) {

						if (isClassFieldVariable && ctAssignment.getAssigned() instanceof CtFieldWriteImpl
								|| !isClassFieldVariable) {

							// Assignment to the array -> Check the expression used to define its size

							/*
							 * 1.1 - CtNewArrayImpl: array = new int[1]; 1.2 - CtNewArrayImpl: array = new
							 * int[i]; 1.3 - CtNewArrayImpl: array = new int[i+1];
							 */
							if (ctAssignment.getAssignment() instanceof CtNewArrayImpl) {

								CtNewArrayImpl<?> arrayInitialization = (CtNewArrayImpl<?>) ctAssignment
										.getAssignment();

								List<CtExpression<Integer>> arrayInitializationExpressionList = arrayInitialization
										.getDimensionExpressions();

								if (arrayInitializationExpressionList.size() == 1) {

									CtExpression<Integer> arrayInitializationExpression = arrayInitializationExpressionList
											.get(0);

									// Constant integer expression (CtLiteralImpl) or complex expression
									// (CtBinaryOperatorImpl)
									if (arrayInitializationExpression instanceof CtLiteralImpl
											|| arrayInitializationExpression instanceof CtBinaryOperatorImpl) {

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitializationExpression.getParent(CtClass.class)
														.getQualifiedName(),
												arrayInitializationExpression.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitializationExpression.getPosition().getLine(),
												arrayInitializationExpression,
												LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

									} else if (arrayInitializationExpression instanceof CtVariableReadImpl) { // Expression
																												// with
																												// single
																												// variable

										// Find the variable

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitializationExpression.getParent(CtClass.class)
														.getQualifiedName(),
												arrayInitializationExpression.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitializationExpression.getPosition().getLine(),
												arrayInitializationExpression,
												LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

										getSuspicousArrayInitialization(arrayInitializationExpression, failureInfo,
												suspiciousLocationList); // variabile: CtVariableReadImpl

									} else if (arrayInitializationExpression instanceof CtFieldReadImpl) { // Expression
																											// with
																											// single
																											// variable:
																											// CtFieldReadImp

										// Find the variable

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitializationExpression.getParent(CtClass.class)
														.getQualifiedName(),
												arrayInitializationExpression.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitializationExpression.getPosition().getLine(),
												arrayInitializationExpression,
												LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

										getSuspicousArrayInitialization(arrayInitializationExpression, failureInfo,
												suspiciousLocationList);
									}
								}
							} else if (ctAssignment.getAssignment() instanceof CtVariableReadImpl) { // 1.4
																										// CtVariableReadImpl:
																										// array =
																										// array2;
								CtVariableReadImpl<?> arrayInitialization = (CtVariableReadImpl<?>) ctAssignment
										.getAssignment();

								// Recursion

								LocationType locationType = null;

								if (arrayInitialization.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										arrayInitialization.getParent(CtClass.class).getQualifiedName(),
										arrayInitialization.getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										arrayInitialization.getPosition().getLine(), arrayInitialization,
										locationType));

								getSuspicousArrayInitialization(arrayInitialization, failureInfo,
										suspiciousLocationList);

							} else if (ctAssignment.getAssignment() instanceof CtFieldReadImpl) { // 1.4
																									// CtVariableReadImpl:array
																									// = array2;
								CtFieldReadImpl<?> arrayInitialization = (CtFieldReadImpl<?>) ctAssignment
										.getAssignment();

								// Recursion

								LocationType locationType = null;

								if (arrayInitialization.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										arrayInitialization.getParent(CtClass.class).getQualifiedName(),
										arrayInitialization.getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										arrayInitialization.getPosition().getLine(), arrayInitialization,
										locationType));

								getSuspicousArrayInitialization(arrayInitialization, failureInfo,
										suspiciousLocationList);
							} else if (ctAssignment.getAssignment() instanceof CtLiteralImpl) {

								LocationType locationType = null;

								if (ctAssignment.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										ctAssignment.getAssignment().getParent(CtClass.class).getQualifiedName(),
										ctAssignment.getAssignment().getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										ctAssignment.getAssignment().getPosition().getLine(),
										ctAssignment.getAssignment(), locationType));
							}
						}
					}
				}
			}

			// if (!isLocalVariableFound) {

			// 3) CtField

			if (isClassFieldVariable) {

				CtClass<?> ctClass = ctArrayReadImpl.getParent(CtClass.class);
				List<CtField<?>> ctFieldList = ctClass.getElements(new TypeFilter<CtField<?>>(CtField.class));

				for (CtField<?> ctField : ctFieldList) {
					if (ctField.getAssignment() != null) {
						if (ctField.getReference().toString().replace(THIS_KEYWORD, "")
								.equals(ctArrayReadImpl.toString().replace(THIS_KEYWORD, ""))
								&& ctField.getType().equals(ctArrayReadImpl.getType())) {

							// Found the array initialization -> Check the expression used to define its
							// size

							/*
							 * 1.1 - CtNewArrayImpl: int[] array = new int[1]; 1.2 - CtNewArrayImpl: int[]
							 * array = new int[i]; 1.3 - CtNewArrayImpl: int[] array = new int[i+1];
							 */
							if (ctField.getAssignment() instanceof CtNewArrayImpl) {

								CtNewArrayImpl<?> arrayInitialization = (CtNewArrayImpl<?>) ctField.getAssignment();

								List<CtExpression<Integer>> arrayInitializationExpressionList = arrayInitialization
										.getDimensionExpressions();

								if (arrayInitializationExpressionList.size() == 1) {

									CtExpression<Integer> arrayInitializationExpression = arrayInitializationExpressionList
											.get(0);

									// Constant integer expression (CtLiteralImpl) or complex expression
									// (CtBinaryOperatorImpl)
									if (arrayInitializationExpression instanceof CtLiteralImpl
											|| arrayInitializationExpression instanceof CtBinaryOperatorImpl) {

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitializationExpression.getParent(CtClass.class)
														.getQualifiedName(),
												arrayInitializationExpression.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitializationExpression.getPosition().getLine(),
												arrayInitializationExpression,
												LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

									} else if (arrayInitializationExpression instanceof CtFieldReadImpl) { // Expression
																											// with
																											// single
																											// variable:
																											// CtFieldReadImp

										// Find the variable

										suspiciousLocationList.add(new SuspiciousLocation(
												arrayInitialization.getParent(CtClass.class).getQualifiedName(),
												arrayInitialization.getPosition().getFile().getName(),
												((CtMethod<?>) ctMethod).getSignature(),
												arrayInitialization.getPosition().getLine(), arrayInitialization,
												LocationType.ARRAY_INITIALIZATION));

										suspiciousLocationList
												.add(new SuspiciousLocation(
														arrayInitialization.getDimensionExpressions().get(0)
																.getParent(CtClass.class).getQualifiedName(),
														arrayInitialization.getDimensionExpressions().get(0)
																.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitialization.getDimensionExpressions().get(0)
																.getPosition().getLine(),
														arrayInitialization.getDimensionExpressions().get(0),
														LocationType.ARRAY_INITIALIZATION));

										getSuspicousArrayInitialization(
												arrayInitialization.getDimensionExpressions().get(0), failureInfo,
												suspiciousLocationList);
									}
								}
							} else if (ctField.getAssignment() instanceof CtFieldReadImpl) { // 1.4 CtVariableReadImpl:
																								// int[] array = array2;
								CtFieldReadImpl<?> arrayInitialization = (CtFieldReadImpl<?>) ctField.getAssignment();

								// Recursion

								LocationType locationType = null;

								if (arrayInitialization.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										arrayInitialization.getParent(CtClass.class).getQualifiedName(),
										arrayInitialization.getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										arrayInitialization.getPosition().getLine(), arrayInitialization,
										locationType));

								getSuspicousArrayInitialization(arrayInitialization, failureInfo,
										suspiciousLocationList);

							} else if (ctField.getAssignment() instanceof CtLiteralImpl) {

								CtLiteralImpl<?> arrayInitialization = (CtLiteralImpl<?>) ctField.getAssignment();

								LocationType locationType = null;

								if (arrayInitialization.getType().isArray()) {
									locationType = LocationType.ARRAY_INITIALIZATION_ASSIGNMENT;
								} else {
									locationType = LocationType.ARRAY_INDEX_VARIABLE_ASSIGNMENT;
								}

								suspiciousLocationList.add(new SuspiciousLocation(
										arrayInitialization.getParent(CtClass.class).getQualifiedName(),
										arrayInitialization.getPosition().getFile().getName(),
										((CtMethod<?>) ctMethod).getSignature(),
										arrayInitialization.getPosition().getLine(), arrayInitialization,
										locationType));
							}
						}
					} else {
						if (ctField.getReference().toString().replace(THIS_KEYWORD, "")
								.equals(ctArrayReadImpl.toString().replace(THIS_KEYWORD, ""))
								&& ctField.getType().equals(ctArrayReadImpl.getType())) {

							List<CtAssignment<?, ?>> ctAssignmentClassList = ctClass
									.getElements(new TypeFilter<CtAssignment<?, ?>>(CtAssignment.class));

							for (int i = 0; i < ctAssignmentClassList.size(); i++) {
								if (ctAssignmentClassList.get(i).getAssigned().toString().replace(THIS_KEYWORD, "")
										.equals(ctArrayReadImpl.toString().replace(THIS_KEYWORD, ""))
										&& ctField.getType().equals(ctArrayReadImpl.getType())) {

									if (ctAssignmentClassList.get(i).getAssignment() instanceof CtNewArrayImpl) {
										CtNewArrayImpl<?> arrayInitialization = (CtNewArrayImpl<?>) ctAssignmentClassList
												.get(i).getAssignment();

										List<CtExpression<Integer>> arrayInitializationExpressionList = arrayInitialization
												.getDimensionExpressions();

										if (arrayInitializationExpressionList.size() == 1) {

											CtExpression<Integer> arrayInitializationExpression = arrayInitializationExpressionList
													.get(0);

											// Constant integer expression (CtLiteralImpl) or complex expression
											// (CtBinaryOperatorImpl)
											if (arrayInitializationExpression instanceof CtLiteralImpl
													|| arrayInitializationExpression instanceof CtBinaryOperatorImpl) {

												suspiciousLocationList.add(new SuspiciousLocation(
														arrayInitialization.getParent(CtClass.class).getQualifiedName(),
														arrayInitialization.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitialization.getPosition().getLine(),
														arrayInitialization, LocationType.ARRAY_INITIALIZATION));

												suspiciousLocationList.add(new SuspiciousLocation(
														arrayInitializationExpression.getParent(CtClass.class)
																.getQualifiedName(),
														arrayInitializationExpression.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitializationExpression.getPosition().getLine(),
														arrayInitializationExpression,
														LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

											} else if (arrayInitializationExpression instanceof CtVariableReadImpl) { // Expression
																														// with
																														// single
																														// variable:
																														// CtVariableReadImpl
												// Find the variable

												suspiciousLocationList.add(new SuspiciousLocation(
														arrayInitialization.getParent(CtClass.class).getQualifiedName(),
														arrayInitialization.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitialization.getPosition().getLine(),
														arrayInitialization, LocationType.ARRAY_INITIALIZATION));

												suspiciousLocationList.add(new SuspiciousLocation(
														arrayInitializationExpression.getParent(CtClass.class)
																.getQualifiedName(),
														arrayInitializationExpression.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitializationExpression.getPosition().getLine(),
														arrayInitializationExpression,
														LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

												getSuspicousArrayInitialization(arrayInitializationExpression,
														failureInfo, suspiciousLocationList);
											} else if (arrayInitializationExpression instanceof CtFieldReadImpl) { // Expression
																													// with
																													// single
																													// variable:
																													// CtFieldReadImp
												// Find the variable

												suspiciousLocationList.add(new SuspiciousLocation(
														arrayInitialization.getParent(CtClass.class).getQualifiedName(),
														arrayInitialization.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitialization.getPosition().getLine(),
														arrayInitialization, LocationType.ARRAY_INITIALIZATION));

												suspiciousLocationList.add(new SuspiciousLocation(
														arrayInitialization.getDimensionExpressions().get(0)
																.getParent(CtClass.class).getQualifiedName(),
														arrayInitialization.getDimensionExpressions().get(0)
																.getPosition().getFile().getName(),
														((CtMethod<?>) ctMethod).getSignature(),
														arrayInitialization.getDimensionExpressions().get(0)
																.getPosition().getLine(),
														arrayInitialization.getDimensionExpressions().get(0),
														LocationType.INDEX_USED_FOR_ARRAY_INITIALIZATION));

												getSuspicousArrayInitialization(arrayInitializationExpression,
														failureInfo, suspiciousLocationList);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		return suspiciousLocationList;
	}

	private List<CtStatement> getSuspiciousStatementList(StackTracePOI stackTracePOI) {

		List<CtStatement> suspiciousStatementList = new ArrayList<CtStatement>();

		// This is the class that contains the suspicious statement
		CtClass<?> ctClass = launcher.getFactory().Class().get(stackTracePOI.getClassName());

		List<CtStatement> classStatementList = ctClass.getElements(new TypeFilter<>(CtStatement.class));

		boolean isStatementFound = false;

		// Find the suspicious statement in the class
		for (CtStatement ctStatement : classStatementList) {
			if (!isStatementFound) {
				try {
					if (ctStatement.getPosition().getLine() == stackTracePOI.getLineNumber()) {
						suspiciousStatementList.add(ctStatement);
						isStatementFound = true;
					}
				} catch (UnsupportedOperationException exception) {
					continue;
				}
			}
		}

		if (suspiciousStatementList.isEmpty()) {
			return null;
		} else {
			return suspiciousStatementList;
		}
	}

	private List<CtArrayReadImpl<?>> getSuspiciousArrayReadImpl(CtStatement ctStatement) {
		return ctStatement.getElements(new TypeFilter<CtArrayReadImpl<?>>(CtArrayReadImpl.class));
	}

	private List<CtArrayWriteImpl<?>> getSuspiciousArrayWriteImpl(CtStatement ctStatement) {
		return ctStatement.getElements(new TypeFilter<CtArrayWriteImpl<?>>(CtArrayWriteImpl.class));
	}

	private List<CtFieldReadImpl<?>> getSuspiciousArrayCtFieldReadImpl(CtStatement ctStatement) {
		List<CtFieldReadImpl<?>> ctFieldReadImplList = ctStatement
				.getElements(new TypeFilter<CtFieldReadImpl<?>>(CtFieldReadImpl.class));
		List<CtFieldReadImpl<?>> ctFieldReadImplFilteredList = new ArrayList<CtFieldReadImpl<?>>();

		ctFieldReadImplList.forEach((e) -> {
			if (e.getType().isArray()) {
				ctFieldReadImplFilteredList.add(e);
			}
		});

		return ctFieldReadImplFilteredList;
	}
}