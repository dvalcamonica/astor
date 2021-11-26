package fr.inria.astor.core.faultlocalization.except;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import fr.inria.astor.core.faultlocalization.except.SuspiciousLocation.LocationType;
import spoon.reflect.code.CtAssignment;
import spoon.reflect.code.CtExpression;
import spoon.reflect.code.CtStatement;
import spoon.reflect.declaration.CtClass;
import spoon.reflect.declaration.CtElement;
import spoon.reflect.declaration.CtMethod;
import spoon.reflect.visitor.filter.TypeFilter;
import spoon.support.reflect.code.CtFieldReadImpl;
import spoon.support.reflect.code.CtInvocationImpl;
import spoon.support.reflect.code.CtLocalVariableImpl;
import spoon.support.reflect.code.CtTypeAccessImpl;
import spoon.support.reflect.code.CtVariableAccessImpl;
import spoon.support.reflect.code.CtVariableReadImpl;
import spoon.support.reflect.declaration.CtParameterImpl;

//@test stackTracePOIList.get(0).getMethodName();

public class StringIndexOutOfBoundsExceptionFailureDrivenLocalizer extends FailureDrivenLocalizer {

	private static List<StackTracePOI> stackTracePOIList;

	public StringIndexOutOfBoundsExceptionFailureDrivenLocalizer(String programSourceCodePath) {
		super(programSourceCodePath);
	}

	@Override
	public List<SuspiciousLocation> getSuspiciousLocations(FailureInfo failureInfo) {

		List<SuspiciousLocation> suspiciousLocationList = new ArrayList<SuspiciousLocation>();
		stackTracePOIList = failureInfo.getStackTracePOIList();

		StackTracePOI stackTracePOI = stackTracePOIList.get(0);

		// CtMethod<?> ctMethod = getMethod(stackTracePOI);
		// assert (ctMethod != null);

		List<CtStatement> suspiciousStatementList = getSuspiciousStatementList(stackTracePOI);

		if (suspiciousStatementList == null) {
			return null;
		}

		List<CtInvocationImpl<?>> ctInvocationImplList = getSuspiciousVariableAccessImpl(
				suspiciousStatementList.get(0));

		List<CtVariableAccessImpl<?>> ctVariableAccessList = new ArrayList<CtVariableAccessImpl<?>>();
		List<CtTypeAccessImpl<?>> ctCtTypeAccessImpl = new ArrayList<CtTypeAccessImpl<?>>();
		List<CtVariableAccessImpl<?>> ctParameterVariableAccessList = new ArrayList<CtVariableAccessImpl<?>>();

		for (int i = 0; i < ctInvocationImplList.size(); i++) {

			if (ctInvocationImplList.get(i).getTarget() instanceof CtVariableAccessImpl<?>
					&& ctInvocationImplList.get(i).getTarget().getType().getSimpleName().equals("String")) {

				suspiciousLocationList.add(new SuspiciousLocation(
						ctInvocationImplList.get(i).getTarget().getParent(CtClass.class).getQualifiedName(),
						ctInvocationImplList.get(i).getTarget().getPosition().getFile().getName(),
						stackTracePOI.getMethodName(), ctInvocationImplList.get(i).getTarget().getPosition().getLine(),
						ctInvocationImplList.get(i).getTarget(), LocationType.VARIABLE_ACCESS));

				ctVariableAccessList.add((CtVariableAccessImpl<?>) ctInvocationImplList.get(i).getTarget());

				List<CtExpression<?>> methodParameters = ctInvocationImplList.get(i).getArguments();

				for (int j = 0; j < methodParameters.size(); j++) {
					if (methodParameters.get(j).getType().getSimpleName().equals("int")) {
						suspiciousLocationList.add(new SuspiciousLocation(
								methodParameters.get(j).getParent(CtClass.class).getQualifiedName(),
								methodParameters.get(j).getPosition().getFile().getName(),
								stackTracePOI.getMethodName(), methodParameters.get(j).getPosition().getLine(),
								methodParameters.get(j), LocationType.INDEX_USED_FOR_VARIABLE_ACCESS));
					}
					if (methodParameters.get(j).getType().getSimpleName().equals("String")
							|| methodParameters.get(j).getType().isArray()) {
						suspiciousLocationList.add(new SuspiciousLocation(
								methodParameters.get(j).getParent(CtClass.class).getQualifiedName(),
								methodParameters.get(j).getPosition().getFile().getName(),
								stackTracePOI.getMethodName(), methodParameters.get(j).getPosition().getLine(),
								methodParameters.get(j), LocationType.METHOD_PARAMETER));
					}

					if (methodParameters.get(j) instanceof CtVariableAccessImpl<?>) {
						ctParameterVariableAccessList.add((CtVariableAccessImpl<?>) methodParameters.get(j));
					}
				}
				// It manages cases in which there is a call to a static method (e.g.,
				// Character.charCount)
			} else if (ctInvocationImplList.get(i).getTarget() instanceof CtTypeAccessImpl<?>) {

				suspiciousLocationList.add(new SuspiciousLocation(
						ctInvocationImplList.get(i).getTarget().getParent(CtClass.class).getQualifiedName(),
						ctInvocationImplList.get(i).getPosition().getFile().getName(), stackTracePOI.getMethodName(),
						ctInvocationImplList.get(i).getPosition().getLine(), ctInvocationImplList.get(i).getTarget(),
						LocationType.VARIABLE_ACCESS));

				ctCtTypeAccessImpl.add((CtTypeAccessImpl<?>) ctInvocationImplList.get(i).getTarget());

				List<CtExpression<?>> methodParameters = ctInvocationImplList.get(i).getArguments();

				for (int j = 0; j < methodParameters.size(); j++) {
					if (methodParameters.get(j).getType().getSimpleName().equals("int")) {
						suspiciousLocationList.add(new SuspiciousLocation(
								methodParameters.get(j).getParent(CtClass.class).getQualifiedName(),
								methodParameters.get(j).getPosition().getFile().getName(),
								stackTracePOI.getMethodName(), methodParameters.get(j).getPosition().getLine(),
								methodParameters.get(j), LocationType.INDEX_USED_FOR_VARIABLE_ACCESS));
					}
					if (methodParameters.get(j).getType().getSimpleName().equals("String")
							|| methodParameters.get(j).getType().isArray()) {
						suspiciousLocationList.add(new SuspiciousLocation(
								methodParameters.get(j).getParent(CtClass.class).getQualifiedName(),
								methodParameters.get(j).getPosition().getFile().getName(),
								stackTracePOI.getMethodName(), methodParameters.get(j).getPosition().getLine(),
								methodParameters.get(j), LocationType.METHOD_PARAMETER));
					}

					if (methodParameters.get(j) instanceof CtVariableAccessImpl<?>) {
						ctParameterVariableAccessList.add((CtVariableAccessImpl<?>) methodParameters.get(j));
					}
				}
			}
		}

		List<CtVariableAccessImpl<?>> ctVariableAccessListFiltered = ctVariableAccessList.stream().distinct()
				.collect(Collectors.toList());
		List<CtVariableAccessImpl<?>> ctParameterVariableAccessListFiltered = ctParameterVariableAccessList.stream()
				.distinct().collect(Collectors.toList());

		for (int i = 0; i < ctVariableAccessListFiltered.size(); i++) {
			suspiciousLocationList.addAll(getSuspiciousLocationsFromStatement(suspiciousStatementList.get(0),
					suspiciousLocationList, ctVariableAccessListFiltered.get(i)));
		}

		for (int i = 0; i < ctParameterVariableAccessListFiltered.size(); i++) {
			suspiciousLocationList.addAll(getSuspiciousLocationsFromStatement(suspiciousStatementList.get(0),
					suspiciousLocationList, ctParameterVariableAccessListFiltered.get(i)));
		}

		suspiciousLocationList
				.sort((SuspiciousLocation s1, SuspiciousLocation s2) -> s2.getLineNumber() - s1.getLineNumber());

		List<SuspiciousLocation> sortedSuspiciousLocationList = new ArrayList<SuspiciousLocation>();

		for (int i = 0; i < suspiciousLocationList.size(); i++) {
			if (suspiciousLocationList.get(i).getLocationType() != LocationType.METHOD_INVOCATION) {
				sortedSuspiciousLocationList.add(suspiciousLocationList.get(i));
			}
		}

		for (int i = 0; i < suspiciousLocationList.size(); i++) {
			if (suspiciousLocationList.get(i).getLocationType() == LocationType.METHOD_INVOCATION) {
				sortedSuspiciousLocationList.add(suspiciousLocationList.get(i));
			}
		}

		return sortedSuspiciousLocationList.stream().distinct().collect(Collectors.toList());
	}

// @DA RIVEDERE
	/**
	 * private CtMethod<?> getMethod(StackTracePOI stackTracePOI) { CtMethod<?>
	 * ctMethod = null;
	 * 
	 * // This is the class that contains the suspicious statement CtClass<?>
	 * ctClass = launcher.getFactory().Class().get(stackTracePOI.getClassName());
	 * assert (ctClass != null); if (ctClass == null) { System.out.println("Ho
	 * ritornato null 179"); return null; }
	 * 
	 * Set<CtMethod<?>> methods = ctClass.getAllMethods(); Iterator<CtMethod<?>> it
	 * = methods.iterator(); boolean isStatementFound = false;
	 * 
	 * // Find the suspicious statement in the class while (it.hasNext()) { if
	 * (!isStatementFound) { try { if (it.next().getSimpleName() ==
	 * stackTracePOI.getMethodName()) { ctMethod = it.next(); isStatementFound =
	 * true; } } catch (UnsupportedOperationException exception) { continue; } } }
	 * 
	 * return ctMethod;
	 * 
	 * }
	 */

	private List<CtStatement> getSuspiciousStatementList(StackTracePOI stackTracePOI) {

		List<CtStatement> suspiciousStatementList = new ArrayList<CtStatement>();

		// This is the class that contains the suspicious statement
		CtClass<?> ctClass = launcher.getFactory().Class().get(stackTracePOI.getClassName());

		if (ctClass == null) {
			return null;
		}

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

	private List<CtInvocationImpl<?>> getSuspiciousVariableAccessImpl(CtStatement ctStatement) {
		return ctStatement.getElements(new TypeFilter<CtInvocationImpl<?>>(CtInvocationImpl.class));
	}

	public List<SuspiciousLocation> getSuspiciousLocationsFromStatement(CtStatement suspiciousStatement,
			List<SuspiciousLocation> suspiciousLocationList, CtExpression<?> ctExpression) {

		CtClass<?> ctClass = suspiciousStatement.getParent(CtClass.class);
		CtElement ctMethod = suspiciousStatement.getParent(CtMethod.class);

		List<CtFieldReadImpl<?>> ctFieldReadImplList = new ArrayList<CtFieldReadImpl<?>>();
		List<CtVariableReadImpl<?>> ctVariableReadImplList = new ArrayList<CtVariableReadImpl<?>>();

		List<CtAssignment<?, ?>> ctAssignmntList = ctMethod
				.getElements(new TypeFilter<CtAssignment<?, ?>>(CtAssignment.class));
		List<CtLocalVariableImpl<?>> ctLocalVariableList = ctMethod
				.getElements(new TypeFilter<CtLocalVariableImpl<?>>(CtLocalVariableImpl.class));
		List<CtParameterImpl<?>> ctParameterList = ctMethod
				.getElements(new TypeFilter<CtParameterImpl<?>>(CtParameterImpl.class));

		for (int i = 0; i < ctAssignmntList.size(); i++) {
			if (ctAssignmntList.get(i).getPosition().getLine() > suspiciousStatement.getPosition().getLine()) {
				ctAssignmntList.remove(i);
				i--;
			}
		}

		for (int i = 0; i < ctLocalVariableList.size(); i++) {
			if (ctLocalVariableList.get(i).getPosition().getLine() > suspiciousStatement.getPosition().getLine()) {
				ctLocalVariableList.remove(i);
				i--;
			}
		}

		for (int i = 0; i < ctParameterList.size(); i++) {
			if (ctParameterList.get(i).getPosition().getLine() > suspiciousStatement.getPosition().getLine()) {
				ctParameterList.remove(i);
				i--;
			}
		}

		Collections.reverse(ctAssignmntList);
		Collections.reverse(ctLocalVariableList);
		Collections.reverse(ctParameterList);

		if (ctExpression instanceof CtFieldReadImpl) {
			ctFieldReadImplList.add((CtFieldReadImpl<?>) ctExpression);

			suspiciousLocationList
					.add(new SuspiciousLocation(ctClass.getQualifiedName(), ctClass.getPosition().getFile().getName(),
							stackTracePOIList.get(0).getMethodName(), ctExpression.getPosition().getLine(),
							((CtFieldReadImpl<?>) ctExpression), LocationType.BEFORE_VARIABLE_ACCESS));

			suspiciousLocationList
					.add(new SuspiciousLocation(ctClass.getQualifiedName(), ctClass.getPosition().getFile().getName(),
							stackTracePOIList.get(0).getMethodName(), ctExpression.getPosition().getLine(),
							((CtFieldReadImpl<?>) ctExpression), LocationType.VARIABLE_ACCESS));

			if (((CtFieldReadImpl<?>) ctExpression).getVariable().getDeclaration() != null) {
				suspiciousLocationList.add(new SuspiciousLocation(ctClass.getQualifiedName(),
						ctClass.getPosition().getFile().getName(), stackTracePOIList.get(0).getMethodName(),
						((CtFieldReadImpl<?>) ctExpression).getVariable().getDeclaration().getPosition().getLine(),
						((CtFieldReadImpl<?>) ctExpression).getVariable().getDeclaration().setComments(null),
						LocationType.VARIABLE_DECLARATION));
			}
		}

		if (ctExpression instanceof CtVariableReadImpl) {
			ctVariableReadImplList.add((CtVariableReadImpl<?>) ctExpression);

			suspiciousLocationList
					.add(new SuspiciousLocation(ctClass.getQualifiedName(), ctClass.getPosition().getFile().getName(),
							stackTracePOIList.get(0).getMethodName(), ctExpression.getPosition().getLine(),
							((CtVariableReadImpl<?>) ctExpression).getVariable(), LocationType.BEFORE_VARIABLE_ACCESS));

			suspiciousLocationList
					.add(new SuspiciousLocation(ctClass.getQualifiedName(), ctClass.getPosition().getFile().getName(),
							stackTracePOIList.get(0).getMethodName(), ctExpression.getPosition().getLine(),
							((CtVariableReadImpl<?>) ctExpression).getVariable(), LocationType.VARIABLE_ACCESS));

			if (((CtVariableReadImpl<?>) ctExpression).getVariable().getDeclaration() != null
					&& !(((CtVariableReadImpl<?>) ctExpression).getVariable()
							.getDeclaration() instanceof CtParameterImpl<?>)) {
				suspiciousLocationList.add(new SuspiciousLocation(ctClass.getQualifiedName(),
						ctClass.getPosition().getFile().getName(), stackTracePOIList.get(0).getMethodName(),
						((CtVariableReadImpl<?>) ctExpression).getVariable().getDeclaration().getPosition().getLine(),
						((CtVariableReadImpl<?>) ctExpression).getVariable().getDeclaration().setComments(null),
						LocationType.VARIABLE_DECLARATION));
			}
		}

		for (int i = 0; i < ctVariableReadImplList.size(); i++) {
			for (int j = 0; j < ctAssignmntList.size(); j++) {
				if (ctAssignmntList.get(j).getAssigned().toString()
						.equals(ctVariableReadImplList.get(i).getVariable().getSimpleName())) {
					suspiciousLocationList.add(new SuspiciousLocation(ctClass.getQualifiedName(),
							ctClass.getPosition().getFile().getName(), stackTracePOIList.get(0).getMethodName(),
							ctAssignmntList.get(j).getPosition().getLine(), ctAssignmntList.get(j),
							LocationType.VARIABLE_ASSIGNMENT));

					List<CtVariableAccessImpl<?>> variableAccessList = ctAssignmntList.get(j)
							.getElements(new TypeFilter<CtVariableAccessImpl<?>>(CtVariableAccessImpl.class));

					for (int x = 0; x < variableAccessList.size(); x++) {
						if (!variableAccessList.get(x).getVariable().getSimpleName()
								.equals(ctVariableReadImplList.get(i).getVariable().getSimpleName())) {
							getSuspiciousLocationsFromStatement(suspiciousStatement, suspiciousLocationList,
									variableAccessList.get(x));
						}
					}
				}
			}
		}

		for (int i = 0; i < ctFieldReadImplList.size(); i++) {
			for (int j = 0; j < ctAssignmntList.size(); j++) {
				if (ctAssignmntList.get(j).getAssigned().toString().equals(ctFieldReadImplList.get(i).toString())) {
					suspiciousLocationList.add(new SuspiciousLocation(ctClass.getQualifiedName(),
							ctClass.getPosition().getFile().getName(), stackTracePOIList.get(0).getMethodName(),
							ctAssignmntList.get(j).getPosition().getLine(), ctAssignmntList.get(j),
							LocationType.VARIABLE_ASSIGNMENT));

					List<CtVariableAccessImpl<?>> variableAccessList = ctAssignmntList.get(j)
							.getElements(new TypeFilter<CtVariableAccessImpl<?>>(CtVariableAccessImpl.class));

					for (int x = 0; x < variableAccessList.size(); x++) {
						getSuspiciousLocationsFromStatement(suspiciousStatement, suspiciousLocationList,
								variableAccessList.get(x));
					}
				}
			}
		}

		for (int i = 0; i < ctVariableReadImplList.size(); i++) {
			for (int j = 0; j < ctParameterList.size(); j++) {
				if (ctParameterList.get(j).getSimpleName()
						.equals(ctVariableReadImplList.get(i).getVariable().getSimpleName())) {

					if (stackTracePOIList.size() > 1) {
						List<CtStatement> suspiciousStatementList = getSuspiciousStatementList(
								stackTracePOIList.get(1));

						if (suspiciousStatementList != null && suspiciousStatementList.size() > 0) {
							suspiciousLocationList.add(new SuspiciousLocation(stackTracePOIList.get(1).getClassName(),
									stackTracePOIList.get(1).getFileName(), stackTracePOIList.get(1).getMethodName(),
									stackTracePOIList.get(1).getLineNumber(), suspiciousStatementList.get(0),
									LocationType.METHOD_INVOCATION));
						}
					}
				}
			}
		}

		for (int i = 0; i < ctVariableReadImplList.size(); i++) {
			for (int j = 0; j < ctLocalVariableList.size(); j++) {
				if (ctLocalVariableList.get(j).getSimpleName()
						.equals(ctVariableReadImplList.get(i).getVariable().getSimpleName())) {
					suspiciousLocationList.add(new SuspiciousLocation(ctClass.getQualifiedName(),
							ctClass.getPosition().getFile().getName(), stackTracePOIList.get(0).getMethodName(),
							ctLocalVariableList.get(j).getPosition().getLine(), ctLocalVariableList.get(j),
							LocationType.VARIABLE_DECLARATION));

					getSuspiciousLocationsFromStatement(suspiciousStatement, suspiciousLocationList,
							ctLocalVariableList.get(j).getAssignment());
				}
			}
		}

		return suspiciousLocationList;
	}
}
