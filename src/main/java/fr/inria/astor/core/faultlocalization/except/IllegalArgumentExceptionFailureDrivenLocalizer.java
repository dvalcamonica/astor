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
import spoon.support.reflect.code.CtArrayReadImpl;
import spoon.support.reflect.code.CtFieldReadImpl;
import spoon.support.reflect.code.CtInvocationImpl;
import spoon.support.reflect.code.CtLocalVariableImpl;
import spoon.support.reflect.code.CtNewArrayImpl;
import spoon.support.reflect.code.CtNewClassImpl;
import spoon.support.reflect.code.CtVariableAccessImpl;
import spoon.support.reflect.code.CtVariableReadImpl;
import spoon.support.reflect.declaration.CtFieldImpl;
import spoon.support.reflect.declaration.CtParameterImpl;

public class IllegalArgumentExceptionFailureDrivenLocalizer extends FailureDrivenLocalizer {

	private List<StackTracePOI> stackTracePOIList;

	public IllegalArgumentExceptionFailureDrivenLocalizer(String programSourceCodePath) {
		super(programSourceCodePath);
	}

	@Override
	public List<SuspiciousLocation> getSuspiciousLocations(FailureInfo failureInfo) {

		List<SuspiciousLocation> suspiciousLocationList = new ArrayList<SuspiciousLocation>();
		stackTracePOIList = failureInfo.getStackTracePOIList();

		StackTracePOI stackTracePOI = null;

		if (stackTracePOIList.size() > 1) {
			stackTracePOI = stackTracePOIList.get(1);
		} else {
			stackTracePOI = stackTracePOIList.get(0);
		}

		List<CtStatement> suspiciousStatementList = getSuspiciousStatementList(stackTracePOI);

		List<CtInvocationImpl<?>> ctInvocationImplList = getSuspiciousCtInvocationImpl(suspiciousStatementList.get(0));

		List<CtNewClassImpl<?>> ctCtNewClassImplList = getSuspiciousCtNewClassImpl(suspiciousStatementList.get(0));

		List<CtVariableAccessImpl<?>> ctParameterVariableAccessList = new ArrayList<CtVariableAccessImpl<?>>();

		for (int i = 0; i < ctInvocationImplList.size(); i++) {
			List<CtExpression<?>> ctMethodArguments = ctInvocationImplList.get(i).getArguments();

			for (int j = 0; j < ctMethodArguments.size(); j++) {

				if (ctMethodArguments.get(j) instanceof CtVariableAccessImpl<?>) {
					ctParameterVariableAccessList.add((CtVariableAccessImpl<?>) ctMethodArguments.get(j));
				}

				suspiciousLocationList.add(
						new SuspiciousLocation(ctMethodArguments.get(j).getParent(CtClass.class).getQualifiedName(),
								ctMethodArguments.get(j).getPosition().getFile().getName(),
								stackTracePOI.getMethodName(), ctMethodArguments.get(j).getPosition().getLine(),
								ctMethodArguments.get(j), LocationType.METHOD_PARAMETER));
			}

			suspiciousLocationList
					.add(new SuspiciousLocation(ctInvocationImplList.get(i).getParent(CtClass.class).getQualifiedName(),
							ctInvocationImplList.get(i).getPosition().getFile().getName(),
							stackTracePOI.getMethodName(), ctInvocationImplList.get(i).getPosition().getLine(),
							ctInvocationImplList.get(i), LocationType.METHOD_INVOCATION));
		}

		for (int i = 0; i < ctCtNewClassImplList.size(); i++) {
			List<CtExpression<?>> ctMethodArguments = ctCtNewClassImplList.get(i).getArguments();

			for (int j = 0; j < ctMethodArguments.size(); j++) {

				if (ctMethodArguments.get(j) instanceof CtVariableAccessImpl<?>) {
					ctParameterVariableAccessList.add((CtVariableAccessImpl<?>) ctMethodArguments.get(j));
				}

				suspiciousLocationList.add(
						new SuspiciousLocation(ctMethodArguments.get(j).getParent(CtClass.class).getQualifiedName(),
								ctMethodArguments.get(j).getPosition().getFile().getName(),
								stackTracePOI.getMethodName(), ctMethodArguments.get(j).getPosition().getLine(),
								ctMethodArguments.get(j), LocationType.METHOD_PARAMETER));
			}

			suspiciousLocationList
					.add(new SuspiciousLocation(ctInvocationImplList.get(i).getParent(CtClass.class).getQualifiedName(),
							ctInvocationImplList.get(i).getPosition().getFile().getName(),
							stackTracePOI.getMethodName(), ctInvocationImplList.get(i).getPosition().getLine(),
							ctInvocationImplList.get(i), LocationType.METHOD_INVOCATION));
		}

		List<CtVariableAccessImpl<?>> ctParameterVariableAccessListFiltered = ctParameterVariableAccessList.stream()
				.distinct().collect(Collectors.toList());

		for (int i = 0; i < ctParameterVariableAccessListFiltered.size(); i++) {
			suspiciousLocationList.addAll(getSuspiciousLocationsFromStatement(suspiciousStatementList.get(0),
					suspiciousLocationList, ctParameterVariableAccessListFiltered.get(i)));
		}

		suspiciousLocationList
				.sort((SuspiciousLocation s1, SuspiciousLocation s2) -> s2.getLineNumber() - s1.getLineNumber());

		return suspiciousLocationList.stream().distinct().collect(Collectors.toList());
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

	private List<CtInvocationImpl<?>> getSuspiciousCtInvocationImpl(CtStatement ctStatement) {
		return ctStatement.getElements(new TypeFilter<CtInvocationImpl<?>>(CtInvocationImpl.class));
	}

	private List<CtNewClassImpl<?>> getSuspiciousCtNewClassImpl(CtStatement ctStatement) {
		return ctStatement.getElements(new TypeFilter<CtNewClassImpl<?>>(CtNewClassImpl.class));
	}

	public List<SuspiciousLocation> getSuspiciousLocationsFromStatement(CtStatement suspiciousStatement,
			List<SuspiciousLocation> suspiciousLocationList, CtExpression<?> ctExpression) {

		CtClass<?> ctClass = suspiciousStatement.getParent(CtClass.class);
		CtElement ctMethod = suspiciousStatement.getParent(CtMethod.class);

		List<CtFieldReadImpl<?>> ctFieldReadImplList = new ArrayList<CtFieldReadImpl<?>>();
		List<CtVariableReadImpl<?>> ctVariableReadImplList = new ArrayList<CtVariableReadImpl<?>>();
		List<CtArrayReadImpl<?>> ctArrayReadImplList = new ArrayList<CtArrayReadImpl<?>>();

		List<CtAssignment<?, ?>> ctAssignmntList = ctMethod
				.getElements(new TypeFilter<CtAssignment<?, ?>>(CtAssignment.class));
		List<CtLocalVariableImpl<?>> ctLocalVariableList = ctMethod
				.getElements(new TypeFilter<CtLocalVariableImpl<?>>(CtLocalVariableImpl.class));
		List<CtParameterImpl<?>> ctParameterList = ctMethod
				.getElements(new TypeFilter<CtParameterImpl<?>>(CtParameterImpl.class));
		List<CtNewArrayImpl<?>> ctNewArrayImplList = ctMethod
				.getElements(new TypeFilter<CtNewArrayImpl<?>>(CtNewArrayImpl.class));
		ctNewArrayImplList.addAll(ctClass.getElements(new TypeFilter<CtNewArrayImpl<?>>(CtNewArrayImpl.class)));

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

		for (int i = 0; i < ctNewArrayImplList.size(); i++) {
			if (ctNewArrayImplList.get(i).getPosition().getLine() > suspiciousStatement.getPosition().getLine()) {
				ctNewArrayImplList.remove(i);
				i--;
			}
		}

		Collections.reverse(ctAssignmntList);
		Collections.reverse(ctLocalVariableList);
		Collections.reverse(ctParameterList);
		Collections.reverse(ctNewArrayImplList);

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

		if (ctExpression instanceof CtArrayReadImpl) {
			ctArrayReadImplList.add((CtArrayReadImpl<?>) ctExpression);

			suspiciousLocationList
					.add(new SuspiciousLocation(ctClass.getQualifiedName(), ctClass.getPosition().getFile().getName(),
							stackTracePOIList.get(0).getMethodName(), ctExpression.getPosition().getLine(),
							((CtArrayReadImpl<?>) ctExpression).getTarget(), LocationType.BEFORE_VARIABLE_ACCESS));

			suspiciousLocationList
					.add(new SuspiciousLocation(ctClass.getQualifiedName(), ctClass.getPosition().getFile().getName(),
							stackTracePOIList.get(0).getMethodName(), ctExpression.getPosition().getLine(),
							((CtArrayReadImpl<?>) ctExpression).getTarget(), LocationType.VARIABLE_ACCESS));

			for (int i = 0; i < ctNewArrayImplList.size(); i++) {
				if (ctNewArrayImplList.get(i).getParent() instanceof CtLocalVariableImpl) {
					if (((CtLocalVariableImpl<?>) ctNewArrayImplList.get(i).getParent()).getSimpleName()
							.equals(((CtArrayReadImpl<?>) ctExpression).getTarget().toString())) {
						suspiciousLocationList.add(new SuspiciousLocation(ctClass.getQualifiedName(),
								ctClass.getPosition().getFile().getName(), stackTracePOIList.get(0).getMethodName(),
								ctNewArrayImplList.get(i).getPosition().getLine(), ctNewArrayImplList.get(i),
								LocationType.VARIABLE_DECLARATION));
					}
				} else if (ctNewArrayImplList.get(i).getParent() instanceof CtFieldImpl) {
					if (((CtFieldImpl<?>) ctNewArrayImplList.get(i).getParent()).getReference().toString()
							.equals(((CtArrayReadImpl<?>) ctExpression).getTarget().toString())) {
						suspiciousLocationList.add(new SuspiciousLocation(ctClass.getQualifiedName(),
								ctClass.getPosition().getFile().getName(), stackTracePOIList.get(0).getMethodName(),
								ctNewArrayImplList.get(i).getPosition().getLine(), ctNewArrayImplList.get(i),
								LocationType.VARIABLE_DECLARATION));
					}
				}
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

		for (int i = 0; i < ctArrayReadImplList.size(); i++) {
			for (int j = 0; j < ctAssignmntList.size(); j++) {
				if (ctAssignmntList.get(j).getAssigned().toString()
						.equals(ctArrayReadImplList.get(i).getTarget().toString())) {
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

						if (suspiciousStatementList.size() > 0) {
							suspiciousLocationList.add(new SuspiciousLocation(stackTracePOIList.get(1).getClassName(),
									stackTracePOIList.get(1).getFileName(), stackTracePOIList.get(1).getMethodName(),
									stackTracePOIList.get(1).getLineNumber(), suspiciousStatementList.get(0),
									LocationType.METHOD_INVOCATION));
						}
					}
				}
			}
		}

		for (int i = 0; i < ctArrayReadImplList.size(); i++) {
			for (int j = 0; j < ctParameterList.size(); j++) {
				if (ctParameterList.get(j).getSimpleName().equals(ctArrayReadImplList.get(i).getTarget().toString())) {
					if (stackTracePOIList.size() > 1) {
						List<CtStatement> suspiciousStatementList = getSuspiciousStatementList(
								stackTracePOIList.get(1));
						if (suspiciousStatementList.size() > 0) {
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
