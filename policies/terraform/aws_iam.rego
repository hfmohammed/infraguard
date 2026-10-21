package infraguard.terraform

deny[tf_message("TF-AWS-IAM-001", "IAM policy contains wildcard access", change.address)] {
	change := changes[_]
	iam_policy_type(change.type)
	document := json.unmarshal(change.change.after.policy)
	statement := document.Statement[_]
	statement.Effect == "Allow"
	wildcard(statement.Action)
	wildcard(statement.Resource)
}

iam_policy_type(kind) {
	kind == "aws_iam_policy"
}

iam_policy_type(kind) {
	kind == "aws_iam_role_policy"
}

wildcard(value) {
	value == "*"
}

wildcard(value) {
	value[_] == "*"
}
