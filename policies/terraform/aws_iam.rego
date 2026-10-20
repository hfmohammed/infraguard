package infraguard.terraform

deny[tf_message("TF-AWS-IAM-001", "IAM policy contains wildcard access", change.address)] {
	change := changes[_]
	change.type == "aws_iam_policy"
	document := json.unmarshal(change.change.after.policy)
	statement := document.Statement[_]
	statement.Effect == "Allow"
	wildcard(statement.Action)
	wildcard(statement.Resource)
}

wildcard(value) {
	value == "*"
}

wildcard(value) {
	value[_] == "*"
}
