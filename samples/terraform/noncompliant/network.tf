resource "aws_security_group" "ssh_open" {
  name = "ssh-open"
  ingress { protocol = "tcp"; from_port = 20; to_port = 25; cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_security_group" "wide_open" {
  name = "wide-open"
  ingress { protocol = "-1"; from_port = 0; to_port = 0; ipv6_cidr_blocks = ["::/0"] }
}

