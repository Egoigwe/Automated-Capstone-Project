variable "all-cidr" {}
variable "cidr" {}
variable "domain" {}
variable "mysqlport" {}
variable "httpport" {}
variable "httpsport" {}
variable "sshport" {}
variable "private_subnet_2" {}
variable "private_subnet_1" {}
variable "public_subnet_1" {}
variable "public_subnet_2" {}
variable "redhat_ami" {}
variable "instance_type" {}
variable "dbusername" {}
variable "dbpassword" {}
variable "db-identifier" {}
variable "dbname" {}

variable "dbcred" {
    type = map(string)
    default =  {
        username = "admin"
        password = "admin123"
  }

}
