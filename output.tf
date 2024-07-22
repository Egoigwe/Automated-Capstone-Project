output "wordpress-server-ip" {
  value = aws_instance.wordpress_server.public_ip

}
output "db-endpoint" {
  value = aws_db_instance.wordpress-db.endpoint

}