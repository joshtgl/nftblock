variable "PLATFORM" {
  default = "linux/amd64"
}

group "default" {
  targets = ["debian", "alpine"]
}

target "common" {
  context   = "."
  platforms = [PLATFORM]
}

target "debian" {
  inherits   = ["common"]
  dockerfile = "Dockerfile.debian"
  tags       = ["cidrwall:debian"]
}

target "alpine" {
  inherits   = ["common"]
  dockerfile = "Dockerfile.alpine"
  tags       = ["cidrwall:alpine"]
}
