package options

type ProxyAuth struct {
	Upstream      string
	GuestRoleName string
	GuestUser     string
	GuestPassword string
	AdminRoleName string
	AdminUser     string
	AdminPassword string
}
