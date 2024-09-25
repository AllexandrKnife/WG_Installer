# WG_Installer
Here's a documentation for the WireGuard installation and management script:

# WireGuard Installation and Management Script

This script automates the installation, configuration, and management of a WireGuard VPN server.

## Prerequisites

- Root access to the server
- A supported operating system (Debian 10+, Ubuntu 18.04+, Fedora 32+, CentOS 8+, AlmaLinux 8+, Rocky Linux 8+, or Arch Linux)
- Python 3.x installed

## Main Features

1. Automatic WireGuard installation
2. User management (add, list, delete users)
3. QR code generation for easy mobile client setup
4. WireGuard server management (restart, remove)

## Usage

Run the script with root privileges:

```
sudo python3 WG_Installer.py
```

The script will perform initial checks and then either install WireGuard or present a management menu if it's already installed.

## Main Menu Options

1. Add new user
2. List all users
3. Create QR code for a user
4. Delete a user
5. Restart WireGuard server
6. Remove WireGuard server
7. Exit menu

## Key Functions

- `install_wireguard()`: Installs and configures WireGuard
- `add_user()`: Adds a new WireGuard client
- `list_users()`: Displays all configured clients
- `regenerate_qr()`: Generates a QR code for a client's configuration
- `delete_user()`: Removes a client's configuration
- `restart_wireguard()`: Restarts the WireGuard service
- `remove_wireguard()`: Uninstalls WireGuard and removes all configurations

## Configuration Files

- Server configuration: `/etc/wireguard/wg0.conf`
- Client configurations: `/etc/wireguard/clients/<username>.conf`
- WireGuard parameters: `/etc/wireguard/params`

## Notes

- The script automatically handles IP address assignment for new clients
- It's recommended to backup the `/etc/wireguard` directory regularly
- For security reasons, always run this script on a trusted, secure system

## Troubleshooting

If you encounter issues:
1. Check system logs: `journalctl -xe`
2. Verify WireGuard status: `systemctl status wg-quick@wg0`
3. Ensure all required ports are open in your firewall

For more detailed information about each function, refer to the inline comments in the script.
