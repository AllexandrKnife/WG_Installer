import ipaddress
import os
import random
import subprocess
import sys

# Color schema for terminal output
RED = '\033[0;31m'
ORANGE = '\033[0;33m'
GREEN = '\033[0;32m'
NC = '\033[0m'


class NotRootException(Exception):
    """Exception for when the script is not run as superuser."""
    pass


def is_root():
    if os.geteuid() != 0:
        raise NotRootException("Script must be run as root.")


def check_virt():
    virt_type = subprocess.check_output(["systemd-detect-virt"]).strip()
    if virt_type in [b"openvz", b"lxc"]:
        print(f"{virt_type.decode()} is not supported.")
        sys.exit(1)


def check_os():
    try:
        os_info = subprocess.check_output(["lsb_release", "-a"]).decode().split('\n')
        os_name, version_id = '', ''

        for line in os_info:
            if "Distributor ID" in line:
                os_name = line.split(':')[1].strip().lower()
            if "Release" in line:
                version_id = line.split(':')[1].strip()

        supported_versions = {
            "debian": 10,
            "raspbian": 10,
            "ubuntu": 18,
            "fedora": 32,
            "centos": 8,
            "almalinux": 8,
            "rocky": 8,
        }

        if os_name in supported_versions:
            if int(version_id.split('.')[0]) < supported_versions[os_name]:
                print(f"Your version of {os_name.capitalize()} ({version_id}) is not supported. "
                      f"Please use {os_name.capitalize()} {supported_versions[os_name]} or newer.")
                sys.exit(1)
        else:
            print("The script does not support your operating system.")
            sys.exit(1)

    except subprocess.CalledProcessError:
        print(
            RED + "Error. Ensure the lsb_release command is installed and available." + NC)
        sys.exit(1)


def is_wireguard_installed():
    try:
        # For Debian/Ubuntu
        if subprocess.call(['dpkg', '-s', 'wireguard'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            return True

        # For RHEL/CentOS
        if subprocess.call(['rpm', '-q', 'wireguard-tools'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            return True

        # For Arch Linux
        if subprocess.call(['pacman', '-Qs', 'wireguard-tools'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0:
            return True
    except FileNotFoundError:
        pass

    return False


def install_wireguard():
    if is_wireguard_installed():
        print(GREEN + "\nWireGuard is already installed. Skipping installation step." + NC)
        os.makedirs("/etc/wireguard/clients", exist_ok=True)
    else:
        server_pub_ip, server_pub_nic, server_wg_nic, server_wg_ipv4, server_wg_ipv6, \
            server_port, client_dns_1, client_dns_2, allowed_ips = install_questions()

        os_info = subprocess.check_output(["lsb_release", "-si"]).decode().strip().lower()
        if os_info in ['ubuntu', 'debian']:
            os.system("apt update && apt install -y wireguard iptables resolvconf qrencode")
        elif os_info == 'fedora':
            os.system("dnf install -y wireguard-tools iptables qrencode")
        elif os_info in ['centos', 'almalinux', 'rocky']:
            os.system("yum install -y epel-release elrepo-release && yum install -y wireguard-tools iptables")
        elif os_info == 'arch':
            os.system("pacman -S --needed --noconfirm wireguard-tools qrencode")

        os.makedirs("/etc/wireguard/clients", exist_ok=True)
        server_priv_key = subprocess.check_output("wg genkey", shell=True).decode().strip()
        server_pub_key = subprocess.check_output(f"echo {server_priv_key} | wg pubkey", shell=True).decode().strip()

        with open("/etc/wireguard/params", "w") as f:
            f.write(f"""
SERVER_PUB_IP={server_pub_ip}
SERVER_PUB_NIC={server_pub_nic}
SERVER_WG_NIC={server_wg_nic}
SERVER_WG_IPV4={server_wg_ipv4}
SERVER_WG_IPV6={server_wg_ipv6}
SERVER_PORT={server_port}
SERVER_PRIV_KEY={server_priv_key}
SERVER_PUB_KEY={server_pub_key}
CLIENT_DNS_1={client_dns_1}
CLIENT_DNS_2={client_dns_2}
ALLOWED_IPS={allowed_ips}
""")

        with open(f"/etc/wireguard/{server_wg_nic}.conf", "w") as f:
            f.write(f"""
[Interface]
Address = {server_wg_ipv4}/24,{server_wg_ipv6}/64
ListenPort = {server_port}
PrivateKey = {server_priv_key}

# iptables setup
PostUp = iptables -I INPUT -p udp --dport {server_port} -j ACCEPT
PostUp = iptables -I FORWARD -i {server_pub_nic} -o {server_wg_nic} -j ACCEPT
PostUp = iptables -I FORWARD -i {server_wg_nic} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o {server_pub_nic} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport {server_port} -j ACCEPT
PostDown = iptables -D FORWARD -i {server_pub_nic} -o {server_wg_nic} -j ACCEPT
PostDown = iptables -D FORWARD -i {server_wg_nic} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {server_pub_nic} -j MASQUERADE
""")

        os.system(f"systemctl start wg-quick@{server_wg_nic}")
        os.system(f"systemctl enable wg-quick@{server_wg_nic}")
        print(GREEN + "WireGuard successfully installed." + NC)

    show_menu()


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_ip_with_cidr(ip_cidr):
    ip, *cidr = ip_cidr.split('/')
    if len(cidr) != 1:
        return False
    cidr = cidr[0]

    if ':' in ip:
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    elif '.' in ip:
        if not is_valid_ip(ip):
            return False

    if not cidr.isdigit() or not (0 <= int(cidr) <= (128 if ':' in ip else 32)):
        return False

    return True


def is_valid_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535


def install_questions():
    print(GREEN + "Welcome to the WireGuard installer!" + NC)

    try:
        server_pub_ip = subprocess.check_output(
            "ip -4 addr | grep -oP '(?<=inet )[^/]*' | grep -v '127.0.0.1' | head -n 1",
            shell=True
        ).decode().strip()
    except subprocess.CalledProcessError:
        server_pub_ip = None

    if not server_pub_ip:
        try:
            server_pub_ip = subprocess.check_output(
                "ip -6 addr | grep -oP '(?<=inet6 )[^/]*'",
                shell=True
            ).decode().strip()
        except subprocess.CalledProcessError:
            server_pub_ip = None

    while True:
        input_ip = input(f"Public IPv4 or IPv6 address [{server_pub_ip}]: ").strip()
        if not input_ip:
            input_ip = server_pub_ip
        if input_ip and is_valid_ip(input_ip):
            server_pub_ip = input_ip
            break
        else:
            print(RED + "Invalid IP address. Please enter a valid IP address." + NC)

    try:
        server_pub_nic = subprocess.check_output(
            "ip -4 route ls | grep default | awk '{print $5}'",
            shell=True
        ).decode().strip()
    except subprocess.CalledProcessError:
        server_pub_nic = None

    server_pub_nic = input(f"Public interface [{server_pub_nic}]: ") or server_pub_nic

    server_wg_nic = input("WireGuard interface name [wg0]: ") or "wg0"

    while True:
        server_wg_ipv4 = input("IPv4 for WireGuard [10.7.77.1]: ") or "10.7.77.1"
        if is_valid_ip(server_wg_ipv4):
            break
        else:
            print(RED + "Invalid IPv4. Please enter a valid IPv4 address." + NC)

    while True:
        server_wg_ipv6 = input("IPv6 for WireGuard [fd43:43:43::1]: ") or "fd43:43:43::1"
        if is_valid_ip(server_wg_ipv6):
            break
        else:
            print(RED + "Invalid IPv6. Please enter a valid IPv6 address." + NC)

    while True:
        server_port = input(f"WireGuard port [1-65535]: ").strip() or str(random.randint(49152, 65535))
        if is_valid_port(server_port):
            break
        else:
            print(RED + "Invalid input. Please enter a number between 1 and 65535." + NC)

    while True:
        client_dns_1 = input("First DNS server [1.1.1.1]: ") or "1.1.1.1"
        if is_valid_ip(client_dns_1):
            break
        else:
            print(RED + "Invalid DNS server. Please enter a valid IP address for the DNS server." + NC)

    while True:
        client_dns_2 = input("Second DNS server [1.0.0.1]: ") or "1.0.0.1"
        if is_valid_ip(client_dns_2):
            break
        else:
            print(RED + "Invalid DNS server. Please enter a valid IP address for the DNS server." + NC)

    while True:
        allowed_ips_input = input("Allowed IP list for clients [0.0.0.0/0,::/0]: ").strip()
        if not allowed_ips_input:
            allowed_ips_input = "0.0.0.0/0,::/0"

        allowed_ips = allowed_ips_input.split(',')
        if all(is_valid_ip_with_cidr(ip.strip()) for ip in allowed_ips):
            break
        else:
            print(RED + "Invalid allowed IP list. Please enter valid IP addresses with CIDR." + NC)

    print(GREEN + "Great! We are ready to set up your WireGuard server." + NC)

    return (
        server_pub_ip, server_pub_nic, server_wg_nic, server_wg_ipv4, server_wg_ipv6,
        server_port, client_dns_1, client_dns_2, allowed_ips_input
    )


def show_menu():
    while True:
        print("\nMenu:\n\n"
              "1. Add a new user\n"
              "2. Show user list\n"
              "3. Show user QR code\n"
              "4. Delete user\n"
              "5. Restart WireGuard server\n"
              "6. Remove WireGuard server\n"
              "7. Exit menu")
        choice = input("\nChoose menu item: ").strip()

        if choice == '1':
            add_user()
        elif choice == '2':
            list_users()
        elif choice == '3':
            regenerate_qr()
        elif choice == '4':
            delete_user()
        elif choice == '5':
            restart_wireguard()
        elif choice == '6':
            remove_wireguard()
            break
        elif choice == '7':
            print("\nExiting menu.")
            break
        else:
            print(RED + "Unknown choice. Please try again." + NC)


user_config_path = None  # /etc/wireguard/users/user_name.conf


def extract_server_ip(server_config_path):
    with open(server_config_path, 'r') as f:
        for line in f:
            if line.startswith('Address'):
                _, address = line.split('=')
                return address.strip().split('/')[0]
    return None


def get_unused_ip(server_ip):
    server_ip_obj = ipaddress.ip_address(server_ip)

    start_ip = int(server_ip_obj) + 1
    end_ip = start_ip + 252

    used_ips = set()

    users_dir = "/etc/wireguard/clients"
    try:
        for user_file in os.listdir(users_dir):
            config_path = os.path.join(users_dir, user_file)
            ip_address = extract_ip_address(config_path)
            if ip_address:
                used_ips.add(int(ipaddress.ip_address(ip_address)))
    except FileNotFoundError:
        print(f"{RED}Client folder not found.{NC}")

    for ip_int in range(start_ip, end_ip + 1):
        if ip_int not in used_ips:
            return str(ipaddress.ip_address(ip_int))

    return None


def add_user():
    global user_config_path
    user_config_path = None

    # Create necessary directories for client configurations and QR codes.
    os.makedirs("/etc/wireguard/clients", exist_ok=True)
    os.makedirs("/etc/wireguard/qrcodes", exist_ok=True)

    # Get server configuration variables.
    source_vars = get_config_vars()
    if not source_vars:
        return

    # Check for the existence of WireGuard interface.
    server_wg_nic = source_vars.get('SERVER_WG_NIC')
    if not server_wg_nic or not os.path.exists(f'/sys/class/net/{server_wg_nic}'):
        print(f"Interface {server_wg_nic} not found.")
        return

    # Server configuration file path.
    server_config_path = f"/etc/wireguard/{server_wg_nic}.conf"
    set_file_permissions(server_config_path)

    # Extract server IP address.
    server_ip = extract_server_ip(server_config_path)
    if not server_ip:
        print(f"Could not extract server IP address.")
        return

    # Request new username with validation.
    while True:
        username = input("Enter the name of the new user: ").strip()
        if not username.isalnum():
            print("Username can only contain letters and numbers.")
            continue

        user_config_path = f"/etc/wireguard/clients/{username}.conf"
        if os.path.exists(user_config_path) or is_user_in_server_config(username, server_config_path):
            print("A user with this name already exists. Please choose another name.")
            continue

        break

    # Decision to use pre-shared key.
    use_psk = input("Use pre-shared key? (y/n): ").strip().lower() == 'y'

    try:
        # Generate user's private and public keys.
        user_priv_key = subprocess.check_output("wg genkey", shell=True).decode().strip()
        user_pub_key = subprocess.check_output(f"echo {user_priv_key} | wg pubkey", shell=True).decode().strip()
        # Generate pre-shared key if chosen.
        user_psk = subprocess.check_output("wg genpsk", shell=True).decode().strip() if use_psk else None
    except subprocess.CalledProcessError:
        print("Error generating keys.")
        return

    # Get the first available IP address for the new client.
    client_wg_ipv4 = get_unused_ip(server_ip)
    if not client_wg_ipv4:
        print(f"No available IP addresses.")
        return

    # Read current server configuration.
    with open(server_config_path, 'r') as f:
        lines = f.readlines()

    # Find the correct index to insert new client.
    insert_index = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == "" and i > 0 and lines[i - 1].startswith("[Peer]"):
            insert_index = i
            break
        elif lines[i].startswith("PresharedKey") or lines[i].startswith("AllowedIPs"):
            # Add an empty line after keys for separation.
            insert_index = i + 1
            break

    # Form the configuration block for the new client.
    client_block = [
        "\n",  # Add an empty line to separate blocks.
        f"# Client {username}\n",
        "[Peer]\n",
        f"PublicKey = {user_pub_key}\n",
        f"AllowedIPs = {client_wg_ipv4}/32\n"
    ]
    if use_psk:
        client_block.append(f"PresharedKey = {user_psk}\n")
    client_block.append("\n")

    # Insert the new client block at the correct place.
    lines[insert_index:insert_index] = client_block

    # Write the updated configuration back to the file.
    with open(server_config_path, 'w') as f:
        f.writelines(lines)

    print(f"User {username} has been added to the server configuration.")

    try:
        # Create individual client configuration and QR code.
        with open(user_config_path, 'w') as f:
            f.write(f"""
[Interface]
PrivateKey = {user_priv_key}
Address = {client_wg_ipv4}/24

[Peer]
PublicKey = {source_vars['SERVER_PUB_KEY']}
Endpoint = {source_vars['SERVER_PUB_IP']}:{source_vars['SERVER_PORT']}
AllowedIPs = {source_vars['ALLOWED_IPS']}
""")
            if use_psk:
                f.write(f"PresharedKey = {user_psk}\n")

        set_file_permissions(user_config_path)

        # Generate and save QR code for the client.
        qr_output_path = f"/etc/wireguard/qrcodes/{username}_qrcode.png"
        with open(user_config_path, 'r') as file:
            input_data = file.read()
            subprocess.run(["qrencode", "-t", "ansiutf8"], input=input_data.encode(), check=True)
            subprocess.run(["qrencode", "-o", qr_output_path, "-t", "PNG"], input=input_data.encode(), check=True)
        print(f"{GREEN}Configuration file saved in {user_config_path}.{NC}")
        print(f"{GREEN}QR code saved in {qr_output_path}.{NC}")
    except subprocess.CalledProcessError:
        print("Error creating or saving configuration/QR code.")
        return

    # Update WireGuard configuration.
    try:
        update_wg_config(server_wg_nic)
    except subprocess.CalledProcessError:
        print("Error reloading server.")
        return


# Function to set file permissions.
def set_file_permissions(file_path):
    try:
        os.chmod(file_path, 0o600)
    except Exception as e:
        print(f"Error setting file permissions: {e}")


def get_config_vars():
    source_vars = {}
    try:
        with open("/etc/wireguard/params") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    name, value = line.split("=", 1)
                    source_vars[name.strip()] = value.strip()
                elif line:  # if the line is not empty but does not contain "="
                    print(f"{RED}Incorrect line format in params: '{line}'. Lines must contain '='.{NC}")
    except FileNotFoundError:
        print(f"{RED}File /etc/wireguard/params not found.{NC}")
        return None
    return source_vars


def is_user_in_server_config(username, server_config_path):
    try:
        with open(server_config_path, 'r') as f:
            return any(f"#Client {username}" in line for line in f)
    except FileNotFoundError:
        print(f"{RED}Configuration file {server_config_path} not found.{NC}")
        return True  # Assume the file will be there if not found


def update_wg_config(server_wg_nic):
    temp_config_file = "/tmp/server_wg_conf.tmp"
    subprocess.run(f"wg-quick strip {server_wg_nic} > {temp_config_file}", shell=True, check=True)
    subprocess.run(f"wg addconf {server_wg_nic} {temp_config_file}", shell=True, check=True)
    os.remove(temp_config_file)


def extract_ip_address(config_path):
    try:
        with open(config_path, 'r') as file_object:
            for line in file_object:
                if line.startswith("Address ="):
                    # Assumes format 'Address = <IP>/24', extracts only the IP
                    return line.split('=', 1)[1].strip().split('/')[0]
    except (FileNotFoundError, IsADirectoryError, PermissionError, IndexError, ValueError):
        return None

    return None


def list_users():
    users_directory = "/etc/wireguard/clients"
    os.makedirs(users_directory, exist_ok=True)
    user_files = os.listdir(users_directory)

    user_ip_list = []

    for user_file in user_files:
        config_path = os.path.join(users_directory, user_file)
        ip = extract_ip_address(config_path)
        if ip is not None:
            user_ip_list.append((user_file, ip))

    # Sort the list by IP address
    user_ip_list.sort(key=lambda user: ipaddress.ip_address(user[1]))

    print(GREEN + "\nList of WireGuard users:" + NC)
    for index, (user_file, ip) in enumerate(user_ip_list):
        print(f"{index + 1}. {user_file} - {ip}")


def regenerate_qr():
    list_users()
    try:
        choice = int(input("Enter the number of the user to regenerate the QR code: ")) - 1
        user_files = os.listdir("/etc/wireguard/clients/")
        if 0 <= choice < len(user_files):
            selected_user_config_path = f"/etc/wireguard/clients/{user_files[choice]}"
            print(f"QR code for {user_files[choice]}:")
            subprocess.run(f"qrencode -t ansiutf8 < {selected_user_config_path}", shell=True, check=True)
        else:
            print(RED + "Invalid choice." + NC)
    except ValueError:
        print(RED + "Invalid input. Please enter a number." + NC)


def delete_user():
    user_directory = "/etc/wireguard/clients/"

    if not os.path.exists(user_directory):
        print(f"Directory {user_directory} not found.")
        return

    # Retrieve user files and their IP addresses
    user_files_with_ips = []
    for user_file in os.listdir(user_directory):
        if user_file.endswith('.conf'):
            ip_address = extract_ip_address(os.path.join(user_directory, user_file))
            if ip_address is not None:
                user_files_with_ips.append((user_file, ip_address))

    # Sort user files by IP addresses
    user_files_with_ips.sort(key=lambda user: ipaddress.ip_address(user[1]))

    if user_files_with_ips:
        print(GREEN + "\nList of WireGuard users:" + NC)
        for index, (filename, ip_address) in enumerate(user_files_with_ips, start=1):
            print(f"{index}. {filename} - {ip_address}")
    else:
        print("No users to display.")
        return

    try:
        choice = int(input("\nEnter the number of the user to delete: ")) - 1

        if 0 <= choice < len(user_files_with_ips):
            user_filename = user_files_with_ips[choice][0]
            username = os.path.splitext(user_filename)[0]  # Extract the username from the filename

            server_wg_nic = get_server_wg_nic()

            if server_wg_nic:
                remove_user_from_wg(server_wg_nic, username)
                os.remove(os.path.join(user_directory, user_filename))
                print(f"User {username} deleted.")

                qr_code_path = f"/etc/wireguard/qrcodes/{username}_qrcode.png"
                if os.path.exists(qr_code_path):
                    os.remove(qr_code_path)
                else:
                    print(f"QR code {qr_code_path} not found.")

                os.system(f"systemctl restart wg-quick@{server_wg_nic}")
            else:
                print("Failed to get the WireGuard network interface name.")
        else:
            print(RED + "Invalid choice." + NC)
    except ValueError:
        print(RED + "Invalid input." + NC)


def get_server_wg_nic():
    try:
        with open("/etc/wireguard/params") as f:
            for line in f:
                if "SERVER_WG_NIC" in line:
                    return line.split('=')[1].strip()
    except FileNotFoundError:
        print("Parameter file not found.")
    return None


def remove_user_from_wg(server_wg_nic, username):
    server_config_path = f"/etc/wireguard/{server_wg_nic}.conf"
    user_identifier = f"Client {username}"

    try:
        with open(server_config_path, 'r') as f:
            lines = f.readlines()

        with open(server_config_path, 'w') as f:
            skip_block = False
            for line in lines:
                # Check for user identifier in the line
                if user_identifier in line:
                    skip_block = True
                    continue  # Skip the line with the found identifier

                # If we are in the process of skipping a block
                if skip_block:
                    # Stop skipping if a blank line is found or a new line with "Client"
                    if line.strip() == "" or "Client" in line:
                        skip_block = False
                        if "Client" in line:
                            f.write(line)  # Write the line if it's a new client block
                    continue

                # Write to file only lines not belonging to the block being removed
                if not skip_block:
                    f.write(line)

    except FileNotFoundError:
        print("Server configuration file not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def restart_wireguard():
    os.system("systemctl restart wg-quick@wg0")
    print(GREEN + "WireGuard server restarted." + NC)


def remove_wireguard():
    os.system("apt remove --purge -y wireguard")
    os.system("rm -rf /etc/wireguard/")
    print(GREEN + "WireGuard server removed." + NC)


def initial_check():
    is_root()
    check_virt()
    check_os()


if __name__ == "__main__":
    initial_check()
    install_wireguard()
