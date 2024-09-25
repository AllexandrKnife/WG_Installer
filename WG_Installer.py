import os
import subprocess
import sys
import random


# Цветовая схема для вывода в терминал
RED = '\033[0;31m'
ORANGE = '\033[0;33m'
GREEN = '\033[0;32m'
NC = '\033[0m'


def is_root():
    if os.geteuid() != 0:
        print("Вы должны запустить этот скрипт с правами суперпользователя.")
        sys.exit(1)


def check_virt():
    virt_type = subprocess.check_output(["systemd-detect-virt"]).strip()
    if virt_type in [b"openvz", b"lxc"]:
        print(f"{virt_type.decode()} не поддерживается.")
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
                print(f"Ваша версия {os_name.capitalize()} ({version_id}) не поддерживается. "
                      f"Пожалуйста, используйте {os_name.capitalize()} {supported_versions[os_name]} или новее.")
                sys.exit(1)
        else:
            print("Скрипт не поддерживает вашу операционную систему.")
            sys.exit(1)

    except subprocess.CalledProcessError:
        print(
            RED + "Ошибка получения информации о системе. Убедитесь, что команда lsb_release установлена и доступна." + NC)
        sys.exit(1)


def is_wireguard_installed():
    try:
        # Для Debian/Ubuntu
        if subprocess.call(['dpkg', '-s', 'wireguard'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            return True

        # Для RHEL/CentOS
        if subprocess.call(['rpm', '-q', 'wireguard-tools'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            return True

        # Для Arch Linux
        if subprocess.call(['pacman', '-Qs', 'wireguard-tools'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0:
            return True
    except FileNotFoundError:
        pass

    return False


def install_wireguard():
    if is_wireguard_installed():
        print(GREEN + "WireGuard уже установлен. Пропускается этап установки." + NC)
        os.makedirs("/etc/wireguard/clients", exist_ok=True)
    else:
        server_pub_ip, server_pub_nic, server_wg_nic, server_wg_ipv4, server_wg_ipv6, server_port, client_dns_1, client_dns_2, allowed_ips = install_questions()

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

# Настройка iptables
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
        print(GREEN + "WireGuard успешно установлен." + NC)

    show_menu()


def is_valid_ip(ip):
    parts = ip.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def is_valid_ip_with_cidr(ip_cidr):
    ip, *cidr = ip_cidr.split('/')
    if len(cidr) != 1:
        return False
    cidr = cidr[0]

    # Check IP address
    if ':' in ip:  # Likely IPv6
        try:
            import ipaddress
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    elif '.' in ip:  # Likely IPv4
        if not is_valid_ip(ip):
            return False

    # Validate CIDR
    if not cidr.isdigit() or not (0 <= int(cidr) <= (128 if ':' in ip else 32)):
        return False

    return True


def is_valid_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535


def install_questions():
    print(GREEN + "Добро пожаловать в установщик WireGuard!" + NC)

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
        input_ip = input(f"Публичный IPv4 или IPv6 адрес [{server_pub_ip}]: ").strip()
        if not input_ip:
            input_ip = server_pub_ip
        if input_ip and is_valid_ip(input_ip):
            server_pub_ip = input_ip
            break
        else:
            print(RED + "Некорректный IP-адрес. Пожалуйста, введите действительный IP-адрес." + NC)

    try:
        server_pub_nic = subprocess.check_output(
            "ip -4 route ls | grep default | awk '{print $5}'",
            shell=True
        ).decode().strip()
    except subprocess.CalledProcessError:
        server_pub_nic = None

    server_pub_nic = input(f"Публичный интерфейс [{server_pub_nic}]: ") or server_pub_nic

    server_wg_nic = input("Имя интерфейса WireGuard [wg0]: ") or "wg0"

    while True:
        server_wg_ipv4 = input("IPv4 для WireGuard [10.7.77.1]: ") or "10.7.77.1"
        if is_valid_ip(server_wg_ipv4):
            break
        else:
            print(RED + "Некорректный IPv4. Пожалуйста, введите действительный IPv4-адрес." + NC)

    server_wg_ipv6 = input("IPv6 для WireGuard [fd43:43:43::1]: ") or "fd43:43:43::1"

    while True:
        input_port = input(f"Порт WireGuard [1-65535]: ").strip() or str(random.randint(49152, 65535))
        if is_valid_port(input_port):
            server_port = int(input_port)
            break
        else:
            print(RED + "Некорректный номер порта. Пожалуйста, введите число от 1 до 65535." + NC)

    while True:
        client_dns_1 = input("Первый DNS-сервер [1.1.1.1]: ") or "1.1.1.1"
        if is_valid_ip(client_dns_1):
            break
        else:
            print(RED + "Некорректный DNS-сервер. Пожалуйста, введите действительный IP-адрес для DNS-сервера." + NC)

    while True:
        client_dns_2 = input("Второй DNS-сервер [1.0.0.1]: ") or "1.0.0.1"
        if is_valid_ip(client_dns_2):
            break
        else:
            print(RED + "Некорректный DNS-сервер. Пожалуйста, введите действительный IP-адрес для DNS-сервера." + NC)

    while True:
        allowed_ips_input = input("Список разрешенных IP для клиентов [0.0.0.0/0,::/0]: ").strip()
        if not allowed_ips_input:
            allowed_ips_input = "0.0.0.0/0,::/0"

        allowed_ips = allowed_ips_input.split(',')
        if all(is_valid_ip_with_cidr(ip.strip()) for ip in allowed_ips):
            break
        else:
            print("Некорректный список разрешенных IP. Пожалуйста, введите действительные IP-адреса с CIDR.")

    print(GREEN + "Отлично! Мы готовы настроить ваш сервер WireGuard." + NC)

    return server_pub_ip, server_pub_nic, server_wg_nic, server_wg_ipv4, server_wg_ipv6, server_port, client_dns_1, client_dns_2, allowed_ips_input


def show_menu():
    while True:
        print("\nМеню:\n"
              "1. Добавить нового пользователя\n"
              "2. Вывести список всех пользователей\n"
              "3. Cоздать QR-код для пользователя\n"
              "4. Удалить пользователя\n"
              "5. Перезагрузить сервер WireGuard\n"
              "6. Удалить сервер WireGuard\n"
              "7. Выйти из меню")
        choice = input("Выберите пункт меню: ").strip()

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
            print("Выход из меню.")
            break
        else:
            print(RED + "Неизвестный выбор. Пожалуйста, повторите попытку." + NC)

user_config_path = None # /etc/wireguard/users/user_name.conf

def add_user():
    global user_config_path
    user_config_path = None
    os.makedirs("/etc/wireguard/clients", exist_ok=True)
    # server_config_path = None
    source_vars = get_config_vars()

    if not source_vars:
        return

    server_wg_nic = source_vars.get('SERVER_WG_NIC')
    if not server_wg_nic or not os.path.exists(f'/sys/class/net/{server_wg_nic}'):
        print(f"{RED}Интерфейс {server_wg_nic} не найден.{NC}")
        return

    server_config_path = f"/etc/wireguard/{server_wg_nic}.conf"

    while True:
        username = input("Введите имя нового пользователя: ").strip()

        if not username.isalnum():
            print(RED + "Имя пользователя может содержать только буквы и цифры." + NC)
            continue

        user_config_path = f"/etc/wireguard/clients/{username}.conf"

        if os.path.exists(user_config_path):
            print(RED + "Конфигурация с таким именем уже существует. Пожалуйста, выберите другое имя." + NC)
            continue

        if is_user_in_server_config(username, server_config_path):
            print(
                RED + "Пользователь с таким именем уже существует в конфигурации сервера. Пожалуйста, выберите другое имя." + NC)
            continue

        break

    try:
        user_priv_key = subprocess.check_output("wg genkey", shell=True).decode().strip()
        user_pub_key = subprocess.check_output(f"echo {user_priv_key} | wg pubkey", shell=True).decode().strip()
    except subprocess.CalledProcessError:
        print(RED + "Ошибка генерации ключей." + NC)
        return

    # Получаем наибольший IP-адрес из существующих
    highest_ip_octet = get_highest_ip_octet()
    client_wg_ipv4 = f"{source_vars['SERVER_WG_IPV4'].rsplit('.', 1)[0]}.{highest_ip_octet + 1}"

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

    try:
        with open(server_config_path, 'a') as f:
            f.write(f"#Пользователь {username}\n"
                    "[Peer]\n"
                    f"PublicKey = {user_pub_key}\n"
                    f"AllowedIPs = {client_wg_ipv4}/32\n")
        print(f"Successfully added {username} to the server configuration.")
    except Exception as e:
        print(f"Error adding user to server configuration: {e}")

    try:
        update_wg_config(server_wg_nic)
    except subprocess.CalledProcessError:
        print(RED + "Ошибка перезагрузки сервера." + NC)
        return

    print(f"{GREEN}Пользователь {username} добавлен. Конфигурация сохранена в {user_config_path}.{NC}")

    try:
        subprocess.run(f"qrencode -t ansiutf8 < {user_config_path}", shell=True, check=True)
    except subprocess.CalledProcessError:
        print(f"{RED}Ошибка генерации QR-кода.{NC}")


def get_highest_ip_octet():
    users_dir = "/etc/wireguard/clients"
    highest_octet = 1  # начинаем как минимальный возможный
    try:
        for user_file in os.listdir(users_dir):
            config_path = os.path.join(users_dir, user_file)
            ip_address = extract_ip_address(config_path)
            if ip_address:
                last_octet = int(ip_address.split('.')[-1])
                if last_octet > highest_octet:
                    highest_octet = last_octet
    except FileNotFoundError:
        print(f"{RED}Папка с клиентами не найдена.{NC}")
    return highest_octet


# def extract_ip_address(config_path):
#    try:
#        with open(config_path, 'r') as f:
#            for line in f:
#                if line.startswith("Address ="):
#                    return line.split('=', 1)[1].strip().split('/')[0]
#    except Exception:
#        return None


def get_config_vars():
    source_vars = {}
    try:
        with open("/etc/wireguard/params") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    name, value = line.split("=", 1)
                    source_vars[name.strip()] = value.strip()
                elif line:  # если строка не пустая, но нет "="
                    print(f"{RED}Неправильный формат строки в params: '{line}'. Строки должны содержать знак '='.{NC}")
    except FileNotFoundError:
        print(f"{RED}Файл /etc/wireguard/params не найден.{NC}")
        return None
    return source_vars


def is_user_in_server_config(username, server_config_path):
    try:
        with open(server_config_path, 'r') as f:
            return any(f"# Пользователь {username}" in line for line in f)
    except FileNotFoundError:
        print(f"{RED}Файл конфигурации {server_config_path} не найден.{NC}")
        return True  # Предполагаем, что файл будет, если не найден


def update_wg_config(server_wg_nic):
    temp_config_file = "/tmp/server_wg_conf.tmp"
    subprocess.run(f"wg-quick strip {server_wg_nic} > {temp_config_file}", shell=True, check=True)
    subprocess.run(f"wg addconf {server_wg_nic} {temp_config_file}", shell=True, check=True)
    os.remove(temp_config_file)


def list_users():
    users_dir = "/etc/wireguard/clients"
    os.makedirs(users_dir, exist_ok=True)
    users = os.listdir(users_dir)

    print(GREEN + "Список пользователей WireGuard:" + NC)
    for i, user in enumerate(users):
        user_config_path = os.path.join(users_dir, user)
        ip_address = extract_ip_address(user_config_path)
        print(f"{i + 1}. {user} - {ip_address}")


def extract_ip_address(config_path):
    try:
        with open(config_path, 'r') as f:
            for line in f:
                if line.startswith("Address ="):
                    # Предполагается формат 'Address = <IP>/24', извлекаем только IP
                    return line.split('=', 1)[1].strip().split('/')[0]
    except FileNotFoundError:
        return "Конфигурация не найдена"
    except Exception as e:
        return f"Ошибка: {str(e)}"
    return "IP-адрес не найден"


def regenerate_qr():
    list_users()
    try:
        choice = int(input("Введите номер пользователя для пересоздания QR-кода: ")) - 1
        user_files = os.listdir("/etc/wireguard/clients/")
        if 0 <= choice < len(user_files):
            user_config_path = f"/etc/wireguard/clients/{user_files[choice]}"
            print(f"QR-код для {user_files[choice]}:")
            subprocess.run(f"qrencode -t ansiutf8 < {user_config_path}", shell=True, check=True)
        else:
            print(RED + "Некорректный выбор." + NC)
    except ValueError:
        print(RED + "Некорректный ввод. Пожалуйста, введите число." + NC)


def delete_user():
    list_users()
    try:
        choice = int(input("Введите номер пользователя для удаления: ")) - 1
        user_files = os.listdir("/etc/wireguard/clients/")

        if 0 <= choice < len(user_files):
            user_filename = user_files[choice]
            server_wg_nic = get_server_wg_nic()

            if server_wg_nic:
                remove_user_from_wg(server_wg_nic, user_filename)
                print(f"Пользователь {user_filename} удален.")
                os.system("systemctl restart wg-quick@wg0")
            else:
                print("Не удалось получить имя сетевого интерфейса WireGuard.")
        else:
            print("Некорректный выбор.")
    except ValueError:
        print("Некорректный ввод. Пожалуйста, введите число.")


def get_server_wg_nic():
    try:
        with open("/etc/wireguard/params") as f:
            for line in f:
                if "SERVER_WG_NIC" in line:
                    return line.split('=')[1].strip()
    except FileNotFoundError:
        print("Файл параметров не найден.")
    return None


def remove_user_from_wg(server_wg_nic, user_config_filename):
    server_config_path = f"/etc/wireguard/{server_wg_nic}.conf"
    user_config_path = f"/etc/wireguard/clients/{user_config_filename}"
    user_identifier = f"#Пользователь {os.path.splitext(user_config_filename)[0]}"

    try:
        # Чтение конфигурационного файла сервера
        with open(server_config_path, 'r') as f:
            lines = f.readlines()

        # Запись конфигурации без удалённого пользователя
        with open(server_config_path, 'w') as f:
            skip_lines = 0
            for line in lines:
                if skip_lines > 0:
                    skip_lines -= 1
                    continue

                if line.strip() == user_identifier:
                    skip_lines = 3  # Удаляем следующие три строки
                    continue

                f.write(line)

        # Удаление конфигурационного файла пользователя
        if os.path.exists(user_config_path):
            os.remove(user_config_path)
            print(f"Конфигурационный файл {user_config_path} успешно удалён.")
        else:
            print(f"Конфигурационный файл {user_config_path} не найден.")

    except FileNotFoundError:
        print("Файл конфигурации сервера не найден.")
    except Exception as e:
        print(f"Произошла ошибка: {str(e)}")


def restart_wireguard():
    os.system("systemctl restart wg-quick@wg0")
    print(GREEN + "Сервер WireGuard перезагружен." + NC)


def remove_wireguard():
    os.system("apt remove --purge -y wireguard")
    os.system("rm -rf /etc/wireguard/")
    print(GREEN + "Сервер WireGuard удален." + NC)


def initial_check():
    is_root()
    check_virt()
    check_os()


if __name__ == "__main__":
    initial_check()
    install_wireguard()
    
