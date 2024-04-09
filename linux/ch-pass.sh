echo "Enter the new password: "; read -s password; for user in $(cut -d: -f1 /etc/passwd); do echo -e "$password\n$password" | passwd $user; done

