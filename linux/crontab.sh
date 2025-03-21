# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use sudo."
    exit 1
fi

echo "Checking .bashrc files for all users..."

# Determine the editor (prefer vi, fallback to nano)
if command -v vi &>/dev/null; then
    EDITOR="vi"
elif command -v nano &>/dev/null; then
    EDITOR="nano"
else
    echo "Error: No suitable text editor (vi or nano) found."
    exit 1
fi

# Loop through all users with valid home directories
for user in $(cut -d: -f1 /etc/passwd); do
    home_dir=$(eval echo ~$user)

    # Skip if the home directory doesn't exist
    if [ ! -d "$home_dir" ]; then
        continue
    fi

    bashrc_file="$home_dir/.bashrc"

    # If the .bashrc file exists, open it
    if [ -f "$bashrc_file" ]; then
        echo "Opening user $user's .bashrc file with $EDITOR..."
        sleep 2
        $EDITOR "$bashrc_file"

        echo "Opening crontab for user $user..."
        sleep 2
        sudo crontab -e -u "$user"

    fi

done

echo "Checking bash.bashrc..."
sleep 2
$EDITOR /etc/bash.bashrc

echo "Check complete."
