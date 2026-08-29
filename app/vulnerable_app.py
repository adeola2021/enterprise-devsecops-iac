import shlex
import subprocess


def run_command(user_input):
    """
    Safely execute an approved command without invoking a shell.
    """

    allowed_commands = {
        "status": ["echo", "Application status: OK"],
        "version": ["python3", "--version"],
    }

    command_parts = shlex.split(user_input)

    if not command_parts:
        raise ValueError("Command cannot be empty.")

    command_name = command_parts[0]

    if command_name not in allowed_commands:
        raise ValueError("Command is not permitted.")

    subprocess.run(
        allowed_commands[command_name],
        shell=False,
        check=True,
    )


if __name__ == "__main__":
    command = input("Enter approved command: ")
    run_command(command)
