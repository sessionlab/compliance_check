# SessionLab SOC2 device compliance checker

How to use:

- Open the Terminal app (command + space, then type Terminal in the search bar and hit enter)
- Run this script on your macbook to make sure we comply with all SOC2 device requirements using the command:
  `ADD_COMAND_WHEN_WE_HAVE_THE_REPO`

## Fixing potential computer issues:

File Vault not enabled:

- Open System Settings, go to Privacy and Security,, scroll to FileVault on the bottom of the page, click on it and toggle it to enabled.

ScreenSaver timeout too long

- Open System Settings, go to Lock Screen and select both "turn display off" settings to be 5 minutes or less.
- In the same screen, select "Immediately" in the require password setting (This doesn't really matter when FileVault is enabled, but still...)

Password length too low (less than 8 characters):

- Since 4+ characters is the default setting on MacOS, we need to change this setting. So go back to the terminal and run:
  `sudo pwpolicy clearaccountpolicies && sudo pwpolicy -setglobalpolicy "minChars=8"`
  You will be prompted for the password, just use the password you logged into the device
