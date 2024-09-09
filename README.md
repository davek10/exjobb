# MITM tool for Bluetooth Low Energy

MITM tool for a nRF 52480 board.

## Setup and Installation

First install [nRF Connect for Desktop and nRF Command Line Tools](https://www.nordicsemi.com/Products/Development-software/nRF-Connect-SDK/GetStarted#infotabs).
Then use either the programmer in nRF Connect for Desktop or nrfutil to [program the device](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/app_dev/programming.html) with the hex file found in `build/zephyr/zephyr.hex`.

## Usage
Once you have flashed the nRF 52480 board and established a connection via a COM/TTY serial port the tool is ready to accept commands.
The device won't respond unless prompted, to verify that the device works properly and you are communicating via the correct serial port you can try to either write a command or an arbitrary string to receive the default error message:
```
$ test
    unknown command
```
To set a target the `set_target <target_address>` the format for addresses are the 6 byte address provided as hexadecimal string followed by a space and address type.

Example:

```
$ set_target acb5e773cc7f random
    New target set: AC:B5:E7:73:CC:7F, random
```

Use command `list devices` to see advertising devices

When a target has been set the `start` command starts the mitm module and awaits incoming connections.
When a device connects to the tool the user will be informed of the address, connection id and the GAP role.
`Connected to: AC:B5:E7:73:CC:7F (random), id:1, role: periphiral`
All incoming requests, responses and notifications will be displayed and relayed to the other party unless a rule specifies otherwise. 

### Rules Syntax

It is possible to block or alter any of the communication between two parties by creating rules.
rules are created using either the `block` or `replace` command.
  `block` and `replace` use the following syntax `block <handle> <dir>` , `replace <handle> <dir> <replacement data>`.
  `<handle>` is the handle id, `dir` is the direction of the rule, the value `0` indicates communication going towards the target and `1` communication going away from the target (i.e. towards a user).
  `<replacement data>` is given as a hex string.
  Example:

  ```
  $ replace 10 1 12ab

  $ block 10 0
  ```
  
This will block a user from sending requests to handle 10 to the target and any notification or response from the target on handle 10 will be replaced with 2 bytes `12 ab`.

## License

[LICENSE](LICENSE)