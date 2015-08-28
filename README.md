# Wildcard

There is number of great Burp extension out there. Most of them create their own tabs. Too many of them makes the interface heavy and ugly. This extension tries to address this issue. It provides ability to hijack tabs belonging to other extensions (it is not oficially supported by Burp Extensions). For safety reasons, in order to work, this feature must be explicitly enabled on Options tab each time extension is loaded.

Before:

![wildcard-1](https://cloud.githubusercontent.com/assets/4956006/9557495/b4b1de86-4ddc-11e5-9b7a-d6bec8af7681.png)

After:

![wildcard-2](https://cloud.githubusercontent.com/assets/4956006/9557497/b84756a2-4ddc-11e5-91a7-01c655147adb.png)

Extension also provides CSRF Handling mini-extension source (Python) which could be saved as a file, customized and loaded into Burp later on. Newly added extension will handle application specific CSRF tokens.

This extension _DOES NOT_ require Burp Suite Professional

## License

[MIT License](https://github.com/twbs/bootstrap/blob/master/LICENSE)
