# PHP2Shell detection rules

Sigma rules for post-exploitation activity after CVE-2026-109618 and CVE-2026-109619 (PHP2Shell).

Both bugs are memory corruption issues in php-src that can lead to RCE. Affected versions: 8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, 8.5 < 8.5.12. Patching is the fix. These rules help find hosts where exploitation may have already happened.

## Rules

| Rule | Platform | Level | Status |
| --- | --- | --- | --- |
| [PHP Spawns Suspicious Child Process - Linux](rules/linux/process_creation/proc_creation_lnx_php_susp_child.yml) | Linux | high | experimental |
| [PHP Spawns Suspicious Child Process - Windows](rules/windows/process_creation/proc_creation_win_php_susp_child.yml) | Windows | high | experimental |

## Approach

The rules do not look for the exploit itself. They look for what usually comes after it: a PHP worker (php-fpm, php-cgi, Apache with mod_php; on Windows php-cgi.exe under IIS or nginx, httpd.exe) starting a shell, recon tools or downloaders. This does not depend on the payload or the web application, so it also catches other PHP RCEs and webshells.

## Requirements

Process creation events with parent process info:

- Linux: Sysmon for Linux (Event ID 1), or auditd `execve` events mapped to Sigma fields
- Windows: Sysmon (Event ID 1), or Security 4688 with command line auditing enabled

## Usage

```
pip install sigma-cli
sigma check rules/
sigma plugin install splunk
sigma convert -t splunk --without-pipeline rules/
```

Replace `splunk` with the backend for your SIEM.

## Known limitations

- Exploit code that runs only in the PHP process memory and never starts a child process is not detected.
- The sendmail filter (Linux) can be bypassed by adding `/usr/sbin/sendmail` to the command line.
- The Windows rule has no sendmail filter. XAMPP-style setups with a local sendmail wrapper may need one.
- Apache servers running CGI scripts will generate noise.
- PHP embedded in other runtimes (FrankenPHP, RoadRunner) is not covered.
- Not tested against a real exploit yet. No public exploit was available at the time of writing.

## References

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.wiz.io/blog/php2shell-php-rce

## License

[Detection Rule License (DRL) 1.1](LICENSE)
