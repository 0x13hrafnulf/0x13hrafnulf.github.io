---
title: Shell
menu:
  notes:
    name: Shell
    identifier: notes-shell
    parent: notes-miscellaneous
    weight: 20
---
# Shell Options
<!-- Upgrade Shell -->
{{< note title="Upgrade Shell">}}
- `python -c 'import pty;pty.spawn("/bin/bash")`
- Press `CTRL+Z`
- `stty raw -echo;fg`
- `export TERM=xterm`
- Check your terminal settings with `stty -a`
- Set columns and rows in upgraded shell to required ones
  - `stty columns <cols>`
  - `stty rows <rows>`

{{< /note >}}