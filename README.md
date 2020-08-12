# MailMask
This milter provides a simple backend to create forwardings (let's say `corona-restaurant@maskmail.invalid`) that hide original mail addresses (let's say `topsecret@yourname.invalid`). Additionally, it adds a `Reply-To` header to the forwarded mail that also allows you to keep your mail address private if you reply to such a mail.

## Usage example
You should write down your mail address to a corona sheet at your favourite restaurant. Most restaurants don't know how to keep your data safe (some just maintain lists which are basically public to all guests and some others hand them off to local police angencies).

In order to identify restaurants that don't follow data protection regulations, you may want include its name to the mail address and create a forwarding to your real mail address in order to get informed when some other guest gets infected. Just send a mail to `corona-restaurant@maskmail.invalid` in order to create the forwarding. The milter automatically uses the sender address (i.e. `topsecret@yourname.invalid`) as the destination.

Once the restaurant or some other person that bought your data annoys you, you can just send a mail to `corona-restaurant+d@maskmail.invalid` in order to delete the forwarding (and of course send an complain to the `Landesdatenschutzbeauftragten`). If you whish to reply to a fowarded mail, your mail client will use the `Reply-To` header that was automatically inserted during forwarding your mail. The `Reply-To` field contains the name of the mask and the sender address (e.g. `corona-restaurant+gesundheitsamt+somestate.de@maskmail.invalid` if a mail was sent from `gesundheitsamt@somestate.de`). Now, the milter tries to strip out all header fields that may identify your original mail address (From, CC, Autocrypt, etc.) and forwards the mail to the actual recipient (`gesundheitsamt@somestate.de`).

# Future work
This is currently just a proof of concept. It works but I (or others) still want to include
* Expiration dates when the forwarding will be deleted automatically (e.g., 4 weeks for corona sheets)
* Support for other databases

## Dependencies (as Debian package names)
* git cmake make gcc
* libmilter1.0.1 libmilter-dev
* libmariadbclient-dev
* libconfig-dev

## Build and install
```bash
mkdir build
cd $_
cmake -DWITH_SYSTEMD=ON ..
make
make install # this installs the executable and the Systemd unit
systemctl daemon-reload
```

If you wish to install to a custom directory:
```bash
cmake -DWITH_SYSTEMD=ON -DCMAKE_INSTALL_PREFIX=/tmp/your/path ..
```

Please have a look at the SQL-files at `/config` and the configuration file at `/etc/mailmask.conf`. I think you know how to handle them.

## Configure (on a Systemd and Postfix environment)
Add a user:
```bash
groupadd mailmask
useradd -g mailmask -s /bin/false -d /var/spool/postfix/mailmask mailmask
adduser postfix mailmask
mkdir /var/spool/postfix/mailmask
chown mailmask:mailmask /var/spool/postfix/mailmask
```

Configure postfix to use the milter:
```
postconf -e "smtpd_milters = unix:/mailmask/mailmask$([[ $(postconf -h smtpd_milters) != "" ]] && echo -n ", " && postconf -h smtpd_milters)"
postconf -e "non_smtpd_milters = unix:/mailmask/mailmask$([[ $(postconf -h non_smtpd_milters) != "" ]] && echo -n ", " && postconf -h non_smtpd_milters)"
```

Start everything:
```bash
systemctl enable mailmask
service mailmask start
service postfix restart
```

## Run
To start the daemon directly, run the following (Remove the `-d` to run in foreground):
```bash
mailmask -u mailmask -g mailmask -m 002 -d -p /var/run/mailmask.pid -s /var/spool/postfix/mailmask/mailmask -c /etc/mailmask.conf
```

## License
Licensed under the 3-Clause BSD License.
