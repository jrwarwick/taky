# Deploying / Setting up a Taky Server

Primarily, there are two ways to install taky, and two ways to configure it for
deployment. You should chose the way that best suits your needs! But if you
aren't sure, and you don't have complex needs, the "Linux System Administrator"
method is probably the one you want to choose!

## Installation

### The Linux System Administrator Way

This is the most standard method of installation, and requires root access to
your computer.

Step 1. Make sure your system has python3 and pip. Remember, this requires
python >= 3.6!

```
$ sudo apt install python3 python3-pip redis-server
$ python3 --version
Python 3.8.5

# If necessary, upgrade pip
$ sudo -H python3 -m pip install --upgrade pip
```

Step 2. Install taky from pip

```
$ sudo -H python3 -m pip install taky
```

And you're done! Should you ever need to upgrade taky, simply run

```
$ sudo -H python3 -m pip install --upgrade taky
```

### The Python Virtualenv Way

This method is more advanced, but is useful if you do not have root access on
your system. Or, you have many python applications on your system, and do not
want packages to interfere with each other. This is not the general use case.
If you don't know what this use case is for, then you probably don't need it!

This method creates a self-contained python deployment, isolated from the rest
of your system. Make sure you have sourced the `bin/activate` file for your
virtual environment!

Step 1. Install requirements

```
$ sudo apt install python3 python3-pip redis-server

$ python3 --version
Python 3.8.5

# If necessary, upgrade pip
$ sudo -H python3 -m pip install --upgrade pip

# Install virtualenv
$ sudo -H python3 -m pip install virtualenv
```

Step 2. Setup the virtual environment for python, and activate it

```
$ mkdir taky_venv
$ python3 -m virtualenv taky_venv
$ . taky_venv/bin/activate
(taky_venv) $
```

Step 3. Install Taky

```
(taky_venv) $ python3 -m pip install taky
```

## Configuration

Like installation, there are two primary ways to setup taky. It does not
matter which installation method you picked, both configuration methods
are valid.

For all configurations, you will need to know the following things:

 * The system's public IP address
 * The system's hostname

### Global Configuration

If you picked the "Linux System Administrator" installation, this configuration
method goes hand in hand. If you have administrated webservers like nginx or
Apache, this layout should be familiar to you.

 * Configuration files go in `/etc/taky`
 * User data goes inside `/var/taky`

Needless to say, you will need to run this setup as root.

Step 1. Make a user to run taky

This step is optional, but highly recommended. In general, it is a good
security practice to run daemons under users other than root. We will name
our user `stickytak`, but you can choose any username you like.

```
$ sudo adduser stickytak.
```

Step 2. Use `takyctl` to build the required files

This step will also generate the certificate authority, and server certificate.
(If you are using the virtualenv installation, don't forget to source the
`bin/activate` file!)

```
admin@bluetack:~$ sudo taky --user stickytak \
                            --public-ip 192.168.1.100 \
                            --host bluetack

admin@bluetack:~$ ls -l /etc/taky
/etc/taky:
total 8
drwxr-xr-x 2 stickytak stickytak 4096 Feb 27 20:12 ssl
-rw-r--r-- 1 stickytak stickytak  408 Feb 27 20:12 taky.conf

/etc/taky/ssl:
total 20
-rw-r--r-- 1 stickytak stickytak  997 Feb 27 20:12 ca.crt
-rw------- 1 stickytak stickytak 1708 Feb 27 20:12 ca.key
-rw-r--r-- 1 stickytak stickytak  969 Feb 27 20:12 server.crt
-rw------- 1 stickytak stickytak 1704 Feb 27 20:12 server.key
-rw-r--r-- 1 stickytak stickytak 3009 Feb 27 20:12 server.p12

admin@bluetack:~$ cat /etc/taky/taky.conf
[taky]
hostname = bluetack
node_id = TAKY
bind_ip = 0.0.0.0
public_ip = 192.168.1.91
redis

[cot_server]
port = 8089
log_cot

[dp_server]
upload_path = /var/taky/dp-user

[ssl]
enabled = true
client_cert_required = True
ca = /etc/taky/ssl/ca.crt
ca_key = /etc/taky/ssl/ca.key
server_p12 = /etc/taky/ssl/server.p12
server_p12_pw = atakatak
cert = /etc/taky/ssl/server.crt
key = /etc/taky/ssl/server.key
key_pw
```

Step 3. Configure the redis backend

If you want the map items to persist between runs of taky, you'll need to
install the redis server. (If you're following the instructions, you already
installed it!)

Pop open `/etc/taky/taky.conf` in your favorite editor, and change this line

```
redis = true
```

Step 4. Generate a client certificate

All your users will need a client certificate. This is fairly straight forward
to do! In any directory, run:

```
admin@bluetack:~$ takyctl build_client JENNY
admin@bluetack:~$ ls -l JENNY.zip
-rw-rw-r-- 1 admin admin 6.9K Feb 27 20:23 JENNY.zip
```

Simply copy that over to your device, and import it.

Step 5. Test start the servers

taky has two servers, the COT server, and the data package server. From any
directory, simply run these commands.

For the COT server:

```
admin@bluetack:~$ sudo su stickytak
stickytak@bluetack:~$ taky
INFO:root:taky v0.7
INFO:load_config:Loading config file from /etc/taky/taky.conf
INFO:COTServer:Loading CA certificate from /etc/taky/ssl/ca.crt
INFO:COTServer:Listening for ssl on 0.0.0.0:8089
```

For the Data Package server:

```
admin@bluetack:~$ sudo su stickytak
stickytak@bluetack:~$ taky_dps
[2021-02-27 20:31:40 -0500] [2521165] [INFO] Starting gunicorn 20.0.4
[2021-02-27 20:31:40 -0500] [2521165] [INFO] Listening at: https://0.0.0.0:8443 (2521165)
[2021-02-27 20:31:40 -0500] [2521165] [INFO] Using worker: sync
[2021-02-27 20:31:40 -0500] [2521167] [INFO] Booting worker with pid: 2521167
[2021-02-27 20:31:41 -0500] [2521168] [INFO] Booting worker with pid: 2521168
```

Step 6. Setup systemd services

 << TODO >>

### Site Installation

If you don't have root, this will let you put all the data within a single
folder. This can also be helpful if you want to run multiple instances of taky
on the same machine.

Unlike the last step, we will not need to make a linux user. We will just run
`taky` from our own account.

```
user@bluetack:~$ takyctl setup --hostname bluetack-1     \
                                --public-ip 192.168.1.100 \
                                bluetack-1

user@bluetack:~$ ls -lR bluetack-1
bluetack-1/:
total 20
drwxrwxr-x 3 user user 4096 Feb 27 20:21 dp-user
drwxrwxr-x 2 user user 4096 Feb 27 20:21 ssl
-rw-rw-r-- 1 user user  360 Feb 27 20:21 taky.conf

bluetack-1/dp-user:
total 4
drwxrwxr-x 2 user user 4096 Feb 27 20:21 meta

bluetack-1/dp-user/meta:
total 0

bluetack-1/ssl:
total 60
-rw-rw-r-- 1 user user  997 Feb 27 20:21 ca.crt
-rw------- 1 user user 1704 Feb 27 20:21 ca.key
-rw-rw-r-- 1 user user  969 Feb 27 20:21 server.crt
-rw------- 1 user user 1704 Feb 27 20:21 server.key
-rw-rw-r-- 1 user user 3009 Feb 27 20:21 server.p12
```

From there, all we need to do is `cd` into the folder, and run `taky`.

Start the COT server:

```
user@bluetack:~$ cd bluetack-1
user@bluetack:~/bluetack-1$ taky
INFO:root:taky v0.7.dev16+g5572cb9.d20210227
INFO:load_config:Loading config file from /home/user/bluetack-1/taky.conf
INFO:RedisPersistence:Connecting to default redis
INFO:RedisPersistence:Tracking 3 items
INFO:COTServer:Listening for ssl on 0.0.0.0:8089
```

Start the Data Package server:

```
user@bluetack:~$ cd bluetack-1
user@bluetack:~/bluetack-1$ taky_dps
INFO:root:taky v0.7
INFO:load_config:Loading config file from /home/user/bluetack-1/taky.conf
INFO:RedisPersistence:Connecting to default redis
INFO:RedisPersistence:Tracking 3 items
INFO:COTServer:Listening for ssl on 0.0.0.0:8089
[2021-02-27 20:31:40 -0500] [2521165] [INFO] Starting gunicorn 20.0.4
[2021-02-27 20:31:40 -0500] [2521165] [INFO] Listening at: https://0.0.0.0:8443 (2521165)
[2021-02-27 20:31:40 -0500] [2521165] [INFO] Using worker: sync
[2021-02-27 20:31:40 -0500] [2521167] [INFO] Booting worker with pid: 2521167
```