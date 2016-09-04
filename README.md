# booty-srv
A no-frills Bash script that sets up web servers just the way I like 'em (literally meaning me, as in [cgddrd](https://github.com/cgddrd)).

## What does it do?

Provides automated support for setting up a new web server instance (as per my own needs), followed by the installation and configuration of the following applications:
* LAMP stack
* Perl
* Proftpd (SFTP)
* ntp (timezone)
* Ghost
* Gitlab

## How does it work?

Well, it's just a Bash script, so kinda works like any other - you download it, run it (passing in some parameters), and it does its thing.

## How do I drive it?

The easiest way to get going is type something like this:

```
$ curl -sSL https://raw.githubusercontent.com/cgddrd/booty-srv/master/booty-srv.sh | sudo bash -s -- -u username -p password -g blog.example.com 
```
**Note:** As it does quite a lot of admin-related stuff (e.g. creating new users, installing packages, `chown`-ing directories etc.), it requires `sudo` privileges.

To get a full list of script parameters, use: `-h`.

## Any questions, suggestions and/or improvements?

Let me know via Github Issues, or contribute via Pull Requests. In either case, thanks in advance for your time!
