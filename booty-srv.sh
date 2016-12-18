#!/bin/bash

# Copyright (c) 2016 Connor Goddard

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

GHOST_CONFIG_FILE_URL="https://raw.githubusercontent.com/cgddrd/booty-srv/master/resources/ghost-config.js"
APACHE_GHOST_VHOST_URL="https://raw.githubusercontent.com/cgddrd/booty-srv/master/resources/vhost-ghost.conf"
APACHE_GITLAB_VHOST_URL="https://gitlab.com/gitlab-org/gitlab-recipes/raw/master/web-server/apache/gitlab-apache24.conf"
ALLOW_ROOT=false

update_repositories() {

  print_message "Updating Ubuntu Cached Package Repositories."

  rm /var/lib/apt/lists/* -vf
  apt-get update

}

install_perl() {

  print_message "Installing Perl."

  apt-get install -y perl

}

install_apache() {

  print_message "Installing Apache."

  apt-get install -y apache2

  ufw app list
  ufw app info "Apache Full"
  ufw allow in "Apache Full"

  update_apache_directory_index

  chown -R $ADMIN_USERNAME:$ADMIN_USERNAME /var/log/apache2

}

update_apache_directory_index() {

  # Remove existing instance of 'index.php' from config file.
  sed -i 's/index.php //g' /etc/apache2/mods-enabled/dir.conf

  # Add 'index.php' back in (with space) immediately after 'DirectoryIndex'.
  # See: http://stackoverflow.com/a/35252457/4768230 for more information.
  sed -i 's/\bDirectoryIndex\b/& index.php/' /etc/apache2/mods-enabled/dir.conf

}

restart_apache_server() {

  print_message "Restarting Apache."
  systemctl restart apache2

}

install_lamp_stack() {

  print_message "Installing LAMP stack."

  install_apache
  install_mysql
  install_php

  local USER_PERMISSION_GROUP="${ADMIN_USERNAME}:${ADMIN_USERNAME}"

  print_message "Updating ownership for webroot folders to user '${ADMIN_USERNAME}'."
  chown -R $USER_PERMISSION_GROUP /var/www/

  restart_apache_server

}

print_message() {

  echo ""
  echo "## ${1}"
  echo ""

}

get_external_ip_address() {

  ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p'

}

install_proftpd() {

  print_message "Installing ProFTPd."

  #apt-get install -y proftpd
  
  apt-get -y install debconf-utils
  echo "proftpd-basic shared/proftpd/inetd_or_standalone select standalone" | debconf-set-selections
  sudo apt-get -y install proftpd
  
  apt-get install proftpd

  # Update the ServerName
  # See: http://stackoverflow.com/a/11245372/4768230 for more information.
  sed -i.bak "s/.*ServerName.*/ServerName\t\t\t\"$(get_external_ip_address)\"/" /etc/proftpd/proftpd.conf

  write_sftp_proftpd_config

  mkdir /etc/proftpd/authorized_keys

  local SSH_PATH="/home/${ADMIN_USERNAME}/.ssh/authorized_keys"
  local PROFTPD_SSH_PATH="/etc/proftpd/authorized_keys/${ADMIN_USERNAME}"
  local USER_PERMISSION_GROUP="${ADMIN_USERNAME}:${ADMIN_USERNAME}"

  print_message "Setting up existing SSH keys for ProFTPd."
  ssh-keygen -e -f $SSH_PATH | sudo tee $PROFTPD_SSH_PATH
  chown -R $USER_PERMISSION_GROUP $PROFTPD_SSH_PATH

  # Uncomment the 'DefaultRoot' line to jail FTP users to their own area.
  # sed -i 's/# DefaultRoot/DefaultRoot/g' /etc/proftpd/proftpd.conf

  service proftpd restart

}

write_sftp_proftpd_config() {

  cat <<EOF > /etc/proftpd/conf.d/sftp.conf
  <IfModule mod_sftp.c>

          SFTPEngine on
          Port 2222
          SFTPLog /var/log/proftpd/sftp.log

          # Configure both the RSA and DSA host keys, using the same host key
          # files that OpenSSH uses.
          SFTPHostKey /etc/ssh/ssh_host_rsa_key
          SFTPHostKey /etc/ssh/ssh_host_dsa_key

          SFTPAuthMethods publickey

          SFTPAuthorizedUserKeys file:/etc/proftpd/authorized_keys/%u

          # Enable compression
          SFTPCompression delayed

  </IfModule>

EOF

}

install_php() {

  print_message "Installing PHP."

  apt-get install -y php libapache2-mod-php php-mcrypt php-mysql

  print_message "Writing PHPInfo page to: /var/www/html/php-info.php".

  echo "<?php phpinfo();" > /var/www/html/php-info.php

}

install_mysql() {

  print_message "Installing MySQL."

  debconf-set-selections <<< "mysql-server mysql-server/root_password password ${MYSQL_ROOT_PASSWORD}"
  debconf-set-selections <<< "mysql-server mysql-server/root_password_again password ${MYSQL_ROOT_PASSWORD}"

  apt-get -y install mysql-server

  secure_mysql

}

secure_mysql() {

  print_message "Securing MySQL."

  if ! is_mysql_command_available; then
    echo "The MySQL/MariaDB client mysql(1) is not installed."
    exit 1
  fi

  mysql --user=root --password=${MYSQL_ROOT_PASSWORD} <<_EOF_
    DELETE FROM mysql.user WHERE User='';
    DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
    DROP DATABASE IF EXISTS test;
    DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
    FLUSH PRIVILEGES;
_EOF_

}

# Predicate that returns exit status 0 if the database root password
# is set, a nonzero exit status otherwise.
is_mysql_root_password_set() {
  ! mysqladmin --user=root status > /dev/null 2>&1
}

# Predicate that returns exit status 0 if the mysql(1) command is available,
# nonzero exit status otherwise.
is_mysql_command_available() {
  which mysql > /dev/null 2>&1
}

check_user_exists() {

  if [ "$#" -ne "1" ]; then
    echo "check_user_exists: Expected 1 parameter." >&2
    exit 2
  fi

  if id "$1" >/dev/null 2>&1; then
    # 0 = true
    return 0
  else
    # 1 = false
    return 1
  fi

}

get_ip_info() {

  ip addr show eth0 | grep inet | awk '{ print $2; }' | sed 's/\/.*$//'

}

initial_setup() {

  print_message "Creating new user - '${1}'."
  print_message "Password: '${2}'"

  if check_user_exists $1; then

    echo "New user ${1} already exists."

  else

    adduser $1 --disabled-password --gecos ""
    echo "${1}:${2}" | chpasswd
    usermod -aG sudo $1

    local USER_HOME_FOLDER="/home/${1}/.ssh/"
    local USER_PERMISSION_GROUP="${1}:${1}"

    # CG - Copy SSH keys over from root to new admin user.
    print_message "Copying SSH keys from root to new admin user '${1}'."
    cp -r /root/.ssh/ $USER_HOME_FOLDER
    chown -R $USER_PERMISSION_GROUP $USER_HOME_FOLDER

  fi

  setup_firewall

  setup_ssh $1

  update_repositories

  set_timezone

}

setup_ssh() {

  print_message "Configuring SSH/SFTP"

  #  CG - Check to see if we have specified a custom port for SSH access.
  if [ ! -z "$SSH_PORT" ]; then
    sed -i.bak "s/.*Port 22.*/Port ${SSH_PORT}/" /etc/ssh/sshd_config
  fi

  if [ "$ALLOW_ROOT" = true ]; then
    echo "AllowUsers root ${1}" >> /etc/ssh/sshd_config
  else 
    echo "AllowUsers ${1}" >> /etc/ssh/sshd_config
    sed -i "s/.*PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
  fi

  restart_firewall

  service ssh restart

}

restart_firewall() {

  ufw --force disable
  ufw --force enable

}

setup_firewall() {

  print_message "Configuring firewall."

  ufw app list

  # Open ports for SSH.
  ufw allow OpenSSH
  ufw allow 25/tcp

  ufw allow 80/tcp
  ufw allow 443/tcp

  ufw allow 2222

  #  CG - Check to see if we have specified a custom port for SSH access.
  if [ ! -z "$SSH_PORT" ]; then
    # SSH/SFTP
    ufw allow $SSH_PORT
  fi

  ufw show added

  ufw --force enable

  ufw status

}

set_timezone() {

  print_message "Configuring timezone."

  ln -sf /usr/share/zoneinfo/Europe/London /etc/localtime

  apt-get install -y ntp

}

restart_server() {

  print_message "Restarting server to apply changes."

  shutdown -r now

}

install_ghost() {

  GHOST_USERNAME="ghost"
  GHOST_PORT="2368"
  GHOST_PASSWORD=$ADMIN_PASSWORD
  local GHOST_DOWNLOAD_URL="https://github.com/TryGhost/Ghost/releases/download/0.9.0/Ghost-0.9.0.zip"

  print_message "Beginning Ghost installation."

  print_message "Installing supporting libraries."
  apt-get install -y zip vim wget npm build-essential python-software-properties python g++ make

  print_message "Downloading and installing NodeJS."
  curl -sL https://deb.nodesource.com/setup | sudo bash -
  apt-get install -y nodejs

  # CG - We need to symlink between the older and newer versions of NodeJS.
  ln -s /usr/bin/nodejs /usr/bin/node

  print_message "Downloading Ghost."
  wget -O /var/www/html/ghost.zip $GHOST_DOWNLOAD_URL

  print_message "Extracting Ghost installer."
  unzip -d /var/www/html/ghost /var/www/html/ghost.zip
  rm /var/www/html/ghost.zip
  cd /var/www/html/ghost/

  print_message "Installing Sqlite3 dependency."
  npm install sqlite3 --save

  print_message "Installing Ghost."
  npm install --production

  configure_ghost

  setup_ghost_forever

  setup_ghost_apache_proxy

  print_message "Ghost installation complete!"

}

configure_ghost() {

  print_message "Creating new user '${GHOST_USERNAME}' for Ghost instance."

  adduser --shell /bin/bash --gecos 'Ghost application' ghost --disabled-password
  echo "${GHOST_USERNAME}:${GHOST_PASSWORD}" | sudo chpasswd
  chown -R $GHOST_USERNAME:$GHOST_USERNAME /var/www/html/ghost/

  print_message "Downloading Ghost configuration template."

  cd /var/www/html/ghost
  wget -O config.js $GHOST_CONFIG_FILE_URL

  print_message "Configuring Ghost."
  sed -i.bak "s/<URL>/$(get_external_ip_address)/g" config.js

  # CG - We use '0.0.0.0' to refer to 'localhost' in this case. Apache is set to reverse-proxy back to 'localhost:2368'.
  sed -i "s/<IP>/0.0.0.0/g" config.js
  # sed -i "s/<IP>/$(get_external_ip_address)/g" config.js

  sed -i "s/<USERNAME>/${SENDGRID_USERNAME}/g" config.js
  sed -i "s/<PASSWORD>/${SENDGRID_PASSWORD}/g" config.js

  print_message "Opening Ghost port in Firewall (Port: ${GHOST_PORT})"
  ufw allow $GHOST_PORT

}

setup_ghost_forever() {

    local GHOST_FOREVER_CRONTAB="@reboot NODE_ENV=production /usr/local/bin/forever start /var/www/html/ghost/index.js"

    cd /var/www/html/ghost
    print_message "Installing Forever NodeJS library."
    npm install -g forever

    # CG - Create symlink between forever install locations - bit of a hack..
    ln -s /usr/bin/forever /usr/local/bin/forever

    print_message "Adding Crontab entry for Forever library."
    { crontab -l -u $GHOST_USERNAME; echo "${GHOST_FOREVER_CRONTAB}"; } | crontab -u $GHOST_USERNAME -

}

setup_ghost_apache_proxy() {

  local BLOG_ADMIN_EMAIL="hello@connorlukegoddard.com"
  local VIRTUALHOST_FILE_NAME="blog.connorlukegoddard.com.conf"

  print_message "Enabling Apache proxy modules."
  a2enmod proxy proxy_http

  print_message "Downloading Apache/Ghost virtualhost configuration file."
  wget -O /etc/apache2/sites-available/$VIRTUALHOST_FILE_NAME $APACHE_GHOST_VHOST_URL

  print_message "Configuring Apache virtualhost for Ghost."
  sed -i.bak "s/<BLOG_URL>/${GHOST_URL}/g" /etc/apache2/sites-available/$VIRTUALHOST_FILE_NAME
  sed -i "s/<ADMIN_EMAIL>/${BLOG_ADMIN_EMAIL}/g" /etc/apache2/sites-available/$VIRTUALHOST_FILE_NAME

  # CG - Replace '/var/log/httpd/logs/' with '/var/log/apache/'
  sed -i "s/\/var\/log\/httpd\/logs\//\/var\/log\/apache2\//g" /etc/apache2/sites-available/$VIRTUALHOST_FILE_NAME

  print_message "Enabling new Apache/Ghost virtualhost."
  a2ensite $VIRTUALHOST_FILE_NAME

}

install_gitlab() {

  local VIRTUALHOST_FILE_NAME="/etc/apache2/sites-available/${GITLAB_URL}.conf"

  print_message "Installing Gitlab..."

  print_message "Downloading Gitlab pre-requisites."
  sudo apt-get install -y curl openssh-server ca-certificates postfix

  print_message "Downloading Gitlab package server configuration."
  curl -sS https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | sudo bash

  print_message "Installing Gitlab package."
  sudo apt-get install gitlab-ce

  print_message "Configuring Gitlab..."

  sed -i.bak "s/^external_url.*/external_url 'http:\/\/${GITLAB_URL}'/" /etc/gitlab/gitlab.rb
  sed -i "s/^#\sgitlab_workhorse\['enable'\].*/gitlab_workhorse\['enable'\] = true/" /etc/gitlab/gitlab.rb
  sed -i "s/^#\sgitlab_workhorse\['listen_network'\].*/gitlab_workhorse\['listen_network'\] = \"tcp\"/" /etc/gitlab/gitlab.rb
  sed -i "s/^#\sgitlab_workhorse\['listen_addr'\].*/gitlab_workhorse\['listen_addr'\] = \"127.0.0.1:8181\"/" /etc/gitlab/gitlab.rb
  sed -i "s/^#\sweb_server\['external_users'\].*/web_server\['external_users'\] = \['www-data'\]/" /etc/gitlab/gitlab.rb
  sed -i "s/^#\snginx\['enable'\].*/nginx\['enable'\] = false/" /etc/gitlab/gitlab.rb

  print_message "Configuring Gitlab/Apache virtualhost."
  wget -O $VIRTUALHOST_FILE_NAME $APACHE_GITLAB_VHOST_URL
  sed -i.bak "s/YOUR_SERVER_FQDN/${GITLAB_URL}/g" $VIRTUALHOST_FILE_NAME

  # CG - Update Apache default log filepath from '/var/log/httpd/logs/' to '/var/log/apache2/'.
  sed -i "s/\/var\/log\/httpd\/logs\//\/var\/log\/apache2\//g" $VIRTUALHOST_FILE_NAME

  print_message "Enabling Apache 'mod_rewrite' module."
  a2enmod rewrite

  print_message "Enabling new Apache/Ghost virtualhost."
  a2ensite "${GITLAB_URL}.conf"

  sudo gitlab-ctl reconfigure

  print_message "Gitlab installation complete!"

}

main() {

  unset ADMIN_USERNAME
  unset ADMIN_PASSWORD
  unset SENDGRID_USERNAME
  unset SENDGRID_PASSWORD
  unset SSH_PORT
  unset MYSQL_ROOT_PASSWORD
  unset GHOST_PASSWORD
  unset FLAG_INSTALL_GITLAB
  unset FLAG_INSTALL_GHOST

  while getopts ":u:p:m:x:s:b:y:g:h" opt; do
  case $opt in
    u)
      echo "-u was triggered, Parameter: $OPTARG" >&2
      ADMIN_USERNAME=${OPTARG}
      ;;
    p)
      echo "-p was triggered, Parameter: $OPTARG" >&2
      ADMIN_PASSWORD=${OPTARG}
      ;;
    m)
      # echo "-m was triggered, Parameter: $OPTARG" >&2
      SENDGRID_USERNAME=${OPTARG}
      ;;
    x)
      # echo "-x was triggered, Parameter: $OPTARG" >&2
      SENDGRID_PASSWORD=${OPTARG}
      ;;
    s)
      # echo "-s was triggered, Parameter: $OPTARG" >&2
      MYSQL_ROOT_PASSWORD=${OPTARG}
      ;;
    b)
      # echo "-b was triggered, Parameter: $OPTARG" >&2
      SSH_PORT=${OPTARG}
      ;;
    g)
      #echo "-g was triggered, Parameter: $OPTARG" >&2
      FLAG_INSTALL_GHOST="true"
      GHOST_URL=${OPTARG}
      ;;
    y)
      #echo "-y was triggered, Parameter: $OPTARG" >&2
      FLAG_INSTALL_GITLAB="true"
      GITLAB_URL=${OPTARG}
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
    h)
      usage
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND -1))

if [[ $(id -u) -ne 0 ]] ; then echo "Script must be run as root (or sudo)." ; exit 1 ; fi

if [ -z "$ADMIN_USERNAME" ] || [ -z "$ADMIN_PASSWORD" ]; then
   usage
fi

if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
  print_message "No explicit MySQL root password specified. Defaulting to admin password."
  MYSQL_ROOT_PASSWORD=$ADMIN_PASSWORD
fi

initial_setup "$ADMIN_USERNAME" "$ADMIN_PASSWORD"

get_ip_info

install_lamp_stack

install_proftpd

install_perl

if [ -n "$FLAG_INSTALL_GHOST" ]; then
  if [ -z "$SENDGRID_USERNAME" ] || [ -z "$SENDGRID_PASSWORD" ]; then
    print_message "Error: Sendgrid username and password must be specified for Ghost installation."
    usage
  fi

  install_ghost
fi

if [ -n "$FLAG_INSTALL_GITLAB" ]; then
  install_gitlab
fi

print_message "Install script completed!"

restart_server

}

usage() {

# CG - Based on DOCOPT convention specification.
# See: http://docopt.org/ for more information.

echo "Usage: $0 -u <username> -p <password> -m <username> -x <password> [-s <password>] [-b <port>] [-y <url>] [-g <url>] [-h]" 1>&2;

cat <<_EOF_

-u

  Username of new admin account.

-p

  Password of new admin account.

-b

  Port for accepting SSH connections (defaults to port 22).

-g

  Flag and domain name associated with the installation Ghost blog package.

-m

  Username of Sendgrid SMTP account (required for Ghost installation).

-x

  Password of Sendgrid SMTP account (required for Ghost installation).

-s

  Password for MySQL root user (defaults to admin account if not set).

-y

  Flag to install and configure Gitlab server package.

_EOF_

exit 1;

}

main "$@"
