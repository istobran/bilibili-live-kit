# Install and Using
```bash
# download and install
wget https://github.com/septs/bilibili-live-get-experience/archive/master.zip -O bilibili-live.zip
unzip bilibili-live.zip
sudo mv bilibili-live-get-experience-master /opt/bilibili-live
sudo ln -s /opt/bilibili-live/bilibili-live.service /etc/systemd/system/bilibili-live.service

# settings your in username and password
editor /opt/bilibili-live/configure.json

# enable and start service
systemctl enable bilibili-live
systemctl start bilibili-live
```

# LICENSE
This project is licensed under version 3 of the GNU Lesser General Public License.
