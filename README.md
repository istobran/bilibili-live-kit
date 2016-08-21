Features:
1. send heartbeat to gain experience
2. every day check in

# Install and Using
```bash
# download and install
git clone https://github.com/septs/bilibili-live-kit /opt/bilibili-live
ln -s /opt/bilibili-live/bilibili-live.service /etc/systemd/system/bilibili-live.service

# settings your in username and password
editor /opt/bilibili-live/configure.json

# enable and start service
systemctl enable bilibili-live
systemctl start bilibili-live
```

# LICENSE
This project is licensed under version 3 of the GNU Lesser General Public License.
