Features:

1. send heartbeat to gain experience
2. every day check in
3. clear all gift

# Install and Using
```bash
# download and install
git clone https://github.com/septs/bilibili-live-kit /opt/bilibili-live
cp /opt/bilibili-live/bilibili-live.service.example /etc/systemd/system/bilibili-live.service

# settings your in username and password
cp /opt/bilibili-live/configure.json.example /opt/bilibili-live/configure.json
editor /opt/bilibili-live/configure.json

# enable and start service
systemctl enable bilibili-live
systemctl start bilibili-live
```

# LICENSE
This project is licensed under version 3 of the GNU Lesser General Public License.
