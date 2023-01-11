
cp KeyboardMouseListener.py /usr/local/bin
chmod 755 /usr/local/bin/KeyboardMouseListener.py
cp KeyboardMouseRunner /usr/local/bin/
chmod 755 /usr/local/bin/KeyboardMouseRunner
cp KeyboardMouseListener.service /etc/systemd/system

systemctl enable KeyboardMouseListener.service
systemctl daemon-reload
