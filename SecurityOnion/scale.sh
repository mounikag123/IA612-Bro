#1/bin/bash
xfconf-query -c xsettings -p /Xft/DPI -s "190"
xfconf-query -c xfwm4 -p /general/theme -s "Default-hdpi"
xfconf-query -c xfce4-panel -p /panels/panel-0/size -s "40"
xfconf-query -c xfce4-desktop -p /desktop-icons/icons-size -s 64
